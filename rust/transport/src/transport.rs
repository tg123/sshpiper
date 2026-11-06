use std::{
    collections::VecDeque,
    pin::Pin,
    sync::Arc,
    task::Poll,
    time::{Duration, Instant},
};

use bytes::Bytes;
use futures_util::{future::poll_fn, Sink, Stream, StreamExt};
use ssh_key::{PrivateKey, PublicKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio_util::codec::Framed;

use crate::{
    codec::Codec,
    kex,
    wire::{string, Reader},
    Algorithms, Error, HostIdentity, HostKeyVerifier, Result,
};

const IDENTIFICATION: &[u8] = b"SSH-2.0-sshpiper-rust-experimental";
const REKEY_BYTES: u64 = 1 << 30;
const MAX_PENDING: usize = 4 * 1024 * 1024;

enum Role {
    Client(Arc<dyn HostKeyVerifier>),
    Server(Vec<HostIdentity>),
}

/// An encrypted packet stream with independent client/server key exchange.
///
/// This is experimental infrastructure. It does not authenticate users, enforce
/// routing policies, or implement the plugin protocol. The caller must complete
/// SSH user authentication before relaying connection-layer messages.
pub struct Transport<S> {
    framed: Framed<BufReader<S>, Codec>,
    role: Role,
    algorithms: Algorithms,
    peer_id: Vec<u8>,
    session_id: Option<[u8; 32]>,
    strict: bool,
    extensions: bool,
    usable: bool,
    keyed_at: Instant,
    pending: VecDeque<Bytes>,
    pending_bytes: usize,
    wire_pending: VecDeque<Bytes>,
    wire_pending_bytes: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Transport<S> {
    /// Establish a server transport with a single host key.
    pub async fn accept(stream: S, host_key: PrivateKey) -> Result<Self> {
        Self::accept_identities(stream, vec![HostIdentity::new(host_key, None)?]).await
    }

    pub async fn accept_identities(stream: S, identities: Vec<HostIdentity>) -> Result<Self> {
        Self::accept_with_algorithms(stream, identities, Algorithms::default()).await
    }

    pub async fn accept_with_algorithms(
        stream: S,
        identities: Vec<HostIdentity>,
        algorithms: Algorithms,
    ) -> Result<Self> {
        if identities.is_empty() {
            return Err(Error::Protocol("at least one host identity is required"));
        }
        Self::start(stream, Role::Server(identities), algorithms).await
    }

    /// Establish a client transport, verifying the server against an explicit
    /// trusted host key. There is deliberately no implicit trust/skip default.
    pub async fn connect(stream: S, trusted_host_key: PublicKey) -> Result<Self> {
        Self::connect_verified(stream, Arc::new(trusted_host_key)).await
    }

    /// Establish a transport with explicit asynchronous host verification policy.
    pub async fn connect_verified(stream: S, verifier: Arc<dyn HostKeyVerifier>) -> Result<Self> {
        Self::start(stream, Role::Client(verifier), Algorithms::default()).await
    }

    async fn start(stream: S, role: Role, algorithms: Algorithms) -> Result<Self> {
        let mut stream = BufReader::new(stream);
        stream.write_all(IDENTIFICATION).await?;
        stream.write_all(b"\r\n").await?;
        stream.flush().await?;
        let server = matches!(role, Role::Server(_));
        let peer_id = read_identification(&mut stream, server).await?;
        let mut transport = Self {
            framed: Framed::new(stream, Codec::default()),
            role,
            algorithms,
            peer_id,
            session_id: None,
            strict: false,
            extensions: false,
            usable: false,
            keyed_at: Instant::now(),
            pending: VecDeque::new(),
            pending_bytes: 0,
            wire_pending: VecDeque::new(),
            wire_pending_bytes: 0,
        };
        transport.framed.set_backpressure_boundary(64 * 1024);
        transport.exchange(None).await?;
        transport.usable = true;
        Ok(transport)
    }

    /// Initial exchange hash used to bind SSH user authentication signatures.
    pub fn session_id(&self) -> &[u8; 32] {
        self.session_id
            .as_ref()
            .expect("constructor completes key exchange")
    }

    /// Whether strict key exchange was negotiated with this peer.
    pub fn strict_kex(&self) -> bool {
        self.strict
    }

    pub fn peer_accepts_extensions(&self) -> bool {
        self.extensions
    }

    fn begin(&mut self) -> Result<()> {
        self.ensure_usable()?;
        self.usable = false;
        Ok(())
    }

    pub(crate) fn ensure_usable(&self) -> Result<()> {
        if self.usable {
            Ok(())
        } else {
            Err(Error::Poisoned)
        }
    }

    pub(crate) fn needs_rekey(&self) -> bool {
        let codec = self.framed.codec();
        codec.rx_bytes >= REKEY_BYTES
            || codec.tx_bytes >= REKEY_BYTES
            || self.keyed_at.elapsed() >= Duration::from_secs(3600)
    }

    /// Send an opaque authentication or connection payload, without channel
    /// decoding or ID remapping. Transport and KEX messages are library-owned.
    ///
    /// Cancelling this future makes subsequent operations return `Poisoned`.
    pub async fn send(&mut self, payload: Bytes) -> Result<()> {
        self.begin()?;
        if !payload.first().copied().is_some_and(application_message) {
            return Err(Error::Protocol(
                "transport messages cannot be sent as application data",
            ));
        }
        if self.needs_rekey() {
            self.exchange(None).await?;
        }
        self.send_packet(payload).await?;
        self.usable = true;
        Ok(())
    }

    pub(crate) async fn send_batch(&mut self, payloads: Vec<Bytes>) -> Result<()> {
        self.begin()?;
        if payloads
            .iter()
            .any(|payload| !payload.first().copied().is_some_and(application_message))
        {
            return Err(Error::Protocol(
                "transport messages cannot be sent as application data",
            ));
        }
        if self.needs_rekey() {
            self.exchange(None).await?;
        }
        self.send_packets(payloads).await?;
        self.usable = true;
        Ok(())
    }

    /// Receive an opaque authentication or connection payload. Handles peer
    /// rekeying internally; never forwards key-exchange packets to another peer.
    ///
    /// Cancelling this future makes subsequent operations return `Poisoned`.
    pub async fn recv(&mut self) -> Result<Bytes> {
        self.begin()?;
        let result = self.receive().await?;
        self.usable = true;
        Ok(result)
    }

    async fn receive(&mut self) -> Result<Bytes> {
        if self.needs_rekey() {
            self.exchange(None).await?;
        }
        loop {
            if let Some(packet) = self.pending.pop_front() {
                self.pending_bytes -= packet.len();
                return Ok(packet);
            }
            let packet = self.packet().await?;
            match packet[0] {
                1 => return Err(Error::Disconnected),
                2..=4 => continue,
                20 => self.exchange(Some(packet)).await?,
                id if application_message(id) => return Ok(packet),
                _ => return Err(Error::Protocol("unexpected transport message")),
            }
        }
    }

    /// Perform a key exchange, preserving the original authentication session ID.
    ///
    /// Cancelling this future makes subsequent operations return `Poisoned`.
    pub async fn rekey(&mut self) -> Result<()> {
        self.begin()?;
        self.exchange(None).await?;
        self.usable = true;
        Ok(())
    }

    /// Run a full-duplex connection driver with bounded input/output queues.
    /// The returned halves may be used concurrently.
    pub fn split(self) -> (crate::PacketSender, crate::PacketReceiver)
    where
        S: Send + 'static,
    {
        crate::connection::spawn(self)
    }

    async fn packet(&mut self) -> Result<Bytes> {
        if let Some(packet) = self.wire_pending.pop_front() {
            self.wire_pending_bytes -= packet.len();
            return Ok(packet);
        }
        self.framed.next().await.ok_or(Error::Disconnected)?
    }

    async fn send_packet(&mut self, payload: Bytes) -> Result<()> {
        self.send_packets(std::iter::once(payload)).await
    }

    async fn send_packets(&mut self, payloads: impl IntoIterator<Item = Bytes>) -> Result<()> {
        let mut payloads = payloads.into_iter().peekable();
        poll_fn(|cx| {
            while payloads.peek().is_some() {
                match Pin::new(&mut self.framed).poll_ready(cx) {
                    Poll::Ready(Ok(())) => {
                        Pin::new(&mut self.framed)
                            .start_send(payloads.next().expect("pending send"))?;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => break,
                }
            }
            if payloads.peek().is_none() {
                if let Poll::Ready(result) = Pin::new(&mut self.framed).poll_flush(cx) {
                    return Poll::Ready(result);
                }
            }
            // Drain in-flight traffic while a write is blocked. Stop at NEWKEYS:
            // subsequent packets must not be decoded until the receive key changes.
            if self.wire_pending.back().is_none_or(|p| p[0] != 21) {
                match Pin::new(&mut self.framed).poll_next(cx) {
                    Poll::Ready(Some(Ok(packet))) => {
                        self.wire_pending_bytes += packet.len();
                        if self.wire_pending_bytes + self.pending_bytes > MAX_PENDING {
                            return Poll::Ready(Err(Error::Protocol(
                                "too much in-flight transport data",
                            )));
                        }
                        self.wire_pending.push_back(packet);
                        cx.waker().wake_by_ref();
                    }
                    Poll::Ready(Some(Err(error))) => return Poll::Ready(Err(error)),
                    Poll::Ready(None) => return Poll::Ready(Err(Error::Disconnected)),
                    Poll::Pending => {}
                }
            }
            Poll::Pending
        })
        .await
    }

    async fn exchange(&mut self, peer_init: Option<Bytes>) -> Result<()> {
        let server = matches!(self.role, Role::Server(_));
        let initial = self.session_id.is_none();
        let host_algorithms = match &self.role {
            Role::Server(identities) => identities
                .iter()
                .flat_map(HostIdentity::algorithms)
                .collect::<Vec<_>>()
                .join(","),
            Role::Client(_) => kex::HOST_KEYS.to_owned(),
        };
        let local_init = kex::init(server, &host_algorithms, initial, &self.algorithms);
        self.send_packet(local_init.clone()).await?;
        let peer_init = match peer_init {
            Some(packet) => packet,
            None => loop {
                let packet = self.packet().await?;
                match packet[0] {
                    20 => break packet,
                    id if !initial && application_message(id) => {
                        self.pending_bytes += packet.len();
                        if self.pending_bytes > MAX_PENDING {
                            return Err(Error::Protocol("too much in-flight data during rekey"));
                        }
                        self.pending.push_back(packet);
                    }
                    2..=4 if !initial => continue,
                    1 => return Err(Error::Disconnected),
                    _ => return Err(Error::Protocol("expected key exchange")),
                }
            },
        };
        let negotiated = kex::negotiate(&peer_init, &local_init, server)?;
        if initial {
            self.strict = negotiated.strict;
            self.extensions = negotiated.extensions;
        }
        if negotiated.discard_guess {
            self.packet().await?;
        }
        let (hash, shared) = if server {
            let packet = self.packet().await?;
            let mut reader = Reader(&packet);
            if reader.byte()? != 30 {
                return Err(Error::Protocol("expected ECDH_INIT"));
            }
            let client_public = reader.string()?;
            reader.end()?;
            let (public, shared) = kex::server_exchange(&negotiated.key_exchange, client_public)?;
            let Role::Server(identities) = &self.role else {
                unreachable!()
            };
            let identity = identities
                .iter()
                .find(|id| id.algorithms().contains(&negotiated.host_key))
                .ok_or(Error::Protocol("negotiated host identity is unavailable"))?;
            let host_key = identity.encoded()?;
            let hash = kex::hash(
                [
                    &self.peer_id,
                    IDENTIFICATION,
                    &peer_init,
                    &local_init,
                    &host_key,
                    client_public,
                    &public,
                ],
                &shared,
            );
            let mut reply = vec![31];
            string(&mut reply, &host_key);
            string(&mut reply, &public);
            string(
                &mut reply,
                &crate::sign(&identity.private, &hash, &negotiated.host_key)?,
            );
            self.send_packet(reply.into()).await?;
            (hash, shared)
        } else {
            let ephemeral = kex::ClientExchange::new(&negotiated.key_exchange)?;
            let public = ephemeral.public.clone();
            let mut request = vec![30];
            string(&mut request, &public);
            self.send_packet(request.into()).await?;
            let packet = self.packet().await?;
            let mut reader = Reader(&packet);
            if reader.byte()? != 31 {
                return Err(Error::Protocol("expected ECDH_REPLY"));
            }
            let host_key = reader.string()?;
            let server_public = reader.string()?;
            let signature = reader.string()?;
            reader.end()?;
            let shared = ephemeral.finish(server_public)?;
            let hash = kex::hash(
                [
                    IDENTIFICATION,
                    &self.peer_id,
                    &local_init,
                    &peer_init,
                    host_key,
                    &public,
                    server_public,
                ],
                &shared,
            );
            let Role::Client(trusted) = &self.role else {
                unreachable!()
            };
            let presented_algorithm = Reader(host_key).text()?.to_owned();
            let certificate = negotiated.host_key.ends_with("-cert-v01@openssh.com");
            let expected =
                if crate::signature_algorithm(&negotiated.host_key).starts_with("rsa-sha2-") {
                    if certificate {
                        "ssh-rsa-cert-v01@openssh.com"
                    } else {
                        "ssh-rsa"
                    }
                } else {
                    &negotiated.host_key
                };
            if presented_algorithm != expected {
                return Err(Error::Protocol(
                    "host key does not match negotiated algorithm",
                ));
            }
            crate::verify_signature(
                &crate::public_key(host_key)?,
                &hash,
                signature,
                &negotiated.host_key,
            )?;
            trusted.verify(host_key).await?;
            (hash, shared)
        };
        let session_id = *self.session_id.get_or_insert(hash);
        let tx = kex::derive(
            &shared,
            &hash,
            &session_id,
            !server,
            if server {
                negotiated.s2c_aes128
            } else {
                negotiated.c2s_aes128
            },
        );
        let rx = kex::derive(
            &shared,
            &hash,
            &session_id,
            server,
            if server {
                negotiated.c2s_aes128
            } else {
                negotiated.s2c_aes128
            },
        );
        self.send_packet(Bytes::from_static(&[21])).await?;
        let codec = self.framed.codec_mut();
        codec.tx = Some(tx);
        codec.tx_bytes = 0;
        if self.strict {
            codec.tx_sequence = 0;
        }
        if self.packet().await?.as_ref() != [21] {
            return Err(Error::Protocol("expected NEWKEYS"));
        }
        let codec = self.framed.codec_mut();
        codec.rx = Some(rx);
        codec.rx_bytes = 0;
        if self.strict {
            codec.rx_sequence = 0;
        }
        self.keyed_at = Instant::now();
        Ok(())
    }
}

/// Relay two already user-authenticated transports without interpreting channel
/// messages. Each side keeps its own keys, nonces and rekey negotiation.
///
/// Consumes both transports so cancellation closes both connections. User
/// authentication and policy enforcement are the caller's responsibility.
pub async fn relay<A, B>(downstream: Transport<A>, upstream: Transport<B>) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (down_tx, down_rx) = downstream.split();
    let (up_tx, up_rx) = upstream.split();
    tokio::select! {
        result = forward(down_rx, up_tx) => result,
        result = forward(up_rx, down_tx) => result,
    }
}

async fn forward(mut rx: crate::PacketReceiver, tx: crate::PacketSender) -> Result<()> {
    loop {
        tx.send(rx.recv().await?).await?;
    }
}

// Only the framed read is awaited; cancellation never abandons a key exchange.
pub(crate) async fn next_relay_packet<S: AsyncRead + AsyncWrite + Unpin>(
    transport: &mut Transport<S>,
) -> Result<Bytes> {
    if let Some(packet) = transport.pending.pop_front() {
        transport.pending_bytes -= packet.len();
        return Ok(packet);
    }
    transport.packet().await
}

impl<S: AsyncRead + AsyncWrite + Unpin> Transport<S> {
    pub(crate) async fn handle_packet(&mut self, packet: Bytes) -> Result<Option<Bytes>> {
        match packet[0] {
            1 => Err(Error::Disconnected),
            2..=4 => Ok(None),
            20 => {
                self.begin()?;
                self.exchange(Some(packet)).await?;
                self.usable = true;
                Ok(None)
            }
            id if application_message(id) => Ok(Some(packet)),
            _ => Err(Error::Protocol("unexpected transport message")),
        }
    }
}

fn application_message(id: u8) -> bool {
    matches!(id, 5..=19 | 50..=255)
}

async fn read_identification<S: AsyncRead + Unpin>(
    stream: &mut S,
    server: bool,
) -> Result<Vec<u8>> {
    for _ in 0..50 {
        let mut line = Vec::new();
        loop {
            if line.len() == 255 {
                return Err(Error::Protocol("identification line too long"));
            }
            let byte = stream.read_u8().await?;
            line.push(byte);
            if byte == b'\n' {
                break;
            }
        }
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.starts_with(b"SSH-") {
            if !line.starts_with(b"SSH-2.0-")
                || line.len() <= 8
                || line.iter().any(|b| !(32..=126).contains(b))
            {
                return Err(Error::Protocol("unsupported SSH identification"));
            }
            return Ok(line);
        }
        if server {
            return Err(Error::Protocol("client sent data before identification"));
        }
    }
    Err(Error::Protocol("too many pre-identification lines"))
}
