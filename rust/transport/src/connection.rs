use std::sync::Arc;

use bytes::Bytes;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot},
    task::AbortHandle,
};

use crate::{transport::next_relay_packet, Error, Result, Transport};

enum Command {
    Send(Bytes, oneshot::Sender<Result<()>>),
    SendBatch(Vec<Bytes>, oneshot::Sender<Result<()>>),
    Rekey(oneshot::Sender<Result<()>>),
}

struct Lifetime(AbortHandle);

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Send half of a full-duplex transport. Clones share one ordered packet queue.
#[derive(Clone)]
pub struct PacketSender {
    commands: mpsc::Sender<Command>,
    _lifetime: Arc<Lifetime>,
}

impl PacketSender {
    /// Write and flush one payload. Cancelling the wait does not cancel the
    /// driver's write; a queued payload can still be delivered.
    pub async fn send(&self, packet: Bytes) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Send(packet, tx))
            .await
            .map_err(|_| Error::Disconnected)?;
        rx.await.map_err(|_| Error::Disconnected)?
    }

    /// Write an ordered batch and flush once, with the same completion and
    /// cancellation semantics as `send`. Batches are bounded like one packet.
    pub async fn send_batch(&self, packets: Vec<Bytes>) -> Result<()> {
        if packets.is_empty()
            || packets.len() > 8
            || packets
                .iter()
                .try_fold(0usize, |size, packet| {
                    size.checked_add(packet.len())
                        .filter(|size| *size <= crate::MAX_PACKET)
                })
                .is_none()
        {
            return Err(Error::Protocol("invalid packet batch size"));
        }
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::SendBatch(packets, tx))
            .await
            .map_err(|_| Error::Disconnected)?;
        rx.await.map_err(|_| Error::Disconnected)?
    }

    /// Request rekeying and wait for it to complete.
    pub async fn rekey(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(Command::Rekey(tx))
            .await
            .map_err(|_| Error::Disconnected)?;
        rx.await.map_err(|_| Error::Disconnected)?
    }
}

/// Receive half of a full-duplex transport. Dropping both halves closes the
/// stream and aborts its driver, including a driver blocked in key exchange.
pub struct PacketReceiver {
    incoming: mpsc::Receiver<Result<Bytes>>,
    _lifetime: Arc<Lifetime>,
}

impl PacketReceiver {
    /// Receive an opaque payload or the transport's terminal error. Unlike
    /// `Transport::recv`, this operation is cancellation-safe.
    pub async fn recv(&mut self) -> Result<Bytes> {
        self.incoming.recv().await.ok_or(Error::Disconnected)?
    }
}

pub(crate) fn spawn<S>(transport: Transport<S>) -> (PacketSender, PacketReceiver)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (commands, receiver) = mpsc::channel(8);
    let (incoming, packets) = mpsc::channel(8);
    let task = tokio::spawn(async move {
        if let Err(error) = drive(transport, receiver, &incoming).await {
            // A dropped receiver has no remaining observer to notify.
            let _ = incoming.send(Err(error)).await;
        }
    });
    let lifetime = Arc::new(Lifetime(task.abort_handle()));
    (
        PacketSender {
            commands,
            _lifetime: lifetime.clone(),
        },
        PacketReceiver {
            incoming: packets,
            _lifetime: lifetime,
        },
    )
}

async fn drive<S>(
    mut transport: Transport<S>,
    mut commands: mpsc::Receiver<Command>,
    incoming: &mpsc::Sender<Result<Bytes>>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    transport.ensure_usable()?;
    let mut delivery = None;
    let mut commands_closed = false;
    loop {
        if transport.needs_rekey() {
            transport.rekey().await?;
        }
        tokio::select! {
            _ = incoming.closed() => return Ok(()),
            permit = incoming.reserve(), if delivery.is_some() => {
                permit.map_err(|_| Error::Disconnected)?
                    .send(Ok(delivery.take().expect("pending delivery")));
            }
            command = commands.recv(), if !commands_closed => {
                let Some(command) = command else {
                    commands_closed = true;
                    continue;
                };
                let (reply, result) = match command {
                    Command::Send(packet, reply) => (reply, transport.send(packet).await),
                    Command::SendBatch(packets, reply) => (reply, transport.send_batch(packets).await),
                    Command::Rekey(reply) => (reply, transport.rekey().await),
                };
                let terminal = result.as_ref().err().map(|error| Error::Driver(error.to_string()));
                // Cancelled send/rekey waiters do not cancel the wire operation.
                let _ = reply.send(result);
                if let Some(error) = terminal {
                    return Err(error);
                }
            }
            packet = next_relay_packet(&mut transport), if delivery.is_none() => {
                delivery = transport.handle_packet(packet?).await?;
            }
        }
    }
}
