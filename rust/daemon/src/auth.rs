use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use rsa::{pkcs1::DecodeRsaPublicKey, pkcs8::DecodePublicKey};
use sha2::Digest;
use ssh_encoding::Encode;
use ssh_key::{Algorithm, Certificate, PublicKey, Signature};
use sshpiper_transport::{
    wire::{extensions, string, Reader},
    Transport,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::{
    config::Config,
    keys::{self, UpstreamVerifier},
    plugin::{BoxConnection, Plugin},
    proto::{plugin::*, signer},
};

type Ssh = Transport<BoxConnection>;

pub struct Authenticated {
    pub downstream: Ssh,
    pub upstream: Ssh,
    pub meta: ConnMeta,
    pub upstream_user: String,
    pub upstream_addr: String,
    pub env: HashMap<String, String>,
}

#[derive(Default)]
struct Banners {
    seen: HashSet<Vec<u8>>,
    count: usize,
}

impl Banners {
    async fn forward(&mut self, downstream: &mut Ssh, packet: Bytes, mode: &str) -> Result<()> {
        let mut reader = Reader(&packet[1..]);
        let message = reader.string()?.to_vec();
        reader.string()?;
        reader.end()?;
        let send = match mode {
            "ignore" => false,
            "first-only" => self.count == 0,
            "dedup" => !self.seen.contains(&message),
            _ => true,
        };
        if send {
            downstream.send(packet).await?;
        }
        self.seen.insert(message);
        self.count += 1;
        Ok(())
    }
}

async fn banner(downstream: &mut Ssh, message: &str) -> Result<()> {
    if !message.is_empty() {
        let mut packet = vec![53];
        string(&mut packet, message.as_bytes());
        string(&mut packet, b"");
        downstream.send(packet.into()).await?;
    }
    Ok(())
}

fn request(user: &str, method: &str) -> Vec<u8> {
    let mut packet = vec![50];
    string(&mut packet, user.as_bytes());
    string(&mut packet, b"ssh-connection");
    string(&mut packet, method.as_bytes());
    packet
}

async fn failure(
    downstream: &mut Ssh,
    plugin: &Plugin,
    meta: &ConnMeta,
    partial: bool,
) -> Result<()> {
    let mut packet = vec![51];
    string(
        &mut packet,
        plugin.methods(meta).await?.join(",").as_bytes(),
    );
    packet.push(u8::from(partial));
    downstream.send(packet.into()).await?;
    Ok(())
}

pub async fn authenticate(
    mut downstream: Ssh,
    plugins: &[Plugin],
    source: &str,
    config: &Config,
) -> Result<Authenticated> {
    if downstream.peer_accepts_extensions() {
        let mut extensions = vec![7];
        extensions.extend_from_slice(&1_u32.to_be_bytes());
        string(&mut extensions, b"server-sig-algs");
        let algorithms = if config.allowed_downstream_pubkey_algos.is_empty() {
            "ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384"
                .to_owned()
        } else {
            config.allowed_downstream_pubkey_algos.join(",")
        };
        string(&mut extensions, algorithms.as_bytes());
        downstream.send(extensions.into()).await?;
    }
    let mut service = downstream.recv().await?;
    if service[0] == 7 {
        extensions(&service)?;
        service = downstream.recv().await?;
    }
    let mut reader = Reader(&service);
    if reader.byte()? != 5 || reader.string()? != b"ssh-userauth" {
        bail!("expected ssh-userauth service request");
    }
    reader.end()?;
    let mut accept = vec![6];
    string(&mut accept, b"ssh-userauth");
    downstream.send(accept.into()).await?;
    let mut meta: Option<ConnMeta> = None;
    let mut index = 0;
    let mut failures = 0;
    let mut cached_key: Option<(String, Vec<u8>, Upstream)> = None;
    let mut banners = Banners::default();
    loop {
        if failures >= 6 {
            bail!("too many authentication failures");
        }
        let packet = downstream.recv().await?;
        if packet[0] == 7 {
            continue;
        }
        let mut reader = Reader(&packet);
        if reader.byte()? != 50 {
            bail!("expected SSH user authentication request");
        }
        let user = reader.text()?.to_owned();
        if reader.string()? != b"ssh-connection" {
            bail!("unsupported SSH authentication service");
        }
        let method = reader.text()?.to_owned();
        if method != "publickey" {
            cached_key = None;
        }
        if meta.is_none() {
            let connection = ConnMeta {
                user_name: user.clone(),
                from_addr: source.to_owned(),
                uniq_id: uuid::Uuid::new_v4().to_string(),
                metadata: HashMap::new(),
            };
            for plugin in plugins {
                if plugin.has("NewConnection") {
                    plugin
                        .client()
                        .new_connection(NewConnectionRequest {
                            meta: Some(connection.clone()),
                        })
                        .await?;
                }
            }
            if let Some(text) = &config.banner_text {
                banner(&mut downstream, text).await?;
            }
            if let Some(path) = &config.banner_file {
                banner(&mut downstream, &tokio::fs::read_to_string(path).await?).await?;
            }
            meta = Some(connection);
            if plugins[index].has("Banner") {
                let message = plugins[index]
                    .client()
                    .banner(BannerRequest { meta: meta.clone() })
                    .await?
                    .into_inner()
                    .message;
                banner(&mut downstream, &message).await?;
            }
        }
        let meta = meta.as_mut().context("missing connection metadata")?;
        if meta.user_name != user {
            bail!("username changed during authentication");
        }
        let plugin = &plugins[index];
        if !plugin.methods(meta).await?.contains(&method.as_str()) {
            if method != "none" {
                failures += 1;
            }
            failure(&mut downstream, plugin, meta, false).await?;
            continue;
        }
        let result: Result<Option<Upstream>> = async {
            match method.as_str() {
                "none" if plugin.has("NoneAuth") => {
                    reader.end()?;
                    Ok(plugin
                        .client()
                        .none_auth(NoneAuthRequest {
                            meta: Some(meta.clone()),
                        })
                        .await?
                        .into_inner()
                        .upstream)
                }
                "password" if plugin.has("PasswordAuth") => {
                    cached_key = None;
                    if reader.boolean()? {
                        bail!("password changes are not supported");
                    }
                    let password = reader.string()?.to_vec();
                    reader.end()?;
                    Ok(plugin
                        .client()
                        .password_auth(PasswordAuthRequest {
                            meta: Some(meta.clone()),
                            password,
                        })
                        .await?
                        .into_inner()
                        .upstream)
                }
                "publickey" if plugin.has("PublicKeyAuth") => {
                    let signed = reader.boolean()?;
                    let algorithm = reader.text()?.to_owned();
                    let encoded = reader.string()?.to_vec();
                    let key = sshpiper_transport::public_key(&encoded)?;
                    let signature_algorithm = sshpiper_transport::signature_algorithm(&algorithm);
                    let supported = [
                        "ssh-ed25519",
                        "rsa-sha2-512",
                        "rsa-sha2-256",
                        "ecdsa-sha2-nistp256",
                        "ecdsa-sha2-nistp384",
                    ];
                    if !supported.contains(&signature_algorithm)
                        || (!config.allowed_downstream_pubkey_algos.is_empty()
                            && !config
                                .allowed_downstream_pubkey_algos
                                .iter()
                                .any(|name| name == signature_algorithm))
                    {
                        bail!("unsupported downstream public-key algorithm");
                    }
                    let encoded_algorithm = Reader(&encoded).text()?.to_owned();
                    let expected = if key.algorithm().is_rsa() {
                        if algorithm.ends_with("-cert-v01@openssh.com") {
                            "ssh-rsa-cert-v01@openssh.com"
                        } else {
                            "ssh-rsa"
                        }
                    } else {
                        &algorithm
                    };
                    if encoded_algorithm != expected {
                        bail!("public-key algorithm does not match key");
                    }
                    if signed {
                        let signed_len = packet.len() - reader.0.len();
                        let signature = reader.string()?;
                        reader.end()?;
                        let mut signed_data = Vec::new();
                        string(&mut signed_data, downstream.session_id());
                        signed_data.extend_from_slice(&packet[..signed_len]);
                        sshpiper_transport::verify_signature(
                            &key,
                            &signed_data,
                            signature,
                            &algorithm,
                        )?;
                    } else {
                        reader.end()?;
                    }
                    let upstream = match cached_key.take() {
                        Some((cached_algorithm, cached_encoded, upstream))
                            if cached_algorithm == algorithm && cached_encoded == encoded =>
                        {
                            Some(upstream)
                        }
                        _ => {
                            plugin
                                .client()
                                .public_key_auth(PublicKeyAuthRequest {
                                    meta: Some(meta.clone()),
                                    public_key: encoded.clone(),
                                })
                                .await?
                                .into_inner()
                                .upstream
                        }
                    }
                    .context("plugin returned no upstream for public-key authentication")?;
                    if !signed {
                        let mut reply = vec![60];
                        string(&mut reply, algorithm.as_bytes());
                        string(&mut reply, &encoded);
                        downstream.send(reply.into()).await?;
                        cached_key = Some((algorithm, encoded, upstream));
                        return Ok(None);
                    }
                    Ok(Some(upstream))
                }
                "keyboard-interactive" if plugin.has("KeyboardInteractiveAuth") => {
                    cached_key = None;
                    reader.string()?;
                    reader.string()?;
                    reader.end()?;
                    Ok(Some(
                        keyboard_interactive(&mut downstream, plugin, meta).await?,
                    ))
                }
                _ => bail!("plugin does not implement authentication method {method}"),
            }
        }
        .await;
        let upstream = match result {
            Ok(Some(upstream)) => upstream,
            Ok(None) if cached_key.is_some() => continue,
            Ok(None) => {
                tracing::warn!(plugin = plugin.name, "plugin returned no upstream");
                failures += 1;
                failure(&mut downstream, plugin, meta, false).await?;
                continue;
            }
            Err(error) => {
                tracing::warn!(plugin = plugin.name, %error, "downstream authentication failed");
                failures += 1;
                failure(&mut downstream, plugin, meta, false).await?;
                continue;
            }
        };
        match &upstream.auth {
            Some(upstream::Auth::NextPlugin(next)) => {
                if index + 1 >= plugins.len() {
                    bail!("plugin requested next plugin beyond end of chain");
                }
                meta.metadata.extend(next.meta.clone());
                index += 1;
                cached_key = None;
                if plugins[index].has("Banner") {
                    let message = plugins[index]
                        .client()
                        .banner(BannerRequest {
                            meta: Some(meta.clone()),
                        })
                        .await?
                        .into_inner()
                        .message;
                    banner(&mut downstream, &message).await?;
                }
                failure(&mut downstream, &plugins[index], meta, true).await?;
            }
            Some(upstream::Auth::RetryCurrentPlugin(retry)) => {
                meta.metadata.extend(retry.meta.clone());
                failures += 1;
                failure(&mut downstream, plugin, meta, false).await?;
            }
            _ => match connect_upstream(
                &mut downstream,
                plugin,
                meta,
                &upstream,
                &mut banners,
                config,
            )
            .await
            {
                Ok((up, upstream_addr, upstream_user)) => {
                    downstream.send(Bytes::from_static(&[52])).await?;
                    return Ok(Authenticated {
                        downstream,
                        upstream: up,
                        meta: meta.clone(),
                        upstream_addr,
                        upstream_user,
                        env: upstream.env,
                    });
                }
                Err(error) => {
                    tracing::warn!(%error, "upstream authentication failed");
                    for plugin in plugins {
                        if plugin.has("UpstreamAuthFailure") {
                            if let Err(notice_error) = plugin
                                .client()
                                .upstream_auth_failure_notice(UpstreamAuthFailureNoticeRequest {
                                    meta: Some(meta.clone()),
                                    method: method.clone(),
                                    error: error.to_string(),
                                    allowed_methods: Vec::new(),
                                })
                                .await
                            {
                                tracing::warn!(%notice_error, "upstream failure notification failed");
                            }
                        }
                    }
                    failures += 1;
                    failure(&mut downstream, plugin, meta, false).await?;
                }
            },
        }
    }
}

async fn keyboard_interactive(
    downstream: &mut Ssh,
    plugin: &Plugin,
    meta: &ConnMeta,
) -> Result<Upstream> {
    use keyboard_interactive_auth_message::Message;
    let (tx, rx) = mpsc::channel(8);
    let mut stream = plugin
        .client()
        .keyboard_interactive_auth(ReceiverStream::new(rx))
        .await?
        .into_inner();
    while let Some(message) = stream.message().await? {
        let reply = match message
            .message
            .context("empty keyboard-interactive RPC message")?
        {
            Message::MetaRequest(_) => Message::MetaResponse(KeyboardInteractiveMetaResponse {
                meta: Some(meta.clone()),
            }),
            Message::FinishRequest(finish) => {
                return finish
                    .upstream
                    .context("keyboard-interactive finished without upstream")
            }
            Message::PromptRequest(prompt) => {
                let mut packet = vec![60];
                string(&mut packet, prompt.name.as_bytes());
                string(&mut packet, prompt.instruction.as_bytes());
                string(&mut packet, b"");
                packet.extend_from_slice(&u32::try_from(prompt.questions.len())?.to_be_bytes());
                for question in &prompt.questions {
                    string(&mut packet, question.text.as_bytes());
                    packet.push(u8::from(question.echo));
                }
                downstream.send(packet.into()).await?;
                let packet = downstream.recv().await?;
                let mut reader = Reader(&packet);
                if reader.byte()? != 61 || reader.uint()? as usize != prompt.questions.len() {
                    bail!("invalid keyboard-interactive response");
                }
                let mut answers = Vec::with_capacity(prompt.questions.len());
                for _ in &prompt.questions {
                    answers.push(reader.text()?.to_owned());
                }
                reader.end()?;
                if answers.is_empty() {
                    continue;
                }
                Message::UserResponse(KeyboardInteractiveUserResponse { answers })
            }
            _ => bail!("unexpected keyboard-interactive RPC message"),
        };
        tx.send(KeyboardInteractiveAuthMessage {
            message: Some(reply),
        })
        .await?;
    }
    bail!("keyboard-interactive RPC ended before authentication completed")
}

async fn upstream_packet(
    upstream: &mut Ssh,
    downstream: &mut Ssh,
    banners: &mut Banners,
    mode: &str,
) -> Result<Bytes> {
    loop {
        let packet = upstream.recv().await?;
        match packet[0] {
            7 => continue,
            53 => banners.forward(downstream, packet, mode).await?,
            _ => return Ok(packet),
        }
    }
}

#[allow(deprecated)]
async fn connect_upstream(
    downstream: &mut Ssh,
    plugin: &Plugin,
    meta: &ConnMeta,
    selected: &Upstream,
    banners: &mut Banners,
    config: &Config,
) -> Result<(Ssh, String, String)> {
    let uri = if selected.uri.is_empty() {
        let port = if selected.port == 0 {
            22
        } else {
            u16::try_from(selected.port)?
        };
        if selected.host.is_empty() {
            bail!("empty upstream address");
        }
        let host = if selected.host.contains(':') {
            format!("[{}]", selected.host)
        } else {
            selected.host.clone()
        };
        format!("tcp://{host}:{port}")
    } else {
        selected.uri.clone()
    };
    let parsed = url::Url::parse(&uri)?;
    let address = if let Some(host) = parsed.host_str() {
        let host = host.trim_matches(['[', ']']);
        let port = parsed.port().unwrap_or(22);
        if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    } else {
        uri.clone()
    };
    let (connection, netaddress): (BoxConnection, String) = if plugin.has("CreateConn") {
        (plugin.create_connection(uri.clone()).await?, uri.clone())
    } else {
        match parsed.scheme() {
            "tcp" | "tcp4" | "tcp6" => {
                let addresses = tokio::net::lookup_host(&address).await?;
                let addresses: Vec<_> = addresses
                    .filter(|addr| match parsed.scheme() {
                        "tcp4" => addr.is_ipv4(),
                        "tcp6" => addr.is_ipv6(),
                        _ => true,
                    })
                    .collect();
                let stream = tokio::net::TcpStream::connect(addresses.as_slice()).await?;
                stream.set_nodelay(true)?;
                let remote = stream.peer_addr()?.to_string();
                (Box::new(stream), remote)
            }
            #[cfg(unix)]
            "unix" => (
                Box::new(tokio::net::UnixStream::connect(parsed.path()).await?),
                uri.clone(),
            ),
            scheme => bail!("unsupported upstream URI scheme {scheme}"),
        }
    };
    let verifier = UpstreamVerifier {
        plugin: plugin.clone(),
        meta: meta.clone(),
        hostname: address.clone(),
        netaddress,
        known_hosts: selected.known_hosts_data.clone(),
    };
    let mut upstream = Transport::connect_verified(connection, Arc::new(verifier)).await?;
    let mut service = vec![5];
    string(&mut service, b"ssh-userauth");
    upstream.send(service.into()).await?;
    let packet = upstream_packet(
        &mut upstream,
        downstream,
        banners,
        &config.upstream_banner_mode,
    )
    .await?;
    let mut reader = Reader(&packet);
    if reader.byte()? != 6 || reader.string()? != b"ssh-userauth" {
        bail!("upstream rejected authentication service");
    }
    reader.end()?;
    let user = if selected.user_name.is_empty() {
        &meta.user_name
    } else {
        &selected.user_name
    };
    upstream.send(request(user, "none").into()).await?;
    let packet = upstream_packet(
        &mut upstream,
        downstream,
        banners,
        &config.upstream_banner_mode,
    )
    .await?;
    if packet.as_ref() == [52] {
        return Ok((upstream, address, user.clone()));
    }
    if packet[0] != 51 {
        bail!("unexpected upstream authentication message");
    }
    let mut packet = match &selected.auth {
        Some(upstream::Auth::Password(password)) => {
            let mut packet = request(user, "password");
            packet.push(0);
            string(&mut packet, password.password.as_bytes());
            packet
        }
        Some(upstream::Auth::PrivateKey(credentials)) => {
            let private = keys::private_key(&credentials.private_key)?;
            let (encoded, algorithm) = if credentials.ca_public_key.is_empty() {
                (
                    private.public_key().to_bytes()?,
                    if private.algorithm().is_rsa() {
                        "rsa-sha2-512".to_owned()
                    } else {
                        private.algorithm().as_str().to_owned()
                    },
                )
            } else {
                let cert =
                    Certificate::from_openssh(std::str::from_utf8(&credentials.ca_public_key)?)?;
                if cert.public_key() != private.public_key().key_data() {
                    bail!("upstream certificate does not match private key");
                }
                let algorithm = if private.algorithm().is_rsa() {
                    "rsa-sha2-512-cert-v01@openssh.com".to_owned()
                } else {
                    cert.algorithm().to_certificate_type()
                };
                (cert.to_bytes()?, algorithm)
            };
            let (mut packet, signed) = public_key_request(&upstream, user, &encoded, &algorithm);
            string(
                &mut packet,
                &sshpiper_transport::sign(&private, &signed, &algorithm)?,
            );
            packet
        }
        Some(upstream::Auth::RemoteSigner(remote)) => {
            let mut client = signer::signer_client::SignerClient::new(plugin.channel.clone());
            let key = client
                .public_key(signer::PublicKeyRequest {
                    metadata: remote.meta.clone(),
                })
                .await?
                .into_inner();
            let rsa = match key.r#type.as_str() {
                "PKCS1" => rsa::RsaPublicKey::from_pkcs1_der(&key.data)?,
                "PKIX" => rsa::RsaPublicKey::from_public_key_der(&key.data)?,
                kind => bail!("unsupported remote signer public key encoding {kind}"),
            };
            let key = PublicKey::new(ssh_key::public::KeyData::Rsa(rsa.try_into()?), "");
            let (mut packet, signed) =
                public_key_request(&upstream, user, &key.to_bytes()?, "rsa-sha2-512");
            let signature = client
                .sign(signer::SignRequest {
                    digest: sha2::Sha512::digest(&signed).to_vec(),
                    algorithm: "RSASSA_PKCS1_V1_5_SHA_512".into(),
                    metadata: remote.meta.clone(),
                })
                .await?
                .into_inner()
                .signature;
            let signature = Signature::new(Algorithm::new("rsa-sha2-512")?, signature)?;
            let mut encoded = Vec::new();
            signature.encode(&mut encoded)?;
            sshpiper_transport::verify_signature(&key, &signed, &encoded, "rsa-sha2-512")?;
            string(&mut packet, &encoded);
            packet
        }
        _ => bail!("upstream rejected none authentication"),
    };
    upstream.send(std::mem::take(&mut packet).into()).await?;
    let packet = upstream_packet(
        &mut upstream,
        downstream,
        banners,
        &config.upstream_banner_mode,
    )
    .await?;
    if packet.as_ref() != [52] {
        if packet[0] == 51 {
            let mut reader = Reader(&packet[1..]);
            bail!(
                "upstream authentication failed; allowed methods: {}",
                reader.text()?
            );
        }
        bail!("unexpected upstream authentication response {}", packet[0]);
    }
    Ok((upstream, address, user.clone()))
}

fn public_key_request(
    upstream: &Ssh,
    user: &str,
    key: &[u8],
    algorithm: &str,
) -> (Vec<u8>, Vec<u8>) {
    let mut packet = request(user, "publickey");
    packet.push(1);
    string(&mut packet, algorithm.as_bytes());
    string(&mut packet, key);
    let mut signed = Vec::new();
    string(&mut signed, upstream.session_id());
    signed.extend_from_slice(&packet);
    (packet, signed)
}
