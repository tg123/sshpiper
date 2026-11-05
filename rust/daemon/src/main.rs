use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Parser;
use sshpiper_transport::Transport;
use sshpiperd::{
    admin::{timestamp, LiveSession, Registry},
    auth,
    config::Config,
    keys,
    plugin::{BoxConnection, Plugin, Runtime},
    proto::{admin::Session, plugin::*},
    relay,
};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    task::JoinSet,
};
use tracing_subscriber::EnvFilter;

mod logging;

fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args_os().collect();
    #[cfg(target_os = "linux")]
    {
        if arguments
            .get(1)
            .is_some_and(|arg| arg == "--internal-plugin-parent")
        {
            use std::os::unix::process::CommandExt;
            let parent: i32 = arguments
                .get(2)
                .context("missing plugin parent PID")?
                .to_str()
                .context("invalid PID")?
                .parse()?;
            nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGKILL)?;
            if nix::unistd::getppid().as_raw() != parent {
                bail!("plugin parent exited before startup");
            }
            let executable = arguments.get(3).context("missing plugin executable")?;
            return Err(std::process::Command::new(executable)
                .args(&arguments[4..])
                .exec())
            .context("executing plugin");
        }
    }
    let config = match arguments.get(1).and_then(|arg| arg.to_str()) {
        Some("--internal-snap-configure") if arguments.len() == 2 => {
            return sshpiperd::snap::configure();
        }
        Some("--internal-snap-launch") if arguments.len() == 2 => sshpiperd::snap::load()?,
        _ => Config::parse_from(arguments),
    };
    let level = if config.log_level == "trace" {
        "trace"
    } else {
        config.log_level.as_str()
    };
    let filter = EnvFilter::try_new(format!("warn,sshpiperd={level},sshpiper_transport={level}"))?;
    if config.log_format == "json" {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .event_format(logging::Json)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .init();
    }
    config.validate()?;
    #[cfg(windows)]
    {
        let mut limits = win32job::ExtendedLimitInfo::new();
        limits.limit_kill_on_job_close();
        let job = win32job::Job::create_with_limit_info(&limits)?;
        job.assign_current_process()?;
        // Retain the non-inheritable handle until process exit, including forced
        // termination. All subsequently spawned plugins inherit job membership.
        std::mem::forget(job);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    if let Err(error) = runtime.block_on(run(Arc::new(config))) {
        tracing::error!(%error, "daemon stopped");
        return Err(error);
    }
    Ok(())
}

async fn shutdown() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            signal = tokio::signal::ctrl_c() => signal?,
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn run(config: Arc<Config>) -> Result<()> {
    let identities = Arc::new(keys::host_identities(&config)?);
    let root = relay::recording_root(&config)?;
    let mut runtime = Runtime::start(config.plugin_commands()?, &config.log_level).await?;
    let plugins = Arc::new(runtime.plugins.clone());
    let listener = TcpListener::bind((config.address.as_str(), config.port)).await?;
    let registry = Registry::new(&config, listener.local_addr()?.to_string())?;
    let mut services = JoinSet::new();
    if config.admin_grpc_port != 0 {
        let registry = registry.clone();
        let config = config.clone();
        services.spawn(async move { registry.serve(&config).await });
    }
    tracing::info!(address = %listener.local_addr()?, "sshpiperd is listening");
    let mut connections = JoinSet::new();
    let shutdown = shutdown();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            result = &mut shutdown => { result?; return Ok(()); }
            result = runtime.wait() => return result,
            result = services.join_next(), if !services.is_empty() => {
                result.context("admin service stopped")???;
                bail!("admin service stopped");
            }
            result = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = result { tracing::error!(%error, "connection task failed"); }
            }
            connection = listener.accept() => {
                let (stream, peer) = connection?;
                stream.set_nodelay(true)?;
                let (config, plugins, identities, root, registry) = (config.clone(), plugins.clone(), identities.clone(), root.clone(), registry.clone());
                connections.spawn(async move {
                    let mut source = peer.to_string();
                    let handshake = async {
                        let (stream, resolved) = proxy_connection(stream, &config).await?;
                        source = resolved;
                        let downstream = Transport::accept_with_algorithms(stream, identities.as_ref().clone(), config.transport_algorithms()?).await?;
                        auth::authenticate(downstream, &plugins, &source, &config).await
                    };
                    let session = if config.login_grace_time.is_zero() {
                        handshake.await
                    } else {
                        match tokio::time::timeout(config.login_grace_time, handshake).await {
                            Ok(result) => result,
                            Err(error) => Err(error.into()),
                        }
                    };
                    match session {
                        Ok(session) => {
                            let meta = session.meta.clone();
                            let live = LiveSession::new(Session {
                                id: meta.uniq_id.clone(), downstream_user: meta.user_name.clone(), downstream_addr: meta.from_addr.clone(),
                                upstream_user: session.upstream_user.clone(), upstream_addr: session.upstream_addr.clone(), started_at: timestamp(), streamable: false,
                            });
                            registry.insert(live.clone());
                            notices(&plugins, &meta, None).await;
                            let result = relay::relay(session, config, root, live.clone()).await;
                            live.cancel.cancel();
                            registry.remove(&meta.uniq_id);
                            let message = result.as_ref().err().map(ToString::to_string).unwrap_or_else(|| "session closed".into());
                            notices(&plugins, &meta, Some(&message)).await;
                            if let Err(error) = result { tracing::debug!(%peer, %error, "SSH pipe closed"); }
                        }
                        Err(error) => {
                            tracing::warn!(%peer, %error, "SSH pipe creation failed");
                            for plugin in plugins.iter().filter(|plugin| plugin.has("PipeCreateError")) {
                                if let Err(error) = plugin.client().pipe_create_error_notice(PipeCreateErrorNoticeRequest { from_addr: source.clone(), error: error.to_string() }).await {
                                    tracing::warn!(%error, "pipe creation notification failed");
                                }
                            }
                        }
                    }
                });
            }
        }
    }
}

async fn notices(plugins: &[Plugin], meta: &ConnMeta, error: Option<&str>) {
    for plugin in plugins {
        let result = if let Some(error) = error {
            if !plugin.has("PipeError") {
                continue;
            }
            plugin
                .client()
                .pipe_error_notice(PipeErrorNoticeRequest {
                    meta: Some(meta.clone()),
                    error: error.to_owned(),
                })
                .await
                .map(|_| ())
        } else {
            if !plugin.has("PipeStart") {
                continue;
            }
            plugin
                .client()
                .pipe_start_notice(PipeStartNoticeRequest {
                    meta: Some(meta.clone()),
                })
                .await
                .map(|_| ())
        };
        if let Err(error) = result {
            tracing::warn!(plugin = plugin.name, %error, "pipe lifecycle notification failed");
        }
    }
}

async fn proxy_connection(
    mut stream: TcpStream,
    config: &Config,
) -> Result<(BoxConnection, String)> {
    let peer = stream.peer_addr()?;
    if !config
        .allowed_proxy_addresses
        .iter()
        .any(|network| network.contains(&peer.ip()))
    {
        return Ok((Box::new(stream), peer.to_string()));
    }
    let mut prefix = Vec::new();
    let detection = tokio::time::timeout(config.proxy_read_header_timeout, async {
        loop {
            let byte = stream.read_u8().await?;
            prefix.push(byte);
            if b"PROXY ".starts_with(&prefix) {
                if prefix.len() == 6 {
                    return Ok::<_, anyhow::Error>(1);
                }
            } else if b"\r\n\r\n\0\r\nQUIT\n".starts_with(&prefix) {
                if prefix.len() == 12 {
                    return Ok(2);
                }
            } else {
                return Ok(0);
            }
        }
    })
    .await;
    let kind = match detection {
        Ok(result) => result?,
        Err(_) if prefix.is_empty() => 0,
        Err(error) => return Err(error).context("truncated PROXY header"),
    };
    let mut source = peer.to_string();
    if kind != 0 {
        source = tokio::time::timeout(config.proxy_read_header_timeout, async {
            if kind == 1 {
                while !prefix.ends_with(b"\r\n") {
                    if prefix.len() >= 108 {
                        bail!("PROXY v1 header exceeds maximum length");
                    }
                    prefix.push(stream.read_u8().await?);
                }
                let fields: Vec<_> = std::str::from_utf8(&prefix)?.split_whitespace().collect();
                if fields.get(1) == Some(&"UNKNOWN") {
                    return Ok(peer.to_string());
                }
                if fields.len() != 6 || !["TCP4", "TCP6"].contains(&fields[1]) {
                    bail!("invalid PROXY v1 header");
                }
                let address: std::net::IpAddr = fields[2].parse()?;
                let destination: std::net::IpAddr = fields[3].parse()?;
                if (fields[1] == "TCP4") != address.is_ipv4()
                    || address.is_ipv4() != destination.is_ipv4()
                {
                    bail!("PROXY v1 address family mismatch");
                }
                let port: u16 = fields[4].parse()?;
                let _: u16 = fields[5].parse()?;
                Ok(std::net::SocketAddr::new(address, port).to_string())
            } else {
                let version_command = stream.read_u8().await?;
                let family = stream.read_u8().await?;
                let size = stream.read_u16().await? as usize;
                let mut bytes = vec![0; size];
                stream.read_exact(&mut bytes).await?;
                if version_command == 0x20 {
                    return Ok(peer.to_string());
                }
                if version_command != 0x21 {
                    bail!("invalid PROXY v2 command");
                }
                let (ip, port) = match family {
                    0x11 if bytes.len() >= 12 => (
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                            bytes[0], bytes[1], bytes[2], bytes[3],
                        )),
                        u16::from_be_bytes([bytes[8], bytes[9]]),
                    ),
                    0x21 if bytes.len() >= 36 => (
                        std::net::IpAddr::V6(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(
                            &bytes[..16],
                        )?)),
                        u16::from_be_bytes([bytes[32], bytes[33]]),
                    ),
                    _ => bail!("unsupported PROXY v2 address family"),
                };
                Ok(std::net::SocketAddr::new(ip, port).to_string())
            }
        })
        .await??;
        prefix.clear();
    }
    let (reader, writer) = stream.into_split();
    let reader = std::io::Cursor::new(prefix).chain(reader);
    Ok((Box::new(tokio::io::join(reader, writer)), source))
}
