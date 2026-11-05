use std::{
    collections::HashSet,
    ffi::OsString,
    io,
    pin::Pin,
    process::Stdio,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{anyhow, bail, Context as _, Result};
use clap::Parser;
use futures_util::Stream;
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    process::Command,
    sync::{mpsc, Mutex},
    task::JoinSet,
};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::PollSender;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tower::service_fn;

use crate::proto::{
    connection::{self, packet::Payload},
    plugin::{self, ssh_piper_plugin_client::SshPiperPluginClient},
};

pub type Client = SshPiperPluginClient<Channel>;
pub trait Connection: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Connection for T {}
pub type BoxConnection = Box<dyn Connection>;

#[derive(Clone)]
pub struct Plugin {
    pub name: String,
    pub channel: Channel,
    callbacks: HashSet<String>,
}

impl Plugin {
    pub fn client(&self) -> Client {
        Client::new(self.channel.clone())
    }

    pub fn has(&self, callback: &str) -> bool {
        self.callbacks.contains(callback)
    }

    pub async fn methods(&self, meta: &plugin::ConnMeta) -> Result<Vec<&'static str>> {
        if self.has("NextAuthMethods") {
            let reply = self
                .client()
                .next_auth_methods(plugin::NextAuthMethodsRequest {
                    meta: Some(meta.clone()),
                })
                .await?
                .into_inner();
            return reply
                .methods
                .into_iter()
                .map(|method| match method {
                    0 => Ok("none"),
                    1 => Ok("password"),
                    2 => Ok("publickey"),
                    3 => Ok("keyboard-interactive"),
                    _ => Err(anyhow!(
                        "plugin returned unknown authentication method {method}"
                    )),
                })
                .collect();
        }
        Ok([
            ("NoneAuth", "none"),
            ("PasswordAuth", "password"),
            ("PublicKeyAuth", "publickey"),
            ("KeyboardInteractiveAuth", "keyboard-interactive"),
        ]
        .into_iter()
        .filter_map(|(callback, method)| self.has(callback).then_some(method))
        .collect())
    }

    pub async fn create_connection(&self, uri: String) -> Result<BoxConnection> {
        let (tx, rx) = mpsc::channel(8);
        tx.send(connection::Packet {
            payload: Some(Payload::DialRequest(connection::DialRequest { uri })),
        })
        .await?;
        let incoming =
            connection::conn_over_grpc_client::ConnOverGrpcClient::new(self.channel.clone())
                .create_conn(ReceiverStream::new(rx))
                .await?
                .into_inner();
        Ok(Box::new(GrpcConnection {
            incoming,
            outgoing: PollSender::new(tx),
            pending: bytes::Bytes::new(),
        }))
    }
}

pub struct Runtime {
    pub plugins: Vec<Plugin>,
    tasks: JoinSet<Result<()>>,
}

impl Runtime {
    pub async fn start(commands: Vec<Vec<OsString>>, level: &str) -> Result<Self> {
        let mut runtime = Self {
            plugins: Vec::new(),
            tasks: JoinSet::new(),
        };
        for command in commands {
            let name = command[0].to_string_lossy().into_owned();
            let channel = if command[0] == "grpc" {
                network_channel(&command).await?
            } else {
                let mut process = plugin_command(&command)?;
                let mut child = process
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .kill_on_drop(true)
                    .spawn()
                    .with_context(|| format!("starting plugin {name}"))?;
                let reader = child.stdout.take().context("plugin stdout unavailable")?;
                let writer = child.stdin.take().context("plugin stdin unavailable")?;
                let io = Arc::new(Mutex::new(Some(tokio::io::join(reader, writer))));
                let label = name.clone();
                runtime.tasks.spawn(async move {
                    let status = child.wait().await?;
                    bail!("plugin {label} exited: {status}");
                });
                Endpoint::from_static("http://127.0.0.1")
                    .connect_timeout(Duration::from_secs(30))
                    .connect_with_connector(service_fn(move |_| {
                        let io = io.clone();
                        async move {
                            io.lock().await.take().map(TokioIo::new).ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::BrokenPipe,
                                    "plugin stdio connection closed",
                                )
                            })
                        }
                    }))
                    .await?
            };
            let mut client = Client::new(channel.clone());
            let callbacks = client
                .list_callbacks(plugin::ListCallbackRequest {})
                .await?
                .into_inner()
                .callbacks;
            for callback in &callbacks {
                if ![
                    "NewConnection",
                    "CreateConn",
                    "NextAuthMethods",
                    "NoneAuth",
                    "PasswordAuth",
                    "PublicKeyAuth",
                    "KeyboardInteractiveAuth",
                    "UpstreamAuthFailure",
                    "Banner",
                    "VerifyHostKey",
                    "PipeStart",
                    "PipeError",
                    "PipeCreateError",
                ]
                .contains(&callback.as_str())
                {
                    bail!("unknown plugin callback {callback}");
                }
            }
            let log_level = level.to_owned();
            let log_name = name.clone();
            runtime.tasks.spawn(async move {
                let result: Result<()> = async {
                    let mut logs = client
                        .logs(plugin::StartLogRequest {
                            uniq_id: uuid::Uuid::new_v4().to_string(),
                            level: log_level,
                            tty: false,
                        })
                        .await?
                        .into_inner();
                    while let Some(log) = logs.message().await? {
                        eprintln!("{}", log.message);
                    }
                    Ok(())
                }
                .await;
                if let Err(error) = result {
                    tracing::error!(plugin = log_name, %error, "plugin log stream stopped");
                }
                Ok(())
            });
            runtime.plugins.push(Plugin {
                name,
                channel,
                callbacks: callbacks.into_iter().collect(),
            });
        }
        Ok(runtime)
    }

    pub async fn wait(&mut self) -> Result<()> {
        while let Some(result) = self.tasks.join_next().await {
            result??;
        }
        bail!("all plugin tasks stopped")
    }
}

fn plugin_command(args: &[OsString]) -> Result<Command> {
    #[cfg(target_os = "linux")]
    {
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg("--internal-plugin-parent")
            .arg(std::process::id().to_string())
            .args(args);
        Ok(command)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut command = Command::new(&args[0]);
        command.args(&args[1..]);
        Ok(command)
    }
}

#[derive(Parser)]
struct GrpcOptions {
    #[arg(long, env = "SSHPIPERD_GRPC_ENDPOINT")]
    endpoint: String,
    #[arg(long, env = "SSHPIPERD_GRPC_INSECURE")]
    insecure: bool,
    #[arg(long, env = "SSHPIPERD_GRPC_KEY")]
    key: Option<String>,
    #[arg(long, env = "SSHPIPERD_GRPC_CERT")]
    cert: Option<String>,
    #[arg(long, env = "SSHPIPERD_GRPC_CACERT")]
    cacert: Option<String>,
}

async fn network_channel(args: &[OsString]) -> Result<Channel> {
    let options = GrpcOptions::try_parse_from(args)?;
    let scheme = if options.insecure { "http" } else { "https" };
    let mut endpoint = Endpoint::from_shared(format!("{scheme}://{}", options.endpoint))?
        .connect_timeout(Duration::from_secs(30));
    if !options.insecure {
        let cert = tokio::fs::read(
            options
                .cert
                .context("gRPC TLS client certificate is required")?,
        )
        .await?;
        let key = tokio::fs::read(options.key.context("gRPC TLS client key is required")?).await?;
        let mut tls = ClientTlsConfig::new().identity(Identity::from_pem(cert, key));
        tls = if let Some(path) = options.cacert {
            tls.ca_certificate(Certificate::from_pem(tokio::fs::read(path).await?))
        } else {
            tls.with_native_roots()
        };
        endpoint = endpoint.tls_config(tls)?;
    }
    Ok(endpoint.connect().await?)
}

struct GrpcConnection {
    incoming: tonic::Streaming<connection::Packet>,
    outgoing: PollSender<connection::Packet>,
    pending: bytes::Bytes,
}

impl AsyncRead for GrpcConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.pending.is_empty() {
                let count = buf.remaining().min(self.pending.len());
                buf.put_slice(&self.pending.split_to(count));
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(Pin::new(&mut self.incoming).poll_next(cx)) {
                Some(Ok(packet)) => match packet.payload {
                    Some(Payload::Data(data)) => self.pending = data.into(),
                    _ => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "expected gRPC connection data",
                        )))
                    }
                },
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for GrpcConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        std::task::ready!(self.outgoing.poll_reserve(cx)).map_err(io::Error::other)?;
        let count = data.len().min(32768);
        self.outgoing
            .send_item(connection::Packet {
                payload: Some(Payload::Data(data[..count].to_vec())),
            })
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.outgoing.close();
        Poll::Ready(Ok(()))
    }
}
