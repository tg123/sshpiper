use std::{
    collections::{BTreeMap, HashMap},
    pin::Pin,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use futures_util::Stream;
use parking_lot::Mutex;
use tokio::sync::broadcast;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_util::sync::CancellationToken;
use tonic::{
    transport::{Certificate, Identity, Server, ServerTlsConfig},
    Request, Response, Status,
};

use crate::{
    config::Config,
    proto::admin::{
        ssh_piper_admin_server::{SshPiperAdmin, SshPiperAdminServer},
        *,
    },
};

pub fn timestamp() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(time) => time.as_secs() as i64,
        Err(error) => -(error.duration().as_secs() as i64),
    }
}

pub struct LiveSession {
    pub info: Session,
    pub cancel: CancellationToken,
    headers: Mutex<BTreeMap<u32, AsciicastHeader>>,
    frames: broadcast::Sender<SessionFrame>,
}

impl LiveSession {
    pub fn new(info: Session) -> Arc<Self> {
        Arc::new(Self {
            info,
            cancel: CancellationToken::new(),
            headers: Mutex::new(BTreeMap::new()),
            frames: broadcast::channel(256).0,
        })
    }

    pub fn publish(&self, frame: SessionFrame) {
        let mut headers = self.headers.lock();
        if let Some(session_frame::Frame::Header(header)) = &frame.frame {
            headers.insert(header.channel_id, header.clone());
        }
        // A session may have no admin subscribers; recording is independent.
        let _ = self.frames.send(frame);
    }

    pub fn close_channel(&self, channel: u32) {
        self.headers.lock().remove(&channel);
    }
}

#[derive(Clone)]
pub struct Registry {
    pub info: ServerInfoResponse,
    sessions: Arc<Mutex<HashMap<String, Arc<LiveSession>>>>,
}

impl Registry {
    pub fn new(config: &Config, address: String) -> Result<Self> {
        let id = match &config.admin_grpc_id {
            Some(id) => id.clone(),
            None => format!("{}@{}", hostname::get()?.to_string_lossy(), address),
        };
        Ok(Self {
            info: ServerInfoResponse {
                id,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                ssh_addr: address,
                started_at: timestamp(),
            },
            sessions: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn insert(&self, session: Arc<LiveSession>) {
        self.sessions
            .lock()
            .insert(session.info.id.clone(), session);
    }

    pub fn remove(&self, id: &str) {
        self.sessions.lock().remove(id);
    }

    pub async fn serve(self, config: &Config) -> Result<()> {
        let listener = tokio::net::TcpListener::bind((
            config.admin_grpc_address.as_str(),
            config.admin_grpc_port,
        ))
        .await?;
        tracing::info!(address = %listener.local_addr()?, "admin gRPC API listening");
        let mut server = Server::builder();
        if !config.admin_grpc_insecure {
            let certificate = tokio::fs::read(
                config
                    .admin_grpc_tls_cert
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("admin TLS certificate is required"))?,
            )
            .await?;
            let key = tokio::fs::read(
                config
                    .admin_grpc_tls_key
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("admin TLS key is required"))?,
            )
            .await?;
            let mut tls = ServerTlsConfig::new().identity(Identity::from_pem(certificate, key));
            if let Some(path) = &config.admin_grpc_tls_cacert {
                tls = tls.client_ca_root(Certificate::from_pem(tokio::fs::read(path).await?));
            }
            server = server.tls_config(tls)?;
        } else {
            tracing::warn!("admin gRPC API is running WITHOUT TLS");
        }
        server
            .add_service(SshPiperAdminServer::new(self))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await?;
        Ok(())
    }
}

#[tonic::async_trait]
impl SshPiperAdmin for Registry {
    async fn server_info(
        &self,
        _request: Request<ServerInfoRequest>,
    ) -> Result<Response<ServerInfoResponse>, Status> {
        Ok(Response::new(self.info.clone()))
    }

    async fn list_sessions(
        &self,
        _request: Request<ListSessionsRequest>,
    ) -> Result<Response<ListSessionsResponse>, Status> {
        let mut sessions: Vec<_> = self
            .sessions
            .lock()
            .values()
            .map(|live| {
                let mut info = live.info.clone();
                info.streamable = !live.headers.lock().is_empty();
                info
            })
            .collect();
        sessions.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(Response::new(ListSessionsResponse { sessions }))
    }

    async fn kill_session(
        &self,
        request: Request<KillSessionRequest>,
    ) -> Result<Response<KillSessionResponse>, Status> {
        let sessions = self.sessions.lock();
        let live = sessions.get(&request.into_inner().id);
        if let Some(live) = live {
            live.cancel.cancel();
        }
        Ok(Response::new(KillSessionResponse {
            killed: live.is_some(),
        }))
    }

    type StreamSessionStream = Pin<Box<dyn Stream<Item = Result<SessionFrame, Status>> + Send>>;

    async fn stream_session(
        &self,
        request: Request<StreamSessionRequest>,
    ) -> Result<Response<Self::StreamSessionStream>, Status> {
        let request = request.into_inner();
        let live = self
            .sessions
            .lock()
            .get(&request.id)
            .cloned()
            .ok_or_else(|| Status::not_found("session not found"))?;
        let (mut receiver, headers) = {
            let headers = live.headers.lock();
            let receiver = live.frames.subscribe();
            let headers = if request.replay {
                headers.values().cloned().collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            (receiver, headers)
        };
        let stream = async_stream::try_stream! {
            for header in headers {
                yield SessionFrame { frame: Some(session_frame::Frame::Header(header)) };
            }
            loop {
                let frame = tokio::select! {
                    _ = live.cancel.cancelled() => break,
                    frame = receiver.recv() => frame,
                };
                match frame {
                    Ok(frame) => yield frame,
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(count)) => Err(Status::resource_exhausted(format!("admin stream subscriber fell behind by {count} frames")))?,
                }
            }
        };
        Ok(Response::new(Box::pin(stream)))
    }
}
