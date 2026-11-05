use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    io::Write,
    sync::Arc,
    time::Instant,
};

use anyhow::{bail, Context, Result};
use bytes::Bytes;
use cap_std::fs::{Dir, File, OpenOptions};
use sshpiper_transport::{
    wire::{string, Reader},
    PacketSender,
};
use tokio::{sync::mpsc, task::JoinSet};

use crate::{
    admin::{timestamp, LiveSession},
    auth::Authenticated,
    config::Config,
    proto::admin::{session_frame::Frame, AsciicastEvent, AsciicastHeader, SessionFrame},
};

const BUFFER_LIMIT: usize = 4 * 1024 * 1024;

pub fn recording_root(config: &Config) -> Result<Option<Arc<Dir>>> {
    let Some(path) = &config.screen_recording_dir else {
        return Ok(None);
    };
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(Some(Arc::new(Dir::open_ambient_dir(
        path,
        cap_std::ambient_authority(),
    )?)))
}

struct Terminal {
    client_id: u32,
    width: u32,
    height: u32,
    env: HashMap<String, String>,
    started: Option<Instant>,
    cast: Option<File>,
}

struct Policy {
    config: Arc<Config>,
    live: Arc<LiveSession>,
    directory: Option<Dir>,
    typescript: Option<(File, File, Instant)>,
    env: BTreeMap<String, String>,
    pending_sessions: HashSet<u32>,
    channels: HashMap<u32, Terminal>,
    globals: [VecDeque<Option<Bytes>>; 2],
}

fn create_file(directory: &Dir, name: &str) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(directory.open_with(name, &options)?)
}

impl Policy {
    fn new(
        config: Arc<Config>,
        root: Option<Arc<Dir>>,
        session: &Authenticated,
        live: Arc<LiveSession>,
    ) -> Result<Self> {
        let directory = if let Some(root) = root {
            let subdir = if config.username_as_recorddir {
                &session.meta.user_name
            } else {
                &session.meta.uniq_id
            };
            if subdir.is_empty()
                || subdir == "."
                || subdir == ".."
                || subdir.contains(['/', '\\', ':', '\0'])
            {
                bail!("invalid username for screen recording dir");
            }
            root.create_dir_all(subdir)?;
            Some(root.open_dir(subdir)?)
        } else {
            None
        };
        let typescript = if config.screen_recording_format == "typescript" {
            if let Some(directory) = &directory {
                let prefix = &session.meta.uniq_id;
                let mut output = create_file(directory, &format!("{prefix}.typescript"))?;
                writeln!(output, "Script started on {}", timestamp())?;
                Some((
                    output,
                    create_file(directory, &format!("{prefix}.timing"))?,
                    Instant::now(),
                ))
            } else {
                None
            }
        } else {
            None
        };
        let mut env = BTreeMap::new();
        for entry in &config.inject_env {
            let (key, value) = entry.split_once('=').context("invalid inject-env")?;
            env.insert(key.to_owned(), value.to_owned());
        }
        env.extend(session.env.clone());
        Ok(Self {
            config,
            live,
            directory,
            typescript,
            env,
            pending_sessions: HashSet::new(),
            channels: HashMap::new(),
            globals: [VecDeque::new(), VecDeque::new()],
        })
    }

    fn event(live: &LiveSession, terminal: &mut Terminal, kind: &str, data: &[u8]) -> Result<()> {
        let Some(started) = terminal.started else {
            return Ok(());
        };
        let time = started.elapsed().as_secs_f64();
        if let Some(file) = &mut terminal.cast {
            serde_json::to_writer(
                &mut *file,
                &serde_json::json!([time, kind, String::from_utf8_lossy(data)]),
            )?;
            file.write_all(b"\n")?;
        }
        live.publish(SessionFrame {
            frame: Some(Frame::Event(AsciicastEvent {
                time,
                kind: kind.to_owned(),
                data: data.to_vec(),
                channel_id: terminal.client_id,
            })),
        });
        Ok(())
    }

    fn drain_globals(&mut self, origin: usize, output: &mut [VecDeque<Bytes>; 2]) {
        while self.globals[origin].front().is_some_and(Option::is_some) {
            if let Some(Some(packet)) = self.globals[origin].pop_front() {
                output[origin].push_back(packet);
            }
        }
    }

    fn handle(
        &mut self,
        origin: usize,
        packet: Bytes,
        output: &mut [VecDeque<Bytes>; 2],
    ) -> Result<()> {
        let destination = 1 - origin;
        let mut reader = Reader(&packet[1..]);
        match packet[0] {
            192 if self.config.reply_ping => {
                let data = reader.string()?;
                reader.end()?;
                let mut pong = vec![193];
                string(&mut pong, data);
                output[origin].push_back(pong.into());
                return Ok(());
            }
            80 => {
                let kind = reader.text()?;
                let want_reply = reader.boolean()?;
                let blocked = (origin == 0
                    && self.config.disable_remote_forwarding
                    && [
                        "tcpip-forward",
                        "cancel-tcpip-forward",
                        "streamlocal-forward@openssh.com",
                        "cancel-streamlocal-forward@openssh.com",
                    ]
                    .contains(&kind))
                    || (origin == 1
                        && self.config.drop_hostkeys_message
                        && kind == "hostkeys-00@openssh.com");
                if want_reply {
                    if self.globals[origin].len() >= 1024 {
                        bail!("too many outstanding global requests");
                    }
                    self.globals[origin].push_back(blocked.then(|| Bytes::from_static(&[82])));
                    self.drain_globals(origin, output);
                }
                if blocked {
                    return Ok(());
                }
            }
            81 | 82 => {
                if self.globals[destination].pop_front() != Some(None) {
                    bail!("unsolicited SSH global reply");
                }
                output[destination].push_back(packet);
                self.drain_globals(destination, output);
                return Ok(());
            }
            90 if origin == 0 => {
                let kind = reader.text()?;
                let client_id = reader.uint()?;
                if self.config.disable_local_forwarding
                    && ["direct-tcpip", "direct-streamlocal@openssh.com"].contains(&kind)
                {
                    let mut reply = vec![92];
                    reply.extend_from_slice(&client_id.to_be_bytes());
                    reply.extend_from_slice(&1_u32.to_be_bytes());
                    string(&mut reply, b"port forwarding is disabled");
                    string(&mut reply, b"");
                    output[0].push_back(reply.into());
                    return Ok(());
                }
                if kind == "session" {
                    if self.channels.len() + self.pending_sessions.len() >= 32768 {
                        bail!("too many SSH session channels");
                    }
                    self.pending_sessions.insert(client_id);
                }
            }
            91 if origin == 1 => {
                let client_id = reader.uint()?;
                let server_id = reader.uint()?;
                if self.pending_sessions.remove(&client_id) {
                    self.channels.insert(
                        server_id,
                        Terminal {
                            client_id,
                            width: 80,
                            height: 24,
                            env: HashMap::new(),
                            started: None,
                            cast: None,
                        },
                    );
                }
            }
            92 if origin == 1 => {
                self.pending_sessions.remove(&reader.uint()?);
            }
            97 => {
                let recipient = reader.uint()?;
                let server_id = if origin == 0 {
                    Some(recipient)
                } else {
                    self.channels.iter().find_map(|(server, channel)| {
                        (channel.client_id == recipient).then_some(*server)
                    })
                };
                if let Some(server_id) = server_id {
                    if let Some(channel) = self.channels.remove(&server_id) {
                        self.live.close_channel(channel.client_id);
                    }
                }
            }
            94 if origin == 1 => {
                let client_id = reader.uint()?;
                let data = reader.string()?;
                reader.end()?;
                if let Some((file, timing, previous)) = &mut self.typescript {
                    writeln!(
                        timing,
                        "{:.6} {}",
                        previous.elapsed().as_secs_f64(),
                        data.len()
                    )?;
                    *previous = Instant::now();
                    file.write_all(data)?;
                }
                if let Some(channel) = self
                    .channels
                    .values_mut()
                    .find(|channel| channel.client_id == client_id)
                {
                    Self::event(&self.live, channel, "o", data)?;
                }
            }
            98 if origin == 0 => {
                let server_id = reader.uint()?;
                let kind = reader.text()?;
                reader.boolean()?;
                if ["shell", "exec", "subsystem"].contains(&kind) {
                    for (key, value) in &self.env {
                        let mut env = vec![98];
                        env.extend_from_slice(&server_id.to_be_bytes());
                        string(&mut env, b"env");
                        env.push(0);
                        string(&mut env, key.as_bytes());
                        string(&mut env, value.as_bytes());
                        output[1].push_back(env.into());
                    }
                }
                if let Some(channel) = self.channels.get_mut(&server_id) {
                    match kind {
                        "pty-req" => {
                            channel.env.insert("TERM".into(), reader.text()?.to_owned());
                            channel.width = reader.uint()?;
                            channel.height = reader.uint()?;
                        }
                        "env" => {
                            channel
                                .env
                                .insert(reader.text()?.to_owned(), reader.text()?.to_owned());
                        }
                        "window-change" => {
                            channel.width = reader.uint()?;
                            channel.height = reader.uint()?;
                            let size = format!("{}x{}", channel.width, channel.height);
                            Self::event(&self.live, channel, "r", size.as_bytes())?;
                        }
                        "shell" | "exec" if channel.started.is_none() => {
                            channel.env.extend(self.env.clone());
                            let header = AsciicastHeader {
                                width: i32::try_from(channel.width)?,
                                height: i32::try_from(channel.height)?,
                                timestamp: timestamp(),
                                env: channel.env.clone(),
                                channel_id: channel.client_id,
                            };
                            if self.config.screen_recording_format == "asciicast" {
                                if let Some(directory) = &self.directory {
                                    let mut file = create_file(
                                        directory,
                                        &format!(
                                            "{}-{kind}-channel-{}.cast",
                                            self.live.info.id, channel.client_id
                                        ),
                                    )?;
                                    serde_json::to_writer(
                                        &mut file,
                                        &serde_json::json!({"version": 2, "width": header.width, "height": header.height, "timestamp": header.timestamp, "env": header.env}),
                                    )?;
                                    file.write_all(b"\n")?;
                                    channel.cast = Some(file);
                                }
                            }
                            channel.started = Some(Instant::now());
                            self.live.publish(SessionFrame {
                                frame: Some(Frame::Header(header)),
                            });
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        output[destination].push_back(packet);
        Ok(())
    }

    fn finish(&mut self) -> Result<()> {
        if let Some((output, _, _)) = &mut self.typescript {
            writeln!(output, "Script done on {}", timestamp())?;
        }
        Ok(())
    }
}

async fn writer(mut packets: mpsc::Receiver<Bytes>, sender: PacketSender) -> Result<()> {
    while let Some(packet) = packets.recv().await {
        sender.send(packet).await?;
    }
    Ok(())
}

pub async fn relay(
    session: Authenticated,
    config: Arc<Config>,
    root: Option<Arc<Dir>>,
    live: Arc<LiveSession>,
) -> Result<()> {
    let mut policy = Policy::new(config, root, &session, live.clone())?;
    let (down_tx, mut down_rx) = session.downstream.split();
    let (up_tx, mut up_rx) = session.upstream.split();
    let (down_queue, down_packets) = mpsc::channel(8);
    let (up_queue, up_packets) = mpsc::channel(8);
    let mut writers = JoinSet::new();
    writers.spawn(writer(down_packets, down_tx));
    writers.spawn(writer(up_packets, up_tx));
    let mut output: [VecDeque<Bytes>; 2] = [VecDeque::new(), VecDeque::new()];
    let result: Result<()> = async {
        loop {
            let sizes: Vec<usize> = output.iter().map(|queue| queue.iter().map(Bytes::len).sum()).collect();
            if sizes.iter().any(|size| *size > BUFFER_LIMIT + sshpiper_transport::MAX_PACKET) {
                bail!("relay policy output exceeds buffering limit");
            }
            tokio::select! {
                _ = live.cancel.cancelled() => break,
                result = writers.join_next() => { result.context("relay writers stopped")???; break; }
                packet = down_rx.recv(), if sizes.iter().all(|size| *size < BUFFER_LIMIT) => policy.handle(0, packet?, &mut output)?,
                packet = up_rx.recv(), if sizes.iter().all(|size| *size < BUFFER_LIMIT) => policy.handle(1, packet?, &mut output)?,
                permit = down_queue.reserve(), if !output[0].is_empty() => permit?.send(output[0].pop_front().context("missing downstream packet")?),
                permit = up_queue.reserve(), if !output[1].is_empty() => permit?.send(output[1].pop_front().context("missing upstream packet")?),
            }
        }
        Ok(())
    }.await;
    policy.finish()?;
    result
}
