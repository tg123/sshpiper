use std::{collections::HashMap, sync::Arc, time::Duration};

use bytes::Bytes;
use clap::Parser;
use rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use sshpiper_transport::{wire::string, Transport};
use sshpiperd::{
    admin::LiveSession,
    auth::Authenticated,
    config::Config,
    plugin::BoxConnection,
    proto::{admin::Session, plugin::ConnMeta},
    relay::{recording_root, relay},
};
use tokio::{io::duplex, task::JoinHandle, time::timeout};

async fn pair() -> (Transport<BoxConnection>, Transport<BoxConnection>) {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let trusted = key.public_key().clone();
    let (server, client) = duplex(256);
    let server: BoxConnection = Box::new(server);
    let client: BoxConnection = Box::new(client);
    tokio::try_join!(
        Transport::accept(server, key),
        Transport::connect(client, trusted)
    )
    .unwrap()
}

#[tokio::test]
async fn drains_final_packets_after_peer_eof() {
    timeout(Duration::from_secs(20), async {
        for reverse in [false, true] {
            for cancel in [false, true] {
                let (downstream, client) = pair().await;
                let (server, upstream) = pair().await;
                let (mut server, mut client) = if reverse {
                    (client, server)
                } else {
                    (server, client)
                };
                let config = Arc::new(Config::try_parse_from(["sshpiperd", "plugin"]).unwrap());
                let session = Authenticated {
                    downstream,
                    upstream,
                    meta: ConnMeta::default(),
                    upstream_user: "user".into(),
                    upstream_addr: "upstream".into(),
                    env: HashMap::new(),
                };
                let live = LiveSession::new(Session::default());
                let task = tokio::spawn(relay(session, config, None, live.clone()));
                let payloads: Vec<_> = (0..64_u8)
                    .map(|index| {
                        let mut data = vec![index; 32768];
                        data[0] = 200;
                        Bytes::from(data)
                    })
                    .collect();
                for payload in &payloads {
                    server.send(payload.clone()).await.unwrap();
                }
                drop(server);
                for payload in payloads {
                    assert_eq!(client.recv().await.unwrap(), payload);
                    if cancel {
                        live.cancel.cancel();
                        break;
                    }
                }
                if cancel {
                    task.await.unwrap().unwrap();
                } else {
                    assert!(client.recv().await.is_err());
                    assert!(task.await.unwrap().is_err());
                }
            }
        }
    })
    .await
    .unwrap();
}

type Relay = (
    Transport<BoxConnection>,
    Transport<BoxConnection>,
    JoinHandle<anyhow::Result<()>>,
);

async fn start(arguments: &[&str], env: HashMap<String, String>) -> Relay {
    let (downstream, client) = pair().await;
    let (server, upstream) = pair().await;
    let mut parameters = vec!["sshpiperd"];
    parameters.extend_from_slice(arguments);
    parameters.push("plugin");
    let config = Arc::new(Config::try_parse_from(parameters).unwrap());
    let root = recording_root(&config).unwrap();
    let session = Authenticated {
        downstream,
        upstream,
        meta: ConnMeta {
            uniq_id: "session".into(),
            ..ConnMeta::default()
        },
        upstream_user: "user".into(),
        upstream_addr: "upstream".into(),
        env,
    };
    let live = LiveSession::new(Session {
        id: "session".into(),
        ..Session::default()
    });
    (
        client,
        server,
        tokio::spawn(relay(session, config, root, live)),
    )
}

fn open(kind: &str, sender: u32) -> Bytes {
    let mut packet = vec![90];
    string(&mut packet, kind.as_bytes());
    for value in [sender, 1 << 20, 32768] {
        packet.extend_from_slice(&value.to_be_bytes());
    }
    packet.into()
}

fn confirm(recipient: u32, sender: u32) -> Bytes {
    let mut packet = vec![91];
    for value in [recipient, sender, 1 << 20, 32768] {
        packet.extend_from_slice(&value.to_be_bytes());
    }
    packet.into()
}

fn close(recipient: u32) -> Bytes {
    let mut packet = vec![97];
    packet.extend_from_slice(&recipient.to_be_bytes());
    packet.into()
}

fn request(recipient: u32, kind: &str, fields: &[&[u8]]) -> Bytes {
    let mut packet = vec![98];
    packet.extend_from_slice(&recipient.to_be_bytes());
    string(&mut packet, kind.as_bytes());
    packet.push(0);
    for field in fields {
        string(&mut packet, field);
    }
    packet.into()
}

#[tokio::test]
async fn rejects_session_requests_before_channel_confirmation() {
    timeout(Duration::from_secs(20), async {
        let (mut client, mut server, task) = start(&[], HashMap::new()).await;
        client.send(open("session", 0)).await.unwrap();
        client.send(request(0, "shell", &[])).await.unwrap();
        let error = task.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("unconfirmed"), "{error}");
        while let Ok(packet) = server.recv().await {
            assert_ne!(packet[0], 98, "unrecorded shell request reached upstream");
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rejects_channel_ids_reused_before_upstream_close() {
    timeout(Duration::from_secs(20), async {
        for duplicate in [open("session", 0), confirm(9, 0)] {
            let (mut client, mut server, task) = start(&[], HashMap::new()).await;
            client.send(open("session", 0)).await.unwrap();
            assert_eq!(server.recv().await.unwrap()[0], 90);
            server.send(confirm(0, 7)).await.unwrap();
            assert_eq!(client.recv().await.unwrap()[0], 91);
            // An id is reusable once both sides have closed its channel.
            client.send(close(7)).await.unwrap();
            assert_eq!(server.recv().await.unwrap()[0], 97);
            server.send(close(0)).await.unwrap();
            assert_eq!(client.recv().await.unwrap()[0], 97);
            client.send(open("session", 0)).await.unwrap();
            assert_eq!(server.recv().await.unwrap()[0], 90);
            server.send(open("forwarded-tcpip", 9)).await.unwrap();
            assert_eq!(client.recv().await.unwrap()[0], 90);
            client.send(duplicate).await.unwrap();
            let error = task.await.unwrap().unwrap_err();
            assert!(error.to_string().contains("already in use"), "{error}");
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn recordings_exclude_injected_environment() {
    timeout(Duration::from_secs(20), async {
        let directory = tempfile::tempdir().unwrap();
        let (mut client, mut server, task) = start(
            &[
                "--inject-env",
                "CLI_SECRET=from-cli",
                "--screen-recording-dir",
                directory.path().to_str().unwrap(),
                "--screen-recording-format",
                "asciicast",
            ],
            HashMap::from([("PLUGIN_SECRET".into(), "from-plugin".into())]),
        )
        .await;
        client.send(open("session", 0)).await.unwrap();
        assert_eq!(server.recv().await.unwrap()[0], 90);
        server.send(confirm(0, 7)).await.unwrap();
        assert_eq!(client.recv().await.unwrap()[0], 91);
        client
            .send(request(7, "env", &[b"LANG", b"C"]))
            .await
            .unwrap();
        client.send(request(7, "shell", &[])).await.unwrap();
        let mut upstream = Vec::new();
        for _ in 0..4 {
            upstream.push(server.recv().await.unwrap());
        }
        assert_eq!(
            upstream,
            [
                request(7, "env", &[b"LANG", b"C"]),
                request(7, "env", &[b"CLI_SECRET", b"from-cli"]),
                request(7, "env", &[b"PLUGIN_SECRET", b"from-plugin"]),
                request(7, "shell", &[]),
            ]
        );
        let recording = std::fs::read_to_string(
            directory
                .path()
                .join("session")
                .join("session-shell-channel-0.cast"),
        )
        .unwrap();
        let header: serde_json::Value =
            serde_json::from_str(recording.lines().next().unwrap()).unwrap();
        assert_eq!(header["env"], serde_json::json!({"LANG": "C"}));
        assert!(!recording.contains("from-"), "{recording}");
        drop((client, server));
        let _ = task.await.unwrap();
    })
    .await
    .unwrap();
}
