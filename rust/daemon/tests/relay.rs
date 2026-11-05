use std::{collections::HashMap, sync::Arc, time::Duration};

use bytes::Bytes;
use clap::Parser;
use rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use sshpiper_transport::Transport;
use sshpiperd::{
    admin::LiveSession,
    auth::Authenticated,
    config::Config,
    plugin::BoxConnection,
    proto::{admin::Session, plugin::ConnMeta},
    relay::relay,
};
use tokio::{io::duplex, time::timeout};

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
