use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use clap::Parser;
use rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use sshpiper_transport::{
    wire::{extensions, string},
    Transport,
};
use sshpiperd::{auth::authenticate, config::Config, plugin::BoxConnection};
use tokio::{io::duplex, time::timeout};

#[tokio::test]
async fn accepts_client_extensions_before_authentication_service() {
    timeout(Duration::from_secs(5), async {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let trusted = key.public_key().clone();
        let (server, client) = duplex(4096);
        let server: BoxConnection = Box::new(server);
        let (server, mut client) = tokio::try_join!(
            Transport::accept(server, key),
            Transport::connect(client, trusted)
        )
        .unwrap();
        let config = Arc::new(Config::try_parse_from(["sshpiperd", "plugin"]).unwrap());
        let daemon = authenticate(server, &[], "127.0.0.1:22", &config);
        let peer = async {
            let packet = client.recv().await.unwrap();
            assert!(extensions(&packet).unwrap().contains_key("server-sig-algs"));
            let mut packet = vec![7];
            packet.extend_from_slice(&1_u32.to_be_bytes());
            string(&mut packet, b"unknown-extension@test");
            string(&mut packet, b"opaque value");
            client.send(packet.into()).await.unwrap();
            let mut service = vec![5];
            string(&mut service, b"ssh-userauth");
            client.send(Bytes::from(service.clone())).await.unwrap();
            service[0] = 6;
            assert_eq!(client.recv().await.unwrap(), service);
            drop(client);
        };
        let (result, ()) = tokio::join!(daemon, peer);
        assert!(result.is_err());
    })
    .await
    .unwrap();
}

#[test]
fn malformed_extension_information_is_rejected() {
    assert!(extensions(&[7, 0, 0, 0, 1]).is_err());
    assert!(extensions(&[7, 0, 0, 0, 0, 0]).is_err());
    let mut duplicate = vec![7, 0, 0, 0, 2];
    for _ in 0..2 {
        string(&mut duplicate, b"server-sig-algs");
        string(&mut duplicate, b"ssh-ed25519");
    }
    assert!(extensions(&duplicate).is_err());
}
