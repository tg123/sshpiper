use std::time::Duration;

use bytes::Bytes;
use rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use sshpiper_transport::{relay, Error, Transport, MAX_PACKET};
use tokio::io::{duplex, AsyncWriteExt, DuplexStream};
use tokio::time::timeout;

async fn pair() -> (Transport<DuplexStream>, Transport<DuplexStream>) {
    pair_with_capacity(MAX_PACKET * 2).await
}

async fn pair_with_capacity(capacity: usize) -> (Transport<DuplexStream>, Transport<DuplexStream>) {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let trusted = key.public_key().clone();
    let (left, right) = duplex(capacity);
    timeout(Duration::from_secs(5), async {
        tokio::try_join!(
            Transport::accept(left, key),
            Transport::connect(right, trusted)
        )
    })
    .await
    .unwrap()
    .unwrap()
}

#[tokio::test]
async fn full_duplex_drivers_do_not_deadlock_small_io_buffers() {
    timeout(Duration::from_secs(10), async {
        let (server, client) = pair_with_capacity(64).await;
        let (server_tx, mut server_rx) = server.split();
        let (client_tx, mut client_rx) = client.split();
        let payload = Bytes::from(vec![200; 32768]);
        tokio::try_join!(
            server_tx.send(payload.clone()),
            client_tx.send(payload.clone())
        )
        .unwrap();
        assert_eq!(server_rx.recv().await.unwrap(), payload);
        assert_eq!(client_rx.recv().await.unwrap(), payload);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn relay_preserves_opaque_messages_and_terminates_each_rekey_locally() {
    timeout(Duration::from_secs(10), async {
        let (downstream, client) = pair_with_capacity(512).await;
        let (server, upstream) = pair_with_capacity(512).await;
        let (client_tx, mut client_rx) = client.split();
        let (server_tx, mut server_rx) = server.split();
        let task = tokio::spawn(relay(downstream, upstream));
        for _ in 0..3 {
            tokio::try_join!(client_tx.rekey(), server_tx.rekey()).unwrap();
            let mut opaque_channel = vec![90];
            opaque_channel.extend_from_slice(b"\0\0\0\x11vendor@example.io");
            opaque_channel.extend_from_slice(&[0xab; 32768]);
            let payload = Bytes::from(opaque_channel);
            tokio::try_join!(
                client_tx.send(payload.clone()),
                server_tx.send(payload.clone())
            )
            .unwrap();
            assert_eq!(server_rx.recv().await.unwrap(), payload);
            assert_eq!(client_rx.recv().await.unwrap(), payload);
        }
        drop((client_tx, client_rx));
        drop((server_tx, server_rx));
        assert!(task.await.unwrap().is_err());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cancelling_a_driver_receive_preserves_connection() {
    let (server, client) = pair().await;
    let (_server_tx, mut server_rx) = server.split();
    let (client_tx, _client_rx) = client.split();
    assert!(timeout(Duration::from_millis(10), server_rx.recv())
        .await
        .is_err());
    client_tx
        .send(Bytes::from_static(b"\x5estill connected"))
        .await
        .unwrap();
    assert_eq!(server_rx.recv().await.unwrap(), b"\x5estill connected"[..]);
}

#[tokio::test]
async fn dropping_driver_halves_closes_peer() {
    let (server, mut client) = pair().await;
    let halves = server.split();
    drop(halves);
    assert!(timeout(Duration::from_secs(5), client.recv())
        .await
        .unwrap()
        .is_err());
}

#[tokio::test]
async fn driver_errors_reach_both_halves() {
    let (server, _client) = pair().await;
    let (tx, mut rx) = server.split();
    assert!(matches!(
        tx.send(Bytes::from_static(&[20])).await,
        Err(Error::Protocol(_))
    ));
    assert!(matches!(rx.recv().await, Err(Error::Driver(_))));
}

#[tokio::test]
async fn splitting_a_poisoned_transport_cannot_resume_it() {
    let (mut server, _client) = pair().await;
    assert!(timeout(Duration::from_millis(10), server.recv())
        .await
        .is_err());
    let (_tx, mut rx) = server.split();
    assert!(matches!(rx.recv().await, Err(Error::Poisoned)));
}

#[tokio::test]
async fn opaque_connection_packets_survive_in_both_directions() {
    let (mut server, mut client) = pair().await;
    assert!(server.strict_kex() && client.strict_kex());
    assert_eq!(server.session_id(), client.session_id());
    for size in [1, 16, 32768, MAX_PACKET - 32] {
        let mut bytes = (0..size).map(|i| (i % 256) as u8).collect::<Vec<_>>();
        bytes[0] = 200;
        let payload = Bytes::from(bytes);
        let (sent, received) = tokio::join!(server.send(payload.clone()), client.recv());
        sent.unwrap();
        assert_eq!(received.unwrap(), payload);
        let (sent, received) = tokio::join!(client.send(payload.clone()), server.recv());
        sent.unwrap();
        assert_eq!(received.unwrap(), payload);
    }
}

#[tokio::test]
async fn initiated_peer_and_simultaneous_rekeys_preserve_session_id() {
    timeout(Duration::from_secs(10), async {
        let (mut server, mut client) = pair().await;
        let id = *server.session_id();
        for _ in 0..3 {
            tokio::try_join!(server.rekey(), client.rekey()).unwrap();
            let (sent, received) = tokio::join!(
                async {
                    server.rekey().await?;
                    server
                        .send(Bytes::from_static(b"\x5eafter server rekey"))
                        .await
                },
                client.recv(),
            );
            sent.unwrap();
            assert_eq!(received.unwrap(), b"\x5eafter server rekey"[..]);
            let (sent, received) = tokio::join!(
                async {
                    client.rekey().await?;
                    client
                        .send(Bytes::from_static(b"\x5eafter client rekey"))
                        .await
                },
                server.recv(),
            );
            sent.unwrap();
            assert_eq!(received.unwrap(), b"\x5eafter client rekey"[..]);
            assert_eq!(server.session_id(), &id);
            assert_eq!(client.session_id(), &id);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rekey_keeps_already_in_flight_packets_in_order() {
    timeout(Duration::from_secs(5), async {
        let (mut server, mut client) = pair().await;
        client
            .send(Bytes::from_static(b"\x5ebefore one"))
            .await
            .unwrap();
        client
            .send(Bytes::from_static(b"\x5ebefore two"))
            .await
            .unwrap();
        tokio::try_join!(server.rekey(), client.rekey()).unwrap();
        client.send(Bytes::from_static(b"\x5eafter")).await.unwrap();
        assert_eq!(server.recv().await.unwrap(), b"\x5ebefore one"[..]);
        assert_eq!(server.recv().await.unwrap(), b"\x5ebefore two"[..]);
        assert_eq!(server.recv().await.unwrap(), b"\x5eafter"[..]);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn wrong_host_key_fails_closed() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let wrong = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let (left, right) = duplex(65536);
    let outcome = timeout(Duration::from_secs(5), async {
        tokio::try_join!(
            Transport::accept(left, key),
            Transport::connect(right, wrong.public_key().clone())
        )
    })
    .await
    .unwrap();
    assert!(matches!(outcome, Err(Error::HostKey)));
}

#[tokio::test]
async fn cancelled_operation_cannot_resume_half_finished_state() {
    let (mut server, _client) = pair().await;
    assert!(timeout(Duration::from_millis(10), server.recv())
        .await
        .is_err());
    assert!(matches!(server.recv().await, Err(Error::Poisoned)));
}

#[tokio::test]
async fn application_cannot_inject_transport_messages() {
    for id in [0, 1, 2, 3, 4, 20, 21, 30, 49] {
        let (mut server, _client) = pair().await;
        assert!(matches!(
            server.send(Bytes::from(vec![id])).await,
            Err(Error::Protocol(_))
        ));
    }
}

#[tokio::test]
async fn bounded_identification_input() {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let (left, mut right) = duplex(4096);
    right.write_all(&[b'A'; 256]).await.unwrap();
    let outcome = timeout(Duration::from_secs(5), Transport::accept(left, key))
        .await
        .unwrap();
    assert!(matches!(
        outcome,
        Err(Error::Protocol("identification line too long"))
    ));
}
