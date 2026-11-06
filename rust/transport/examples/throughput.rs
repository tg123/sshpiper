//! In-memory transport microbenchmark, not an end-to-end daemon comparison.
use std::time::{Duration, Instant};

use bytes::Bytes;
use rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use sshpiper_transport::{relay, Transport};
use tokio::{
    io::{duplex, DuplexStream},
    time::timeout,
};

async fn pair() -> (Transport<DuplexStream>, Transport<DuplexStream>) {
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let trusted = key.public_key().clone();
    let (left, right) = duplex(1024 * 1024);
    tokio::try_join!(
        Transport::accept(left, key),
        Transport::connect(right, trusted)
    )
    .unwrap()
}

#[tokio::main]
async fn main() {
    timeout(Duration::from_secs(120), async {
        const PACKET_SIZE: usize = 32768;
        const PACKETS: usize = 2048;
        let (downstream, mut client) = pair().await;
        let (mut server, upstream) = pair().await;
        let worker = tokio::spawn(relay(downstream, upstream));
        let payload = Bytes::from(vec![200; PACKET_SIZE]);
        for _ in 0..32 {
            let (sent, received) = tokio::join!(client.send(payload.clone()), server.recv());
            sent.unwrap();
            assert_eq!(received.unwrap(), payload);
        }
        let started = Instant::now();
        let (send, receive) = tokio::join!(
            async {
                for _ in 0..PACKETS {
                    client.send(payload.clone()).await?;
                }
                Ok::<_, sshpiper_transport::Error>(())
            },
            async {
                for _ in 0..PACKETS {
                    assert_eq!(server.recv().await?, payload);
                }
                Ok::<_, sshpiper_transport::Error>(())
            },
        );
        send.unwrap();
        receive.unwrap();
        let elapsed = started.elapsed().as_secs_f64();
        println!(
            "{{\"benchmark\":\"in_memory_encrypted_relay\",\"payload_bytes\":{},\"seconds\":{elapsed:.6},\"mib_per_second\":{:.2}}}",
            PACKET_SIZE * PACKETS, (PACKET_SIZE * PACKETS) as f64 / (1024.0 * 1024.0) / elapsed
        );
        drop(client);
        drop(server);
        assert!(worker.await.unwrap().is_err());
    }).await.unwrap();
}
