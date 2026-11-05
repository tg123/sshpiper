use std::time::Duration;

use rand_core::OsRng;
use ssh_key::{Algorithm, PrivateKey};
use sshpiper_transport::Transport;
use tokio::{net::TcpListener, process::Command, time::timeout};

fn string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn channel_message(kind: u8, recipient: &[u8]) -> Vec<u8> {
    let mut message = vec![kind];
    message.extend_from_slice(recipient);
    message
}

// This loopback-only test deliberately accepts "none" authentication. The library
// itself implements no user authentication and must not be deployed as a daemon.
#[tokio::test]
#[ignore = "requires the OpenSSH ssh executable on PATH"]
async fn openssh_client_exec_and_server_initiated_rekey() {
    timeout(Duration::from_secs(20), async {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let temp = tempfile::tempdir().unwrap();
        let known_hosts = temp.path().join("known_hosts");
        std::fs::write(
            &known_hosts,
            format!(
                "[127.0.0.1]:{port} {}\n",
                key.public_key().to_openssh().unwrap()
            ),
        )
        .unwrap();
        let mut command = Command::new("ssh");
        command
            .args([
                "-F",
                "none",
                "-oBatchMode=yes",
                "-oStrictHostKeyChecking=yes",
            ])
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
            .args([
                "-oPreferredAuthentications=none",
                "-oKexAlgorithms=curve25519-sha256",
                "-oCiphers=aes256-gcm@openssh.com",
                "-oConnectTimeout=5",
                "-T",
                "-p",
            ])
            .arg(port.to_string())
            .args(["user@127.0.0.1", "transport-test"])
            .kill_on_drop(true);
        let child = command.output();
        let server = async {
            let (stream, _) = listener.accept().await.unwrap();
            let mut transport = Transport::accept(stream, key).await.unwrap();
            let mut service = transport.recv().await.unwrap().to_vec();
            if service[0] == 7 {
                sshpiper_transport::wire::extensions(&service).unwrap();
                service = transport.recv().await.unwrap().to_vec();
            }
            assert_eq!(service[0], 5);
            service[0] = 6;
            transport.send(service.into()).await.unwrap();
            assert_eq!(transport.recv().await.unwrap()[0], 50);
            transport.send(vec![52].into()).await.unwrap();
            let recipient = loop {
                let packet = transport.recv().await.unwrap();
                match packet[0] {
                    90 => {
                        assert_eq!(&packet[5..12], b"session");
                        let recipient = packet[12..16].to_vec();
                        let mut reply = channel_message(91, &recipient);
                        reply.extend_from_slice(&9_u32.to_be_bytes());
                        reply.extend_from_slice(&(4 * 1024 * 1024_u32).to_be_bytes());
                        reply.extend_from_slice(&32768_u32.to_be_bytes());
                        transport.send(reply.into()).await.unwrap();
                        break recipient;
                    }
                    80 => {
                        let length = u32::from_be_bytes(packet[1..5].try_into().unwrap()) as usize;
                        if packet[5 + length] != 0 {
                            transport.send(vec![82].into()).await.unwrap();
                        }
                    }
                    other => panic!("unexpected message before channel open: {other}"),
                }
            };
            loop {
                let packet = transport.recv().await.unwrap();
                if packet[0] == 80 {
                    let length = u32::from_be_bytes(packet[1..5].try_into().unwrap()) as usize;
                    if packet[5 + length] != 0 {
                        transport.send(vec![82].into()).await.unwrap();
                    }
                    continue;
                }
                assert_eq!(packet[0], 98);
                let length = u32::from_be_bytes(packet[5..9].try_into().unwrap()) as usize;
                let name = &packet[9..9 + length];
                if packet[9 + length] != 0 {
                    transport
                        .send(channel_message(99, &recipient).into())
                        .await
                        .unwrap();
                }
                if name == b"exec" {
                    break;
                }
                assert_eq!(name, b"env");
            }
            transport.rekey().await.unwrap();
            let mut data = channel_message(94, &recipient);
            string(&mut data, b"rust packet transport\n");
            transport.send(data.into()).await.unwrap();
            let mut exit = channel_message(98, &recipient);
            string(&mut exit, b"exit-status");
            exit.push(0);
            exit.extend_from_slice(&0_u32.to_be_bytes());
            transport.send(exit.into()).await.unwrap();
            transport
                .send(channel_message(96, &recipient).into())
                .await
                .unwrap();
            transport
                .send(channel_message(97, &recipient).into())
                .await
                .unwrap();
            let mut closed = false;
            loop {
                match transport.recv().await {
                    Ok(packet) => {
                        assert!([96, 97].contains(&packet[0]));
                        closed |= packet[0] == 97;
                    }
                    Err(sshpiper_transport::Error::Disconnected) => break,
                    // Windows OpenSSH can reset TCP after CHANNEL_CLOSE. The
                    // client must still exit successfully with the exact output.
                    Err(sshpiper_transport::Error::Io(error))
                        if closed && error.kind() == std::io::ErrorKind::ConnectionReset =>
                    {
                        break;
                    }
                    Err(error) => {
                        panic!("client disconnected without a clean SSH shutdown: {error}")
                    }
                }
                assert!(
                    closed,
                    "client did not complete the channel close handshake"
                );
            }
        };
        let (output, ()) = tokio::join!(child, server);
        let output = output.unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"rust packet transport\n");
    })
    .await
    .unwrap();
}
