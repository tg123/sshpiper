//go:build rustdaemon

package interop_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// BenchmarkDaemonTransfer isolates bidirectional transport from disk and shell
// execution. The separate E2E comparison remains the OpenSSH/SCP performance gate.
func BenchmarkDaemonTransfer(b *testing.B) {
	daemon := os.Getenv("SSHPIPERD_BENCH_DAEMON")
	plugin := os.Getenv("SSHPIPERD_RUST_FIXED_PLUGIN")
	if daemon == "" || plugin == "" {
		b.Fatal("SSHPIPERD_BENCH_DAEMON and SSHPIPERD_RUST_FIXED_PLUGIN must name built binaries")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	key, err := ssh.NewSignerFromKey(private)
	if err != nil {
		b.Fatal(err)
	}
	server := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) != "benchmark-password" {
				return nil, fmt.Errorf("wrong password")
			}
			return nil, nil
		},
		Config: ssh.Config{Ciphers: []string{"aes128-gcm@openssh.com"}},
	}
	server.AddHostKey(key)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 64*1024*1024)
	var serving sync.WaitGroup
	serving.Add(1)
	go func() {
		defer serving.Done()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			serving.Add(1)
			go func() {
				defer serving.Done()
				defer connection.Close()
				if err := connection.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
					b.Error(err)
					return
				}
				_, channels, requests, err := ssh.NewServerConn(connection, server)
				if err != nil {
					return // Endpoint readiness probes are not SSH handshakes.
				}
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					channel, requests, err := incoming.Accept()
					if err != nil {
						b.Error(err)
						return
					}
					go ssh.DiscardRequests(requests)
					switch incoming.ChannelType() {
					case "bench-upload@test":
						n, err := io.Copy(io.Discard, channel)
						if err != nil {
							b.Error(err)
						} else if err := binary.Write(channel, binary.BigEndian, uint64(n)); err != nil {
							b.Error(err)
						}
					case "bench-download@test":
						if _, err := channel.Write(payload); err != nil {
							b.Error(err)
						}
					default:
						b.Errorf("unexpected benchmark channel %s", incoming.ChannelType())
					}
					channel.Close()
				}
			}()
		}
	}()
	b.Cleanup(func() {
		listener.Close()
		serving.Wait()
	})
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		b.Fatal(err)
	}
	keyPath := filepath.Join(b.TempDir(), "host-key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		b.Fatal(err)
	}
	address := freeAddress(b)
	_, port, _ := net.SplitHostPort(address)
	command := exec.Command(daemon, "--address", "127.0.0.1", "--port", port,
		"--server-key", keyPath, "--log-level", "error",
		plugin, "--target", listener.Addr().String())
	startDaemon(b, command, address)
	clientConfig := &ssh.ClientConfig{
		User: "benchmark", Auth: []ssh.AuthMethod{ssh.Password("benchmark-password")},
		HostKeyCallback: ssh.FixedHostKey(key.PublicKey()), Timeout: 10 * time.Second,
		Config: ssh.Config{Ciphers: []string{"aes128-gcm@openssh.com"}},
	}
	for _, direction := range []string{"upload", "download"} {
		b.Run(direction, func(b *testing.B) {
			b.SetBytes(int64(len(payload)))
			for b.Loop() {
				connection, err := net.DialTimeout("tcp", address, 10*time.Second)
				if err != nil {
					b.Fatal(err)
				}
				if err := connection.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
					connection.Close()
					b.Fatal(err)
				}
				conn, channels, requests, err := ssh.NewClientConn(connection, address, clientConfig)
				if err != nil {
					connection.Close()
					b.Fatal(err)
				}
				client := ssh.NewClient(conn, channels, requests)
				channel, incoming, err := client.OpenChannel("bench-"+direction+"@test", nil)
				if err != nil {
					client.Close()
					b.Fatal(err)
				}
				go ssh.DiscardRequests(incoming)
				var n uint64
				if direction == "upload" {
					_, err = channel.Write(payload)
					if err == nil {
						err = channel.CloseWrite()
					}
					if err == nil {
						err = binary.Read(channel, binary.BigEndian, &n)
					}
				} else {
					var received int64
					received, err = io.Copy(io.Discard, channel)
					n = uint64(received)
				}
				channel.Close()
				client.Close()
				if err != nil || n != uint64(len(payload)) {
					b.Fatalf("transfer: bytes=%d err=%v", n, err)
				}
			}
		})
	}
}
