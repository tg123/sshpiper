//go:build rustdaemon

package interop_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/tg123/sshpiper/libadmin"
	"golang.org/x/crypto/ssh"
)

type lockedBuffer struct {
	sync.Mutex
	bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.Write(p)
}

func (b *lockedBuffer) text() string {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.String()
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

func TestRustDaemonUnchangedFixedPlugin(t *testing.T) {
	daemon := os.Getenv("SSHPIPERD_RUST_DAEMON")
	plugin := os.Getenv("SSHPIPERD_RUST_FIXED_PLUGIN")
	if daemon == "" || plugin == "" {
		t.Fatal("SSHPIPERD_RUST_DAEMON and SSHPIPERD_RUST_FIXED_PLUGIN must name built binaries")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	server := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if meta.User() != "testuser" || string(password) != "correct-password" {
				return nil, fmt.Errorf("wrong credentials")
			}
			return nil, nil
		},
		BannerCallback: func(ssh.ConnMetadata) string { return "upstream-banner\n" },
	}
	server.AddHostKey(key)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, channels, requests, err := ssh.NewServerConn(connection, server)
				if err != nil {
					return
				}
				go func() {
					for request := range requests {
						request.Reply(request.Type == "opaque-request@test", request.Payload)
					}
				}()
				for incoming := range channels {
					channel, requests, err := incoming.Accept()
					if err != nil {
						continue
					}
					go func(kind string) {
						defer channel.Close()
						if kind == "opaque-channel@test" {
							go ssh.DiscardRequests(requests)
							io.Copy(channel, channel)
							return
						}
						env := make(map[string]string)
						for request := range requests {
							switch request.Type {
							case "env":
								var payload struct{ Name, Value string }
								if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
									return
								}
								env[payload.Name] = payload.Value
								request.Reply(true, nil)
							case "exec":
								request.Reply(true, nil)
								fmt.Fprintf(channel, "rust-daemon:%s\n", env["RUST_TEST"])
								channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
								return
							case "shell":
								request.Reply(true, nil)
								io.Copy(channel, channel)
								return
							default:
								request.Reply(false, nil)
							}
						}
					}(incoming.ChannelType())
				}
			}()
		}
	}()
	temp := t.TempDir()
	hostKey, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(temp, "host-key")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(hostKey), 0o600); err != nil {
		t.Fatal(err)
	}
	address, adminAddress := freeAddress(t), freeAddress(t)
	_, port, _ := net.SplitHostPort(address)
	_, adminPort, _ := net.SplitHostPort(adminAddress)
	command := exec.Command(daemon, "--address", "127.0.0.1", "--port", port,
		"--server-key", keyPath, "--inject-env", "RUST_TEST=injected",
		"--screen-recording-dir", filepath.Join(temp, "recordings"),
		"--admin-grpc-port", adminPort, "--admin-grpc-insecure",
		plugin, "--target", listener.Addr().String())
	var logs lockedBuffer
	command.Stderr = &logs
	command.Stdout = &logs
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	t.Cleanup(func() {
		command.Process.Kill()
		select {
		case <-exited:
		case <-time.After(10 * time.Second):
			t.Error("daemon did not exit")
		}
		if t.Failed() {
			t.Log(logs.text())
		}
	})
	deadline := time.Now().Add(30 * time.Second)
	for {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			connection.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon did not listen: %s", logs.text())
		}
		time.Sleep(20 * time.Millisecond)
	}
	var banners []string
	clientConfig := &ssh.ClientConfig{
		User: "testuser", Auth: []ssh.AuthMethod{ssh.Password("wrong-password")},
		HostKeyCallback: ssh.FixedHostKey(key.PublicKey()), Timeout: 10 * time.Second,
		BannerCallback: func(message string) error { banners = append(banners, message); return nil },
		Config:         ssh.Config{Ciphers: []string{"aes128-gcm@openssh.com"}},
	}
	if client, err := ssh.Dial("tcp", address, clientConfig); err == nil {
		client.Close()
		t.Fatal("wrong upstream password was accepted downstream")
	}
	if len(banners) == 0 {
		t.Fatal("upstream banner was lost on failed authentication")
	}
	clientConfig.Auth = []ssh.AuthMethod{ssh.Password("correct-password")}
	client, err := ssh.Dial("tcp", address, clientConfig)
	if err != nil {
		t.Fatalf("dial: %v\n%s", err, logs.text())
	}
	defer client.Close()
	reply, data, err := client.SendRequest("opaque-request@test", true, []byte("opaque payload"))
	if err != nil || !reply || string(data) != "opaque payload" {
		t.Fatalf("opaque global request: reply=%v data=%q err=%v", reply, data, err)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	output, err := session.CombinedOutput("probe")
	session.Close()
	if err != nil || string(output) != "rust-daemon:injected\n" {
		t.Fatalf("exec: output=%q err=%v\n%s", output, err, logs.text())
	}
	channel, requests, err := client.OpenChannel("opaque-channel@test", []byte("opaque type-specific data"))
	if err != nil {
		t.Fatal(err)
	}
	go ssh.DiscardRequests(requests)
	payload := bytes.Repeat([]byte("full-duplex-opaque-data"), 1024*1024)
	written := make(chan error, 1)
	go func() {
		_, err := channel.Write(payload)
		if err == nil {
			err = channel.CloseWrite()
		}
		written <- err
	}()
	received := make(chan []byte, 1)
	go func() { data, _ := io.ReadAll(channel); received <- data }()
	select {
	case data := <-received:
		if !bytes.Equal(data, payload) {
			t.Fatalf("opaque channel payload mismatch: got %d bytes, want %d", len(data), len(payload))
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("opaque channel transfer deadlocked\n%s", logs.text())
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	channel.Close()
	adminClient, err := libadmin.NewClient(adminAddress, libadmin.DialOptions{Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer adminClient.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sessions, err := adminClient.ListSessions(ctx)
	if err != nil || len(sessions) != 1 {
		t.Fatalf("admin sessions: count=%d err=%v", len(sessions), err)
	}
	if sessions[0].DownstreamUser != "testuser" {
		t.Fatalf("wrong admin username: %q", sessions[0].DownstreamUser)
	}
	killed, err := adminClient.KillSession(ctx, sessions[0].Id)
	if err != nil || !killed {
		t.Fatalf("kill session: killed=%v err=%v", killed, err)
	}
	var casts []string
	filepath.WalkDir(filepath.Join(temp, "recordings"), func(path string, entry os.DirEntry, err error) error {
		if err == nil && filepath.Ext(path) == ".cast" {
			casts = append(casts, path)
		}
		return err
	})
	if len(casts) != 1 {
		t.Fatalf("expected one recording, got %s", strconv.Itoa(len(casts)))
	}
	recording, err := os.ReadFile(casts[0])
	if err != nil || !bytes.Contains(recording, []byte("rust-daemon:injected")) {
		t.Fatalf("recording missing session output: err=%v data=%s", err, recording)
	}
}
