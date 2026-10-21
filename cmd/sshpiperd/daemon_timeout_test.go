package main

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tg123/sshpiper/cmd/sshpiperd/internal/plugin"
	"golang.org/x/crypto/ssh"
)

func TestEstablishPipe(t *testing.T) {
	establishErr := errors.New("establishment failed")
	for _, tt := range []struct {
		name    string
		timeout bool
		err     error
	}{
		{name: "success before timeout"},
		{name: "error before timeout", err: establishErr},
		{name: "success after timeout", timeout: true},
		{name: "error after timeout", timeout: true, err: establishErr},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var p *ssh.PiperConn
			var downstream, upstream *closeTrackedConn
			var conn net.Conn
			if tt.err == nil {
				p, downstream, upstream = newTimeoutTestPipe(t)
				conn = downstream
			} else {
				local, remote := net.Pipe()
				t.Cleanup(func() { local.Close() })
				t.Cleanup(func() { remote.Close() })
				conn = local
			}

			// Keep SSH transport goroutines outside the bubble. Only the
			// daemon's result delivery and cleanup run on the fake clock.
			synctest.Test(t, func(t *testing.T) {
				var callbackErrors []error
				d := &daemon{
					loginGraceTime: time.Minute,
					config: &plugin.GrpcPluginConfig{
						PipeCreateErrorCallback: func(c net.Conn, err error) {
							if c != conn {
								t.Error("error callback received the wrong connection")
							}
							callbackErrors = append(callbackErrors, err)
						},
					},
				}
				release := make(chan struct{})
				done := make(chan struct{})
				var got *ssh.PiperConn
				go func() {
					got = d.establishPipe(conn, func() (*ssh.PiperConn, error) {
						<-release
						return p, tt.err
					})
					close(done)
				}()

				synctest.Wait()
				select {
				case <-done:
					t.Fatal("establishment returned before completion or timeout")
				default:
				}

				if tt.timeout {
					time.Sleep(d.loginGraceTime)
					synctest.Wait()
					select {
					case <-done:
					default:
						t.Fatal("timeout did not return while establishment was blocked")
					}
				}

				close(release)
				synctest.Wait()
				select {
				case <-done:
				default:
					t.Fatal("establishment did not return after completion")
				}

				switch {
				case tt.timeout:
					if got != nil {
						t.Error("timed-out establishment returned a pipe")
					}
					if len(callbackErrors) != 1 || callbackErrors[0].Error() != "pipe establishing timeout" {
						t.Errorf("timeout callback errors = %v", callbackErrors)
					}
				case tt.err != nil:
					if got != nil {
						t.Error("failed establishment returned a pipe")
					}
					if len(callbackErrors) != 1 || !errors.Is(callbackErrors[0], tt.err) {
						t.Errorf("establishment callback errors = %v, want %v", callbackErrors, tt.err)
					}
				default:
					if got != p {
						t.Error("successful establishment did not return its pipe")
					}
					if len(callbackErrors) != 0 {
						t.Errorf("unexpected callback errors: %v", callbackErrors)
					}
				}

				if p != nil {
					if downstream.closed.Load() != tt.timeout {
						t.Errorf("downstream closed = %v, want %v", downstream.closed.Load(), tt.timeout)
					}
					if upstream.closed.Load() != tt.timeout {
						t.Errorf("upstream closed = %v, want %v", upstream.closed.Load(), tt.timeout)
					}
				}
				// synctest also fails if either the establishing goroutine
				// or the late-result cleanup goroutine remains blocked.
			})
		})
	}
}

type closeTrackedConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeTrackedConn) Close() error {
	err := c.Conn.Close()
	c.closed.Store(true)
	return err
}

func newTimeoutTestPipe(t *testing.T) (*ssh.PiperConn, *closeTrackedConn, *closeTrackedConn) {
	t.Helper()

	downstream, client := timeoutTestTCPPair(t)
	upstream, server := timeoutTestTCPPair(t)
	down := &closeTrackedConn{Conn: downstream}
	up := &closeTrackedConn{Conn: upstream}
	hostKey := genHostKey(t)
	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(hostKey)
	clientConfig := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.NoneAuth()},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	serverDone := make(chan error, 1)
	go func() {
		_, _, _, err := ssh.NewServerConn(server, serverConfig)
		serverDone <- err
	}()
	clientDone := make(chan error, 1)
	go func() {
		_, _, _, err := ssh.NewClientConn(client, client.RemoteAddr().String(), clientConfig)
		clientDone <- err
	}()

	config := &ssh.PiperConfig{
		NoClientAuthCallback: func(ssh.ConnMetadata, ssh.ChallengeContext) (*ssh.Upstream, error) {
			return &ssh.Upstream{Conn: up, ClientConfig: *clientConfig}, nil
		},
	}
	config.AddHostKey(hostKey)
	p, err := ssh.NewSSHPiperConn(down, config)
	if err != nil {
		t.Fatalf("establish test pipe: %v", err)
	}
	t.Cleanup(p.Close)
	if err := <-serverDone; err != nil {
		t.Fatalf("upstream handshake: %v", err)
	}
	if err := <-clientDone; err != nil {
		t.Fatalf("downstream handshake: %v", err)
	}
	return p, down, up
}

func timeoutTestTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	client, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	for _, c := range []net.Conn{client, server} {
		if err := c.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	return client, server
}
