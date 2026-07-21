package e2e_test

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// tcpipForwardRequest is the SSH wire payload for a "tcpip-forward" global request.
type tcpipForwardRequest struct {
	BindAddr string
	BindPort uint32
}

// tcpipForwardSuccess is the SSH wire reply payload when port 0 was requested.
type tcpipForwardSuccess struct {
	BoundPort uint32
}

// forwardedTCPPayload is the SSH wire payload for a "forwarded-tcpip" channel open.
type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

// localForwardTarget starts a TCP server that writes "SSH-" to every connection.
// It returns the port it is listening on.
func localForwardTarget(t *testing.T) int {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start local forward target: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				_, _ = conn.Write([]byte("SSH-"))
				conn.Close()
			}(conn)
		}
	}()

	return l.Addr().(*net.TCPAddr).Port
}

// forwardingSSHServer starts a minimal SSH server that supports both local and
// remote port forwarding.  For local forwarding it accepts "direct-tcpip"
// channels and replies with "SSH-".  For remote forwarding it actually listens
// on the requested port and opens "forwarded-tcpip" channels back through the
// SSH connection so that real ssh -R flows can be tested end-to-end.
func forwardingSSHServer(t *testing.T) net.Listener {
	t.Helper()

	signer, err := ssh.ParsePrivateKey([]byte(testprivatekey))
	if err != nil {
		t.Fatalf("failed to parse upstream host key: %v", err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for upstream ssh: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				serverConn, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					conn.Close()
					return
				}
				defer serverConn.Close()

				go func() {
					for request := range requests {
						switch request.Type {
						case "tcpip-forward":
							var req tcpipForwardRequest
							if err := ssh.Unmarshal(request.Payload, &req); err != nil {
								_ = request.Reply(false, nil)
								continue
							}

							// Bind a real listener so that the test can connect to it.
							fwdListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", req.BindPort))
							if err != nil {
								_ = request.Reply(false, nil)
								continue
							}
							t.Cleanup(func() { fwdListener.Close() })

							actualPort := uint32(fwdListener.Addr().(*net.TCPAddr).Port)

							// When port 0 was requested we must report the allocated port.
							var replyPayload []byte
							if req.BindPort == 0 {
								replyPayload = ssh.Marshal(tcpipForwardSuccess{BoundPort: actualPort})
							}
							_ = request.Reply(true, replyPayload)

							// Accept connections on the forwarded port and pipe them through
							// a "forwarded-tcpip" channel so the real ssh client handles them.
							go func(fwdListener net.Listener) {
								defer fwdListener.Close()
								for {
									fwdConn, err := fwdListener.Accept()
									if err != nil {
										return
									}
									go func(fwdConn net.Conn) {
										defer fwdConn.Close()

										origin := fwdConn.RemoteAddr().(*net.TCPAddr)
										payload := ssh.Marshal(forwardedTCPPayload{
											Addr:       req.BindAddr,
											Port:       actualPort,
											OriginAddr: origin.IP.String(),
											OriginPort: uint32(origin.Port),
										})

										ch, chReqs, err := serverConn.OpenChannel("forwarded-tcpip", payload)
										if err != nil {
											return
										}
										go ssh.DiscardRequests(chReqs)
										defer ch.Close()

										done := make(chan struct{})
										go func() {
											defer close(done)
											_, _ = io.Copy(ch, fwdConn)
											_ = ch.CloseWrite()
										}()
										_, _ = io.Copy(fwdConn, ch)
										<-done
									}(fwdConn)
								}
							}(fwdListener)

						case "cancel-tcpip-forward":
							_ = request.Reply(true, nil)
						default:
							_ = request.Reply(false, nil)
						}
					}
				}()

				for newChannel := range channels {
					if newChannel.ChannelType() != "direct-tcpip" {
						_ = newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
						continue
					}
					channel, channelRequests, err := newChannel.Accept()
					if err != nil {
						continue
					}
					go ssh.DiscardRequests(channelRequests)
					_, _ = channel.Write([]byte("SSH-"))
					channel.Close()
				}
			}(conn)
		}
	}()

	return listener
}

func startForwardingSSH(t *testing.T, piperPort, readyText string, forwardingArgs ...string) {
	t.Helper()

	args := []string{
		"-v",
		"-N",
		"-o", "ExitOnForwardFailure=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
	}
	args = append(args, forwardingArgs...)
	args = append(args,
		"-p", piperPort,
		"-l", "user",
		"127.0.0.1",
	)

	cmd, stdin, stdout, err := runCmd("ssh", args...)
	if err != nil {
		t.Fatalf("failed to start ssh: %v", err)
	}
	t.Cleanup(func() { killCmd(cmd) })

	enterPassword(stdin, stdout, "pass")
	waitForStdoutContains(stdout, readyText, func(_ string) {})
}

func checkLocalForwarding(t *testing.T, port int, wantSuccess bool) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), waitTimeout)
	if err != nil {
		t.Fatalf("failed to connect to local forward: %v", err)
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatalf("failed to set local forwarding deadline: %v", err)
	}
	banner := make([]byte, len("SSH-"))
	_, err = io.ReadFull(conn, banner)
	gotSuccess := err == nil && string(banner) == "SSH-"
	if gotSuccess != wantSuccess {
		t.Fatalf("local forwarding success = %v, want %v (response: %q, error: %v)", gotSuccess, wantSuccess, banner, err)
	}
}

func checkDynamicForwarding(t *testing.T, port int, wantSuccess bool) {
	t.Helper()

	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), waitTimeout)
	if err != nil {
		t.Fatalf("failed to connect to dynamic forward: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatalf("failed to set dynamic forwarding deadline: %v", err)
	}
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatalf("failed to write SOCKS greeting: %v", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		t.Fatalf("failed to read SOCKS greeting: %v", err)
	}

	host := "target"
	request := []byte{5, 1, 0, 3, byte(len(host))}
	request = append(request, host...)
	request = append(request, 0x08, 0xae)
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("failed to write SOCKS request: %v", err)
	}
	reply := make([]byte, 4)
	_, err = io.ReadFull(conn, reply)
	gotSuccess := err == nil && reply[1] == 0
	if gotSuccess != wantSuccess {
		t.Fatalf("dynamic forwarding success = %v, want %v (response: %v, error: %v)", gotSuccess, wantSuccess, reply, err)
	}
}

// checkRemoteForwarding connects to the remote port that ssh -R set up on the
// upstream server.  If wantSuccess is true it verifies that data ("SSH-") is
// delivered end-to-end through the tunnel; otherwise it expects a connection
// failure because sshpiper should have rejected the tcpip-forward request.
func checkRemoteForwarding(t *testing.T, remotePort int, wantSuccess bool) {
	t.Helper()

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(remotePort))
	conn, err := net.DialTimeout("tcp", addr, waitTimeout)
	if wantSuccess {
		if err != nil {
			t.Fatalf("remote forwarding: expected connection to succeed but got: %v", err)
		}
		defer conn.Close()

		if err := conn.SetReadDeadline(time.Now().Add(waitTimeout)); err != nil {
			t.Fatalf("failed to set remote forwarding read deadline: %v", err)
		}
		banner := make([]byte, len("SSH-"))
		_, err = io.ReadFull(conn, banner)
		gotSuccess := err == nil && string(banner) == "SSH-"
		if !gotSuccess {
			t.Fatalf("remote forwarding: got %q err %v, want SSH-", banner, err)
		}
	} else {
		if err == nil {
			conn.Close()
			t.Fatalf("remote forwarding: expected connection to fail but it succeeded")
		}
	}
}

func TestForwardingControls(t *testing.T) {
	upstream := forwardingSSHServer(t)
	// localTarget is reachable by the ssh subprocess on the testrunner; it is
	// the destination used for ssh -R <remotePort>:127.0.0.1:<localTarget>.
	localTargetPort := localForwardTarget(t)

	for _, tc := range []struct {
		name        string
		flags       []string
		localWorks  bool
		remoteWorks bool
	}{
		{
			name:        "forwarding enabled",
			localWorks:  true,
			remoteWorks: true,
		},
		{
			name:        "local and dynamic forwarding disabled",
			flags:       []string{"--disable-local-forwarding"},
			remoteWorks: true,
		},
		{
			name:       "remote forwarding disabled",
			flags:      []string{"--disable-remote-forwarding"},
			localWorks: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			piperaddr, piperport := nextAvailablePiperAddress()
			args := append([]string{"-p", piperport}, tc.flags...)
			args = append(args,
				"/sshpiperd/plugins/fixed",
				"--target",
				upstream.Addr().String(),
			)
			piper, _, _, err := runCmd("/sshpiperd/sshpiperd", args...)
			if err != nil {
				t.Fatalf("failed to run sshpiperd: %v", err)
			}
			t.Cleanup(func() { killCmd(piper) })
			waitForEndpointReady(piperaddr)

			// Test ssh -L (local forwarding).
			localPort := nextAvailablePort()
			startForwardingSSH(t, piperport, "Local forwarding listening", "-L", fmt.Sprintf("%d:target:22", localPort))
			checkLocalForwarding(t, localPort, tc.localWorks)

			// Test ssh -D (dynamic / SOCKS forwarding).
			dynamicPort := nextAvailablePort()
			startForwardingSSH(t, piperport, "Local forwarding listening", "-D", strconv.Itoa(dynamicPort))
			checkDynamicForwarding(t, dynamicPort, tc.localWorks)

			// Test ssh -R (remote forwarding) using real ssh and verify actual
			// end-to-end data transfer through the tunnel.
			remotePort := nextAvailablePort()
			if tc.remoteWorks {
				// "remote forward success" is a substring of the real OpenSSH
				// debug message: "debug1: remote forward success for: listen port …"
				startForwardingSSH(t, piperport, "remote forward success", "-R",
					fmt.Sprintf("%d:127.0.0.1:%d", remotePort, localTargetPort))
			} else {
				// When the request is rejected, OpenSSH prints:
				// "Warning: remote port forwarding failed for listen port …"
				startForwardingSSH(t, piperport, "port forwarding failed", "-R",
					fmt.Sprintf("%d:127.0.0.1:%d", remotePort, localTargetPort))
			}
			checkRemoteForwarding(t, remotePort, tc.remoteWorks)
		})
	}
}
