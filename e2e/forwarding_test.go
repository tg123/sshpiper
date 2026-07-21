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
			go func() {
				serverConn, channels, requests, err := ssh.NewServerConn(conn, config)
				if err != nil {
					conn.Close()
					return
				}
				defer serverConn.Close()

				go func() {
					for request := range requests {
						switch request.Type {
						case "tcpip-forward", "cancel-tcpip-forward":
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
			}()
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

func TestForwardingControls(t *testing.T) {
	upstream := forwardingSSHServer(t)

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

			localPort := nextAvailablePort()
			startForwardingSSH(t, piperport, "Local forwarding listening", "-L", fmt.Sprintf("%d:target:22", localPort))
			checkLocalForwarding(t, localPort, tc.localWorks)

			dynamicPort := nextAvailablePort()
			startForwardingSSH(t, piperport, "Local forwarding listening", "-D", strconv.Itoa(dynamicPort))
			checkDynamicForwarding(t, dynamicPort, tc.localWorks)

			remotePort := nextAvailablePort()
			expected := "remote forward success"
			if !tc.remoteWorks {
				expected = "remote forward failure"
			}
			startForwardingSSH(t, piperport, expected, "-R", fmt.Sprintf("%d:target:22", remotePort))
		})
	}
}
