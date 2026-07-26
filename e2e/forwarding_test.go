package e2e_test

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

// upstreamForwardingContainer/Port identify the real OpenSSH server (from
// docker-compose) used as the upstream for these tests. Using a real sshd
// (instead of a custom in-process Go SSH server) means the forwarding filter
// is exercised against actual OpenSSH global-request/channel-open wire
// behavior.
const (
	upstreamForwardingContainer = "host-password"
	upstreamForwardingPort      = 2222
)

var upstreamForwardingHost = net.JoinHostPort(upstreamForwardingContainer, strconv.Itoa(upstreamForwardingPort))

// localForwardTarget starts a plain TCP server that writes "SSH-" to every
// connection. It returns the port it is listening on. This is only ever used
// as the destination of a remote (ssh -R) forward, reached from within the
// upstream sshd container back through the tunnel to the testrunner - it is
// not itself an SSH server.
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

// checkLocalForwarding verifies a local (ssh -L) forward by connecting to the
// forwarded port and reading the real OpenSSH version banner ("SSH-...") that
// the upstream sshd sends back through the tunnel.
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

	// Ask the SOCKS proxy (dynamic forward) to connect back to the upstream
	// sshd itself so we don't need any extra service in the upstream's
	// network namespace.
	host := "127.0.0.1"
	request := []byte{5, 1, 0, 3, byte(len(host))}
	request = append(request, host...)
	request = append(request, byte(upstreamForwardingPort>>8), byte(upstreamForwardingPort&0xff))
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

// checkRemoteForwarding connects to the remote port that ssh -R asked the
// upstream sshd to bind. The bind happens inside the upstream container's
// network namespace, so it must be reached via the upstream's docker-compose
// service name, not via the testrunner's own loopback address. If
// wantSuccess is true it verifies that data ("SSH-") is delivered end-to-end
// through the tunnel; otherwise it expects a connection failure because
// sshpiper should have rejected the tcpip-forward request.
func checkRemoteForwarding(t *testing.T, remotePort int, wantSuccess bool) {
	t.Helper()

	addr := net.JoinHostPort(upstreamForwardingContainer, strconv.Itoa(remotePort))
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
				upstreamForwardingHost,
			)
			piper, _, _, err := runCmd("/sshpiperd/sshpiperd", args...)
			if err != nil {
				t.Fatalf("failed to run sshpiperd: %v", err)
			}
			t.Cleanup(func() { killCmd(piper) })
			waitForEndpointReady(piperaddr)

			// Test ssh -L (local forwarding), tunneling back into the
			// upstream sshd's own port.
			localPort := nextAvailablePort()
			startForwardingSSH(t, piperport, "Local forwarding listening", "-L",
				fmt.Sprintf("%d:127.0.0.1:%d", localPort, upstreamForwardingPort))
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
