package e2e_test

import (
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
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

// startForwardingSSH starts an ssh subprocess with the given forwarding
// args, waits for readyText to appear on stdout, and returns the full line
// that matched (so callers can parse dynamically-assigned values out of it,
// e.g. a server-allocated remote forward port).
func startForwardingSSH(t *testing.T, piperPort, readyText string, forwardingArgs ...string) string {
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

	var matchedLine string
	waitForStdoutContains(stdout, readyText, func(line string) { matchedLine = line })
	return matchedLine
}

// allocatedPortPattern matches OpenSSH's client-side debug message emitted
// when a remote forward is requested with port 0 and the server picks a
// port to bind, e.g. "Allocated port 41191 for remote forward to ...".
var allocatedPortPattern = regexp.MustCompile(`Allocated port (\d+) for remote forward`)

// parseAllocatedPort extracts the server-allocated port number from an
// OpenSSH "Allocated port NNNN for remote forward to ..." debug line.
func parseAllocatedPort(t *testing.T, line string) int {
	t.Helper()

	m := allocatedPortPattern.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("failed to find allocated remote forward port in line: %q", line)
	}
	port, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("failed to parse allocated remote forward port %q: %v", m[1], err)
	}
	return port
}

// checkNormalSSHSessionWorks runs a plain exec session (no forwarding)
// through sshpiperd and verifies it completes successfully. This proves that
// disabling local/remote port forwarding only rejects forwarding requests and
// does not interfere with ordinary SSH usage.
func checkNormalSSHSessionWorks(t *testing.T, piperPort string) {
	t.Helper()

	randtext := uuid.New().String()

	c, stdin, stdout, err := runCmd(
		"ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-p", piperPort,
		"-l", "user",
		"127.0.0.1",
		fmt.Sprintf("echo %v", randtext),
	)
	if err != nil {
		t.Fatalf("failed to start ssh: %v", err)
	}
	t.Cleanup(func() { killCmd(c) })

	enterPassword(stdin, stdout, "pass")
	waitForStdoutContains(stdout, randtext, func(_ string) {})
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
			// end-to-end data transfer through the tunnel. We ask for port 0
			// (server-allocated) rather than picking a port ourselves: a
			// port chosen on the testrunner's network namespace is not
			// guaranteed to be free inside the upstream sshd container,
			// which could otherwise make the "enabled" case flaky or make
			// the "disabled" case pass for the wrong reason (bind failure
			// instead of sshpiper's rejection).
			var remotePort int
			if tc.remoteWorks {
				// OpenSSH's client prints "Allocated port NNNN for remote
				// forward to ..." once the server picks the actual port.
				line := startForwardingSSH(t, piperport, "Allocated port", "-R",
					fmt.Sprintf("0:127.0.0.1:%d", localTargetPort))
				remotePort = parseAllocatedPort(t, line)
			} else {
				// When the request is rejected, OpenSSH prints:
				// "Warning: remote port forwarding failed for listen port …"
				// No port is ever bound, so which port number we ask for
				// does not matter here.
				remotePort = nextAvailablePort()
				startForwardingSSH(t, piperport, "port forwarding failed", "-R",
					fmt.Sprintf("%d:127.0.0.1:%d", remotePort, localTargetPort))
			}
			checkRemoteForwarding(t, remotePort, tc.remoteWorks)

			// Disabling forwarding must not break normal (non-forwarding)
			// SSH usage such as running a command over the same connection.
			checkNormalSSHSessionWorks(t, piperport)
		})
	}
}
