package e2e_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pires/go-proxyproto"
)

// startProxyProtocolUpstream listens on a random local port, requires a
// PROXY protocol header on every connection and then forwards the rest of
// the stream to host-password. The parsed header is sent on the returned
// channel so tests can assert on it. Connections without a valid header are
// closed, which makes the upstream unreachable for a piper that does not
// send one.
func startProxyProtocolUpstream(t *testing.T) (string, <-chan *proxyproto.Header, func()) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	headers := make(chan *proxyproto.Header, 16)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}

			go func(down net.Conn) {
				defer down.Close()

				r := bufio.NewReader(down)
				hdr, err := proxyproto.Read(r)
				if err != nil {
					return
				}

				headers <- hdr

				up, err := net.Dial("tcp", "host-password:2222")
				if err != nil {
					return
				}
				defer up.Close()

				go func() { _, _ = io.Copy(up, r) }()
				_, _ = io.Copy(down, up)
			}(conn)
		}
	}()

	return l.Addr().String(), headers, func() { l.Close() }
}

func TestUpstreamProxyProtocol(t *testing.T) {
	for _, tc := range []struct {
		flag    string
		version byte
	}{
		{"v1", 1},
		{"v2", 2},
	} {
		t.Run(tc.flag, func(t *testing.T) {
			upstream, headers, stop := startProxyProtocolUpstream(t)
			defer stop()

			piperaddr, piperport := nextAvailablePiperAddress()

			piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
				"-p",
				piperport,
				"--upstream-proxy-protocol",
				tc.flag,
				"/sshpiperd/plugins/fixed",
				"--target",
				upstream,
			)
			if err != nil {
				t.Fatalf("failed to run sshpiperd: %v", err)
			}

			defer killCmd(piper)

			waitForEndpointReady(piperaddr)

			randtext := uuid.New().String()
			targetfie := uuid.New().String()

			c, stdin, stdout, err := runCmd(
				"ssh",
				"-v",
				"-o",
				"StrictHostKeyChecking=no",
				"-o",
				"UserKnownHostsFile=/dev/null",
				"-p",
				piperport,
				"-l",
				"user",
				"127.0.0.1",
				fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
			)
			if err != nil {
				t.Fatalf("failed to ssh to piper, %v", err)
			}

			defer killCmd(c)

			enterPassword(stdin, stdout, "pass")

			time.Sleep(time.Second) // wait for file flush

			checkSharedFileContent(t, targetfie, randtext)

			select {
			case hdr := <-headers:
				if hdr.Version != tc.version {
					t.Errorf("expected PROXY protocol version %d, got %d", tc.version, hdr.Version)
				}

				src, ok := hdr.SourceAddr.(*net.TCPAddr)
				if !ok {
					t.Fatalf("expected TCP source address in PROXY header, got %T", hdr.SourceAddr)
				}

				if !src.IP.IsLoopback() {
					t.Errorf("expected downstream client address in PROXY header, got %v", src)
				}

				if strconv.Itoa(src.Port) == piperport {
					t.Errorf("PROXY header carries the piper port %v, not the client's", piperport)
				}
			case <-time.After(waitTimeout):
				t.Fatalf("upstream did not receive a PROXY protocol header")
			}
		})
	}
}

func TestUpstreamProxyProtocolOff(t *testing.T) {
	upstream, headers, stop := startProxyProtocolUpstream(t)
	defer stop()

	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"--login-grace-time",
		"5s",
		"/sshpiperd/plugins/fixed",
		"--target",
		upstream,
	)
	if err != nil {
		t.Fatalf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	targetfie := uuid.New().String()

	c, stdin, stdout, err := runCmd(
		"ssh",
		"-v",
		"-o",
		"StrictHostKeyChecking=no",
		"-o",
		"UserKnownHostsFile=/dev/null",
		"-p",
		piperport,
		"-l",
		"user",
		"127.0.0.1",
		fmt.Sprintf(`sh -c "echo -n nope > /shared/%v"`, targetfie),
	)
	if err != nil {
		t.Fatalf("failed to ssh to piper, %v", err)
	}

	defer killCmd(c)

	enterPassword(stdin, stdout, "pass")

	done := make(chan error, 1)
	go func() {
		done <- c.Wait()
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("expected ssh to fail when upstream requires a PROXY protocol header and none is sent")
		}
	case <-time.After(waitTimeout * 3):
		t.Fatalf("timeout waiting for ssh to fail")
	}

	select {
	case hdr := <-headers:
		t.Fatalf("upstream unexpectedly received a PROXY protocol header: %+v", hdr)
	default:
	}

	if _, err := os.Stat(fmt.Sprintf("/shared/%v", targetfie)); err == nil {
		t.Fatalf("command must not have run on upstream without a PROXY protocol header")
	}
}
