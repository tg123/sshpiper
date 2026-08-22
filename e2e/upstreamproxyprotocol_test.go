package e2e_test

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// proxyHeader is the subset of a PROXY protocol header the tests assert on.
type proxyHeader struct {
	version byte
	source  *net.TCPAddr
}

var proxyV2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// readProxyHeader parses a PROXY protocol v1 or v2 header from r. It fails
// on anything else, including a plain ssh banner, so an upstream built on it
// only accepts connections that really carry the header.
func readProxyHeader(r *bufio.Reader) (*proxyHeader, error) {
	peek, err := r.Peek(12)
	if err != nil {
		return nil, err
	}

	if bytes.Equal(peek, proxyV2Signature) {
		return readProxyV2(r)
	}

	if bytes.HasPrefix(peek, []byte("PROXY ")) {
		return readProxyV1(r)
	}

	return nil, fmt.Errorf("no PROXY protocol header, got %q", peek)
}

func readProxyV1(r *bufio.Reader) (*proxyHeader, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}

	// PROXY TCP4 <src> <dst> <srcport> <dstport>\r\n
	fields := strings.Fields(strings.TrimSuffix(line, "\r\n"))
	if len(fields) != 6 || fields[0] != "PROXY" {
		return nil, fmt.Errorf("malformed PROXY v1 line %q", line)
	}

	port, err := strconv.Atoi(fields[4])
	if err != nil {
		return nil, fmt.Errorf("malformed PROXY v1 source port in %q", line)
	}

	ip := net.ParseIP(fields[2])
	if ip == nil {
		return nil, fmt.Errorf("malformed PROXY v1 source address in %q", line)
	}

	return &proxyHeader{version: 1, source: &net.TCPAddr{IP: ip, Port: port}}, nil
}

func readProxyV2(r *bufio.Reader) (*proxyHeader, error) {
	var fixed [16]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return nil, err
	}

	// byte 12: version (high nibble) and command, byte 13: family/transport,
	// bytes 14-15: length of the address block that follows.
	if fixed[12]>>4 != 2 {
		return nil, fmt.Errorf("unexpected PROXY v2 version byte %#x", fixed[12])
	}

	family := fixed[13] >> 4
	addrLen := int(binary.BigEndian.Uint16(fixed[14:16]))

	addrs := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addrs); err != nil {
		return nil, err
	}

	var ipLen int
	switch family {
	case 1:
		ipLen = 4
	case 2:
		ipLen = 16
	default:
		return nil, fmt.Errorf("unexpected PROXY v2 address family %d", family)
	}

	if addrLen < 2*ipLen+4 {
		return nil, fmt.Errorf("PROXY v2 address block too short: %d", addrLen)
	}

	src := &net.TCPAddr{
		IP:   net.IP(addrs[:ipLen]),
		Port: int(binary.BigEndian.Uint16(addrs[2*ipLen : 2*ipLen+2])),
	}

	return &proxyHeader{version: 2, source: src}, nil
}

// startProxyProtocolUpstream listens on a random local port, requires a
// PROXY protocol header on every connection and then forwards the rest of
// the stream to host-password. The parsed header is sent on the returned
// channel so tests can assert on it. Connections without a valid header are
// closed, which makes the upstream unreachable for a piper that does not
// send one.
func startProxyProtocolUpstream(t *testing.T) (string, <-chan *proxyHeader, func()) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	headers := make(chan *proxyHeader, 16)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}

			go func(down net.Conn) {
				defer down.Close()

				r := bufio.NewReader(down)
				hdr, err := readProxyHeader(r)
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
				if hdr.version != tc.version {
					t.Errorf("expected PROXY protocol version %d, got %d", tc.version, hdr.version)
				}

				if !hdr.source.IP.IsLoopback() {
					t.Errorf("expected downstream client address in PROXY header, got %v", hdr.source)
				}

				if strconv.Itoa(hdr.source.Port) == piperport {
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
