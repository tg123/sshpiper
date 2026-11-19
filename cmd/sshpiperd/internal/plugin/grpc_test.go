package plugin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/tg123/sshpiper/libplugin"
	"github.com/tg123/sshpiper/libplugin/connovergrpc"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"google.golang.org/grpc"
)

// hostKeyMockClient implements libplugin.SshPiperPluginClient with only the
// VerifyHostKey method wired up. The embedded interface is nil, so any other
// method call would panic — these tests must only exercise VerifyHostKey.
type hostKeyMockClient struct {
	libplugin.SshPiperPluginClient
	verifyFn func(*libplugin.VerifyHostKeyRequest) (*libplugin.VerifyHostKeyResponse, error)
	lastReq  *libplugin.VerifyHostKeyRequest
}

func (m *hostKeyMockClient) VerifyHostKey(_ context.Context, in *libplugin.VerifyHostKeyRequest, _ ...grpc.CallOption) (*libplugin.VerifyHostKeyResponse, error) {
	m.lastReq = in
	return m.verifyFn(in)
}

func newTestHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	return pub
}

func TestBuildHostKeyCallbackEmptyDataIsInsecureSkip(t *testing.T) {
	g := &GrpcPlugin{}
	cb := g.buildHostKeyCallback(&libplugin.ConnMeta{}, &libplugin.Upstream{})
	if cb == nil {
		t.Fatal("expected non-nil callback")
	}
	if err := cb("host:22", mockAddr("1.2.3.4:22"), newTestHostKey(t)); err != nil {
		t.Fatalf("expected empty known_hosts_data to skip verification, got %v", err)
	}
}

func TestBuildHostKeyCallbackKnownHostsDataMatches(t *testing.T) {
	pub := newTestHostKey(t)
	host := "[127.0.0.1]:2222"
	line := knownhosts.Line([]string{host}, pub)

	g := &GrpcPlugin{}
	cb := g.buildHostKeyCallback(&libplugin.ConnMeta{}, &libplugin.Upstream{KnownHostsData: []byte(line)})

	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:2222")
	if err != nil {
		t.Fatalf("ResolveTCPAddr: %v", err)
	}
	if err := cb(host, addr, pub); err != nil {
		t.Fatalf("expected matching key to succeed, got %v", err)
	}
}

func TestBuildHostKeyCallbackKnownHostsDataMismatch(t *testing.T) {
	expected := newTestHostKey(t)
	wrong := newTestHostKey(t)
	host := "[127.0.0.1]:2222"
	line := knownhosts.Line([]string{host}, expected)

	g := &GrpcPlugin{}
	cb := g.buildHostKeyCallback(&libplugin.ConnMeta{}, &libplugin.Upstream{KnownHostsData: []byte(line)})

	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:2222")
	if err != nil {
		t.Fatalf("ResolveTCPAddr: %v", err)
	}
	if err := cb(host, addr, wrong); err == nil {
		t.Fatal("expected mismatched key to fail")
	}
}

func TestBuildHostKeyCallbackMalformedKnownHostsData(t *testing.T) {
	g := &GrpcPlugin{}
	cb := g.buildHostKeyCallback(&libplugin.ConnMeta{}, &libplugin.Upstream{KnownHostsData: []byte("not-a-known-hosts-line\n")})
	err := cb("host:22", mockAddr("1.2.3.4:22"), newTestHostKey(t))
	if err == nil || !strings.Contains(err.Error(), "failed to parse known_hosts data") {
		t.Fatalf("expected parse-error callback, got %v", err)
	}
}

func TestBuildHostKeyCallbackRPCVerified(t *testing.T) {
	mock := &hostKeyMockClient{
		verifyFn: func(*libplugin.VerifyHostKeyRequest) (*libplugin.VerifyHostKeyResponse, error) {
			return &libplugin.VerifyHostKeyResponse{Verified: true}, nil
		},
	}
	g := &GrpcPlugin{client: mock, hasVerifyHostKeyCallback: true}
	cb := g.buildHostKeyCallback(&libplugin.ConnMeta{UserName: "alice"}, &libplugin.Upstream{})

	pub := newTestHostKey(t)
	if err := cb("host", mockAddr("1.2.3.4:22"), pub); err != nil {
		t.Fatalf("expected verified RPC to succeed, got %v", err)
	}
	if mock.lastReq == nil || mock.lastReq.Hostname != "host" || mock.lastReq.Netaddress != "1.2.3.4:22" {
		t.Fatalf("unexpected VerifyHostKey request: %+v", mock.lastReq)
	}
	if mock.lastReq.Meta == nil || mock.lastReq.Meta.UserName != "alice" {
		t.Fatalf("expected meta to be propagated, got %+v", mock.lastReq.Meta)
	}
}

func TestBuildHostKeyCallbackRPCRejected(t *testing.T) {
	mock := &hostKeyMockClient{
		verifyFn: func(*libplugin.VerifyHostKeyRequest) (*libplugin.VerifyHostKeyResponse, error) {
			return &libplugin.VerifyHostKeyResponse{Verified: false}, nil
		},
	}
	g := &GrpcPlugin{client: mock, hasVerifyHostKeyCallback: true}
	cb := g.buildHostKeyCallback(&libplugin.ConnMeta{}, &libplugin.Upstream{})

	if err := cb("host", mockAddr("1.2.3.4:22"), newTestHostKey(t)); err == nil {
		t.Fatal("expected unverified RPC response to fail")
	}
}

func TestBuildHostKeyCallbackRPCError(t *testing.T) {
	rpcErr := errors.New("rpc broke")
	mock := &hostKeyMockClient{
		verifyFn: func(*libplugin.VerifyHostKeyRequest) (*libplugin.VerifyHostKeyResponse, error) {
			return nil, rpcErr
		},
	}
	g := &GrpcPlugin{client: mock, hasVerifyHostKeyCallback: true}
	cb := g.buildHostKeyCallback(&libplugin.ConnMeta{}, &libplugin.Upstream{})

	if err := cb("host", mockAddr("1.2.3.4:22"), newTestHostKey(t)); !errors.Is(err, rpcErr) {
		t.Fatalf("expected rpc error to propagate, got %v", err)
	}
}

// RPC callback takes precedence over KnownHostsData when both are present.
func TestBuildHostKeyCallbackRPCTakesPrecedenceOverData(t *testing.T) {
	called := false
	mock := &hostKeyMockClient{
		verifyFn: func(*libplugin.VerifyHostKeyRequest) (*libplugin.VerifyHostKeyResponse, error) {
			called = true
			return &libplugin.VerifyHostKeyResponse{Verified: true}, nil
		},
	}
	g := &GrpcPlugin{client: mock, hasVerifyHostKeyCallback: true}
	cb := g.buildHostKeyCallback(&libplugin.ConnMeta{}, &libplugin.Upstream{KnownHostsData: []byte("not-a-known-hosts-line\n")})

	if err := cb("host", mockAddr("1.2.3.4:22"), newTestHostKey(t)); err != nil {
		t.Fatalf("expected RPC path to be used, got %v", err)
	}
	if !called {
		t.Fatal("expected RPC to be called even when KnownHostsData is also set")
	}
}

type proxyProtocolMockClient struct {
	grpc.ClientStream
	ctx      context.Context
	written  []byte
	writeErr error
	closed   bool
}

func (m *proxyProtocolMockClient) CreateConn(ctx context.Context, _ ...grpc.CallOption) (grpc.BidiStreamingClient[connovergrpc.Packet, connovergrpc.Packet], error) {
	m.ctx = ctx
	return m, nil
}

func (m *proxyProtocolMockClient) Send(packet *connovergrpc.Packet) error {
	if packet.GetDialRequest() != nil {
		return nil
	}
	if m.writeErr != nil {
		return m.writeErr
	}
	m.written = append(m.written, packet.GetData()...)
	return nil
}

func (m *proxyProtocolMockClient) Recv() (*connovergrpc.Packet, error) {
	panic("unexpected read before SSH handshake")
}

func (m *proxyProtocolMockClient) CloseSend() error {
	m.closed = true
	return nil
}

func TestCreateUpstreamProxyProtocol(t *testing.T) {
	downstream := mockConnMetadata{
		user:       "alice",
		remoteAddr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 45678},
		localAddr:  &net.TCPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 2222},
	}
	for _, tt := range []struct {
		name    string
		version byte
		header  string
	}{
		{name: "off"},
		{
			name:    "v1",
			version: 1,
			header:  "PROXY TCP4 192.0.2.1 198.51.100.2 45678 2222\r\n",
		},
		{
			name:    "v2",
			version: 2,
			header:  "\r\n\r\n\x00\r\nQUIT\n\x21\x11\x00\x0c\xc0\x00\x02\x01\xc6\x33\x64\x02\xb2\x6e\x08\xae",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := &proxyProtocolMockClient{}
			g := &GrpcPlugin{
				connClient:                   client,
				hasCreateConnCallback:        true,
				upstreamProxyProtocolVersion: tt.version,
			}
			upstream, err := g.createUpstream(downstream, &PluginConnMeta{}, &libplugin.Upstream{
				Uri: "tcp://upstream.example:22",
			})
			if err != nil {
				t.Fatalf("createUpstream: %v", err)
			}
			t.Cleanup(func() { _ = upstream.Conn.Close() })

			if got := string(client.written); got != tt.header {
				t.Fatalf("bytes before SSH = %q, want %q", got, tt.header)
			}
			if client.closed {
				t.Fatal("successful connection was closed")
			}
			const banner = "SSH-2.0-test\r\n"
			if _, err := upstream.Conn.Write([]byte(banner)); err != nil {
				t.Fatalf("write SSH banner: %v", err)
			}
			if got := string(client.written); got != tt.header+banner {
				t.Fatalf("wire bytes = %q, want %q", got, tt.header+banner)
			}
		})
	}
}

func TestCreateUpstreamProxyProtocolWriteFailure(t *testing.T) {
	for _, version := range []byte{1, 2} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			writeErr := errors.New("header write failed")
			client := &proxyProtocolMockClient{writeErr: writeErr}
			g := &GrpcPlugin{
				connClient:                   client,
				hasCreateConnCallback:        true,
				upstreamProxyProtocolVersion: version,
			}
			upstream, err := g.createUpstream(mockConnMetadata{
				user:       "alice",
				remoteAddr: &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 45678},
				localAddr:  &net.TCPAddr{IP: net.IPv4(198, 51, 100, 2), Port: 2222},
			}, &PluginConnMeta{}, &libplugin.Upstream{Uri: "tcp://upstream.example:22"})
			if upstream != nil {
				_ = upstream.Conn.Close()
				t.Fatal("expected no upstream on header write failure")
			}
			if !errors.Is(err, writeErr) {
				t.Fatalf("createUpstream error = %v, want wrapped %v", err, writeErr)
			}
			if !strings.Contains(err.Error(), "failed to send PROXY protocol header to upstream upstream.example:22") {
				t.Fatalf("missing header write error context: %v", err)
			}
			if !client.closed || !errors.Is(client.ctx.Err(), context.Canceled) {
				t.Fatal("header write failure did not close the dialed connection")
			}
		})
	}
}
