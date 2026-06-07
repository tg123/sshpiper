package plugin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"google.golang.org/grpc"
)

// hostKeyMockClient implements libplugin.SshPiperPluginClient with only the
// VerifyHostKey method wired up. All other methods are no-ops so the type
// satisfies the interface; tests should only exercise VerifyHostKey.
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
