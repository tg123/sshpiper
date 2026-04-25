package libadmin

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
)

// stubServer is a minimal SshPiperAdminServer implementation used by tests.
type stubServer struct {
	UnimplementedSshPiperAdminServer
	id       string
	addr     string
	sessions []*Session
	killed   string
}

func (s *stubServer) ServerInfo(_ context.Context, _ *ServerInfoRequest) (*ServerInfoResponse, error) {
	return &ServerInfoResponse{Id: s.id, Version: "stub", SshAddr: s.addr, StartedAt: time.Now().Unix()}, nil
}

func (s *stubServer) ListSessions(_ context.Context, _ *ListSessionsRequest) (*ListSessionsResponse, error) {
	return &ListSessionsResponse{Sessions: s.sessions}, nil
}

func (s *stubServer) KillSession(_ context.Context, req *KillSessionRequest) (*KillSessionResponse, error) {
	s.killed = req.GetId()
	return &KillSessionResponse{Killed: true}, nil
}

func startStub(t *testing.T, id string, sessions []*Session) (*stubServer, string) {
	t.Helper()
	stub := &stubServer{id: id, addr: id + "-ssh", sessions: sessions}
	gs := grpc.NewServer()
	RegisterSshPiperAdminServer(gs, stub)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() { gs.Stop() })
	return stub, lis.Addr().String()
}

func TestAggregator_RefreshAndListAcrossInstances(t *testing.T) {
	stubA, addrA := startStub(t, "piper-a", []*Session{
		{Id: "a1", DownstreamUser: "u1"},
		{Id: "a2", DownstreamUser: "u2"},
	})
	_, addrB := startStub(t, "piper-b", []*Session{
		{Id: "b1", DownstreamUser: "u3"},
	})

	disc := NewStaticDiscovery([]string{addrA, addrB})
	agg := NewAggregator(disc, DialOptions{Insecure: true})
	defer agg.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	infos, errs := agg.Refresh(ctx)
	if len(errs) != 0 {
		t.Fatalf("Refresh errors: %v", errs)
	}
	if len(infos) != 2 {
		t.Fatalf("expected 2 instances, got %d", len(infos))
	}

	all, errs := agg.ListAllSessions(ctx)
	if len(errs) != 0 {
		t.Fatalf("ListAllSessions errors: %v", errs)
	}
	if len(all) != 3 {
		t.Fatalf("expected 3 sessions, got %d", len(all))
	}
	byID := map[string]string{}
	for _, s := range all {
		byID[s.Session.GetId()] = s.InstanceID
	}
	if byID["a1"] != "piper-a" || byID["b1"] != "piper-b" {
		t.Fatalf("session→instance mapping wrong: %+v", byID)
	}

	if _, err := agg.KillSession(ctx, "piper-a", "a1"); err != nil {
		t.Fatalf("KillSession: %v", err)
	}
	if stubA.killed != "a1" {
		t.Fatalf("stubA.killed = %q", stubA.killed)
	}

	if _, err := agg.KillSession(ctx, "unknown", "x"); err == nil {
		t.Fatal("KillSession to unknown instance should error")
	}
}

func TestAggregator_RefreshClosesRemovedEndpoints(t *testing.T) {
	_, addrA := startStub(t, "piper-a", nil)
	_, addrB := startStub(t, "piper-b", nil)

	disc := NewStaticDiscovery([]string{addrA, addrB})
	agg := NewAggregator(disc, DialOptions{Insecure: true})
	defer agg.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, errs := agg.Refresh(ctx); len(errs) != 0 {
		t.Fatalf("first Refresh: %v", errs)
	}
	if got := len(agg.Instances()); got != 2 {
		t.Fatalf("want 2 instances, got %d", got)
	}

	disc.Set([]string{addrA})
	if _, errs := agg.Refresh(ctx); len(errs) != 0 {
		t.Fatalf("second Refresh: %v", errs)
	}
	if got := len(agg.Instances()); got != 1 {
		t.Fatalf("want 1 instance after shrink, got %d", got)
	}
	if agg.ClientFor("piper-b") != nil {
		t.Fatal("ClientFor(piper-b) should be nil after removal")
	}
}
