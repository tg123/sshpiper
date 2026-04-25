package httpapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tg123/sshpiper/cmd/sshpiperd-webadmin/internal/aggregator"
	"github.com/tg123/sshpiper/libadmin"
	"google.golang.org/grpc"
)

// stub mirrors libadmin/aggregator_test.go's stub but lives here to avoid a
// cross-package internal test dependency.
type stub struct {
	libadmin.UnimplementedSshPiperAdminServer
	id       string
	sessions []*libadmin.Session
}

func (s *stub) ServerInfo(_ context.Context, _ *libadmin.ServerInfoRequest) (*libadmin.ServerInfoResponse, error) {
	return &libadmin.ServerInfoResponse{Id: s.id, Version: "stub"}, nil
}

func (s *stub) ListSessions(_ context.Context, _ *libadmin.ListSessionsRequest) (*libadmin.ListSessionsResponse, error) {
	return &libadmin.ListSessionsResponse{Sessions: s.sessions}, nil
}

func (s *stub) KillSession(_ context.Context, req *libadmin.KillSessionRequest) (*libadmin.KillSessionResponse, error) {
	return &libadmin.KillSessionResponse{Killed: req.GetId() == "k"}, nil
}

func startStub(t *testing.T, id string, sessions []*libadmin.Session) string {
	t.Helper()
	s := &stub{id: id, sessions: sessions}
	gs := grpc.NewServer()
	libadmin.RegisterSshPiperAdminServer(gs, s)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() { gs.Stop() })
	return lis.Addr().String()
}

func newAgg(t *testing.T, addrs ...string) *aggregator.Aggregator {
	t.Helper()
	disc := libadmin.NewStaticDiscovery(addrs)
	a := aggregator.New(disc, libadmin.DialOptions{Insecure: true}, time.Hour)
	if _, errs := a.Refresh(context.Background()); len(errs) != 0 {
		t.Fatalf("refresh: %v", errs)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

func TestHTTP_SessionsAndKill(t *testing.T) {
	addr := startStub(t, "i1", []*libadmin.Session{{Id: "s1", DownstreamUser: "u"}})
	a := newAgg(t, addr)
	h := New(a, Options{AllowKill: true, Version: "v"})

	// /api/v1/sessions
	r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var listResp struct {
		Sessions []sessionJSON `json:"sessions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(listResp.Sessions) != 1 || listResp.Sessions[0].ID != "s1" || listResp.Sessions[0].InstanceID != "i1" {
		t.Fatalf("unexpected sessions: %+v", listResp.Sessions)
	}

	// DELETE /api/v1/sessions/i1/k → killed=true
	r = httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/i1/k", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body=%s", w.Code, w.Body.String())
	}
	var killResp struct{ Killed bool }
	_ = json.Unmarshal(w.Body.Bytes(), &killResp)
	if !killResp.Killed {
		t.Fatalf("kill body: %s", w.Body.String())
	}
}

func TestHTTP_KillForbiddenWhenReadonly(t *testing.T) {
	addr := startStub(t, "i1", nil)
	a := newAgg(t, addr)
	h := New(a, Options{AllowKill: false, Version: "v"})

	r := httptest.NewRequest(http.MethodDelete, "/api/v1/sessions/i1/x", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", w.Code)
	}
}

func TestParseSessionPath(t *testing.T) {
	cases := []struct {
		in       string
		instance string
		id       string
		action   string
		ok       bool
	}{
		{"/api/v1/sessions/inst/sess", "inst", "sess", "", true},
		{"/api/v1/sessions/inst/sess/stream", "inst", "sess", "stream", true},
		{"/api/v1/sessions/", "", "", "", false},
		{"/api/v1/sessions/onlyinstance", "", "", "", false},
		{"/something/else", "", "", "", false},
	}
	for _, c := range cases {
		i, id, a, ok := parseSessionPath(c.in)
		if i != c.instance || id != c.id || a != c.action || ok != c.ok {
			t.Errorf("parseSessionPath(%q) = (%q,%q,%q,%v), want (%q,%q,%q,%v)",
				c.in, i, id, a, ok, c.instance, c.id, c.action, c.ok)
		}
	}
}
