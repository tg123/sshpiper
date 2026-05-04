package httpapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		{"/api/v1/sessions/host%2F%5B%3A%3A%5D%3A2222/abc-123/stream", "host/[::]:2222", "abc-123", "stream", true},
		{"/api/v1/sessions/host%2F%5B%3A%3A%5D%3A2222/abc-123", "host/[::]:2222", "abc-123", "", true},
		{"/api/v1/sessions/", "", "", "", false},
		{"/api/v1/sessions/onlyinstance", "", "", "", false},
		{"/something/else", "", "", "", false},
		// reject extra trailing segments / slashes
		{"/api/v1/sessions/inst/sess/stream/extra", "", "", "", false},
		{"/api/v1/sessions/inst/sess/", "", "", "", false},
	}
	for _, c := range cases {
		i, id, a, ok := parseSessionPath(c.in)
		if i != c.instance || id != c.id || a != c.action || ok != c.ok {
			t.Errorf("parseSessionPath(%q) = (%q,%q,%q,%v), want (%q,%q,%q,%v)",
				c.in, i, id, a, ok, c.instance, c.id, c.action, c.ok)
		}
	}
}

func TestStaticPath_DisableDoesNotServeUI(t *testing.T) {
	addr := startStub(t, "i1", nil)
	a := newAgg(t, addr)
	h := New(a, Options{StaticPath: "disable"})

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET / status = %d, want 404 when UI is disabled", w.Code)
	}

	// API still works.
	r = httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/version status = %d, want 200", w.Code)
	}
}

func TestStaticPath_InvalidDirIsRejected(t *testing.T) {
	addr := startStub(t, "i1", nil)
	a := newAgg(t, addr)

	// A directory that is missing the required index.html / dist layout.
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, "secret.txt"), []byte("nope"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	h := New(a, Options{StaticPath: bad})

	r := httptest.NewRequest(http.MethodGet, "/secret.txt", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET /secret.txt status = %d, want 404 (UI handler should not be registered for invalid dir)", w.Code)
	}

	if err := validateStaticDir(bad); err == nil {
		t.Fatalf("validateStaticDir(%q) = nil, want error", bad)
	}
}

func TestStaticPath_DirectoryListingIsDisabled(t *testing.T) {
	addr := startStub(t, "i1", nil)
	a := newAgg(t, addr)

	// Build a minimal valid layout: index.html, dist/, plus an extra
	// directory without an index.html — which must NOT be listable.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>root"), 0o600); err != nil {
		t.Fatalf("write index.html: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "dist"), 0o700); err != nil {
		t.Fatalf("mkdir dist: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dist", "app.js"), []byte("console.log('hi')"), 0o600); err != nil {
		t.Fatalf("write dist/app.js: %v", err)
	}

	h := New(a, Options{StaticPath: dir})

	// Direct file access still works.
	r := httptest.NewRequest(http.MethodGet, "/dist/app.js", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /dist/app.js = %d, want 200", w.Code)
	}

	// Directory request without index.html returns 404, not a listing.
	r = httptest.NewRequest(http.MethodGet, "/dist/", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET /dist/ = %d, want 404 (no directory listing)", w.Code)
	}

	// Root directory with index.html is still served.
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET / = %d, want 200 (index.html should be served)", w.Code)
	}
}
