//go:build full || e2e

package main

import (
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// fakeChannel is a no-op ssh.Channel: reads return EOF so serveSession's stdin
// scanner exits immediately.
type fakeChannel struct{}

func (fakeChannel) Read([]byte) (int, error)                       { return 0, io.EOF }
func (fakeChannel) Write(b []byte) (int, error)                    { return len(b), nil }
func (fakeChannel) Close() error                                   { return nil }
func (fakeChannel) CloseWrite() error                              { return nil }
func (fakeChannel) SendRequest(string, bool, []byte) (bool, error) { return false, nil }
func (fakeChannel) Stderr() io.ReadWriter                          { return nil }

// fakeNewChannel records whether it was accepted or rejected.
type fakeNewChannel struct {
	typ      string
	ch       ssh.Channel
	reqs     chan *ssh.Request
	rejected bool
	reason   ssh.RejectionReason
}

func (c *fakeNewChannel) Accept() (ssh.Channel, <-chan *ssh.Request, error) {
	return c.ch, c.reqs, nil
}

func (c *fakeNewChannel) Reject(r ssh.RejectionReason, _ string) error {
	c.rejected, c.reason = true, r
	return nil
}
func (c *fakeNewChannel) ChannelType() string { return c.typ }
func (c *fakeNewChannel) ExtraData() []byte   { return nil }

// TestOneSessionPerConnection verifies only the first session channel is
// accepted; a second is rejected so guidCh has a single consumer.
func TestOneSessionPerConnection(t *testing.T) {
	h := &connHandler{
		reg:      newRegistry(newMemoryStore()),
		srv:      &registerServer{},
		guidCh:   make(chan registrationNotif, 4),
		forwards: make(map[string]string),
	}

	// The first session gets a "signal" request so serveSession returns fast.
	reqs1 := make(chan *ssh.Request, 1)
	reqs1 <- &ssh.Request{Type: "signal"}
	close(reqs1)

	first := &fakeNewChannel{typ: "session", ch: fakeChannel{}, reqs: reqs1}
	second := &fakeNewChannel{typ: "session", ch: fakeChannel{}, reqs: make(chan *ssh.Request)}

	chans := make(chan ssh.NewChannel, 2)
	chans <- first
	chans <- second
	close(chans)

	h.handleChannels(chans)

	if first.rejected {
		t.Fatal("the first session channel must be accepted")
	}
	if !second.rejected || second.reason != ssh.Prohibited {
		t.Fatalf("the second session must be rejected as Prohibited; rejected=%v reason=%v", second.rejected, second.reason)
	}
}

func TestRegistrationNotificationQueue(t *testing.T) {
	srv := &registerServer{maxPerConn: 2, maxTotal: 10}
	if got := srv.notificationQueueCapacity(); got != 2 {
		t.Fatalf("notification queue capacity = %d, want 2", got)
	}

	h := &connHandler{guidCh: make(chan registrationNotif, srv.notificationQueueCapacity())}
	if !h.enqueueRegistration("a") || !h.enqueueRegistration("b") {
		t.Fatal("allowed notifications should fit in the queue")
	}
	if h.enqueueRegistration("overflow") {
		t.Fatal("overflow notification must be rejected, not silently dropped")
	}

	unlimited := &registerServer{maxPerConn: 0, maxTotal: 0}
	if got := unlimited.notificationQueueCapacity(); got != 1024 {
		t.Fatalf("unlimited pending-burst capacity = %d, want 1024", got)
	}
}

// fakeSSHConn is a minimal ssh.Conn that only records Close calls, used to
// verify that the registry closes a shared registrar connection at the right
// time.
type fakeSSHConn struct {
	closed atomic.Int32
}

func (c *fakeSSHConn) Close() error { c.closed.Add(1); return nil }
func (c *fakeSSHConn) Wait() error  { return nil }
func (c *fakeSSHConn) SendRequest(string, bool, []byte) (bool, []byte, error) {
	return false, nil, nil
}

func (c *fakeSSHConn) OpenChannel(string, []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	return nil, nil, nil
}
func (c *fakeSSHConn) User() string          { return "" }
func (c *fakeSSHConn) SessionID() []byte     { return nil }
func (c *fakeSSHConn) ClientVersion() []byte { return nil }
func (c *fakeSSHConn) ServerVersion() []byte { return nil }
func (c *fakeSSHConn) RemoteAddr() net.Addr  { return &net.IPAddr{} }
func (c *fakeSSHConn) LocalAddr() net.Addr   { return &net.IPAddr{} }

var _ ssh.Conn = (*fakeSSHConn)(nil)

// TestEvictIdleSharedConn verifies that evicting one idle forward does not tear
// down a sibling forward that shares the same registrar connection, and that
// the connection is closed only once every forward on it is gone.
func TestEvictIdleSharedConn(t *testing.T) {
	reg := newRegistry(newMemoryStore())
	now := time.Unix(2_000_000_000, 0).UTC()
	reg.now = func() time.Time { return now }

	conn := &fakeSSHConn{}
	if err := reg.Put(mkRecord("idle"), conn); err != nil {
		t.Fatalf("Put idle: %v", err)
	}
	if err := reg.Put(mkRecord("active"), conn); err != nil {
		t.Fatalf("Put active: %v", err)
	}

	// Advance time so both are stale, then keep "active" fresh.
	later := now.Add(3 * time.Hour)
	reg.now = func() time.Time { return later }
	reg.Touch("active")

	evicted := reg.EvictIdle(2 * time.Hour)
	if len(evicted) != 1 || evicted[0] != "idle" {
		t.Fatalf("evicted = %v, want [idle]", evicted)
	}
	if got := conn.closed.Load(); got != 0 {
		t.Fatalf("shared conn closed %d times while a sibling is still live; want 0", got)
	}
	if _, _, ok := reg.Lookup("active"); !ok {
		t.Fatal("active sibling must survive eviction of an idle forward")
	}

	// Now let the sibling go idle too; the connection should be closed once.
	reg.now = func() time.Time { return later.Add(3 * time.Hour) }
	evicted = reg.EvictIdle(2 * time.Hour)
	if len(evicted) != 1 || evicted[0] != "active" {
		t.Fatalf("second eviction = %v, want [active]", evicted)
	}
	if got := conn.closed.Load(); got != 1 {
		t.Fatalf("shared conn closed %d times, want 1", got)
	}
}

// TestRemoveKeepsConn verifies Remove deletes a record without closing the
// registrar connection (used by cancel-tcpip-forward / override revocation).
func TestRemoveKeepsConn(t *testing.T) {
	reg := newRegistry(newMemoryStore())
	conn := &fakeSSHConn{}
	if err := reg.Put(mkRecord("g"), conn); err != nil {
		t.Fatalf("Put: %v", err)
	}
	reg.Remove("g")
	if _, _, ok := reg.Lookup("g"); ok {
		t.Fatal("record should be gone after Remove")
	}
	if got := conn.closed.Load(); got != 0 {
		t.Fatalf("Remove closed the shared conn %d times; want 0", got)
	}
}

// TestDeleteSharedConn verifies that Delete does not close a registrar
// connection while a sibling forward on the same connection remains live, and
// closes it once the last forward is deleted.
func TestDeleteSharedConn(t *testing.T) {
	reg := newRegistry(newMemoryStore())
	conn := &fakeSSHConn{}
	if err := reg.Put(mkRecord("a"), conn); err != nil {
		t.Fatalf("Put a: %v", err)
	}
	if err := reg.Put(mkRecord("b"), conn); err != nil {
		t.Fatalf("Put b: %v", err)
	}

	reg.Delete("a")
	if got := conn.closed.Load(); got != 0 {
		t.Fatalf("Delete closed the shared conn %d times while sibling b is live; want 0", got)
	}
	if _, _, ok := reg.Lookup("b"); !ok {
		t.Fatal("sibling b must survive Delete of a")
	}

	reg.Delete("b")
	if got := conn.closed.Load(); got != 1 {
		t.Fatalf("shared conn closed %d times after deleting the last forward, want 1", got)
	}
}

// TestRevokeForward covers cancel-tcpip-forward semantics: a specific-port
// cancel revokes only the exact forward (unmatched is a no-op), while a bare
// `-R 0` cancel revokes every forward sharing the bind address.
func TestRevokeForward(t *testing.T) {
	newHandler := func(reg *registry) *connHandler {
		return &connHandler{reg: reg, forwards: make(map[string]string)}
	}
	register := func(h *connHandler, reg *registry, guid, addr string, port uint32) {
		if err := reg.Put(mkRecord(guid), nil); err != nil {
			t.Fatalf("Put %s: %v", guid, err)
		}
		h.guids = append(h.guids, guid)
		h.forwards[forwardKey(addr, port)] = guid
	}

	t.Run("specific matched revokes only that forward", func(t *testing.T) {
		reg := newRegistry(newMemoryStore())
		h := newHandler(reg)
		register(h, reg, "a", "localhost", 4000)
		register(h, reg, "b", "localhost", 5000)

		h.revokeForward("localhost", 4000)

		if _, _, ok := reg.Lookup("a"); ok {
			t.Fatal("forward a should be revoked")
		}
		if _, _, ok := reg.Lookup("b"); !ok {
			t.Fatal("forward b must survive a specific cancel for a's port")
		}
	})

	t.Run("specific unmatched is a no-op", func(t *testing.T) {
		reg := newRegistry(newMemoryStore())
		h := newHandler(reg)
		register(h, reg, "a", "localhost", 4000)

		h.revokeForward("localhost", 9999) // no forward on this port

		if _, _, ok := reg.Lookup("a"); !ok {
			t.Fatal("an unmatched specific cancel must not revoke unrelated tunnels")
		}
	})

	t.Run("bare port-zero sweeps the bind address", func(t *testing.T) {
		reg := newRegistry(newMemoryStore())
		h := newHandler(reg)
		register(h, reg, "a", "localhost", 4000)
		register(h, reg, "b", "localhost", 5000)
		register(h, reg, "c", "other", 6000)

		h.revokeForward("localhost", 0)

		if _, _, ok := reg.Lookup("a"); ok {
			t.Fatal("forward a on localhost should be swept")
		}
		if _, _, ok := reg.Lookup("b"); ok {
			t.Fatal("forward b on localhost should be swept")
		}
		if _, _, ok := reg.Lookup("c"); !ok {
			t.Fatal("forward c on a different bind address must survive")
		}
	})

	t.Run("IPv6 sweep matches the exact address", func(t *testing.T) {
		reg := newRegistry(newMemoryStore())
		h := newHandler(reg)
		register(h, reg, "a", "2001:db8::1", 4000)
		register(h, reg, "b", "2001:db8::1:2", 5000)

		h.revokeForward("2001:db8::1", 0)

		if _, _, ok := reg.Lookup("a"); ok {
			t.Fatal("forward a on the exact IPv6 address should be swept")
		}
		if _, _, ok := reg.Lookup("b"); !ok {
			t.Fatal("forward b on a longer IPv6 address must survive")
		}
	})
}

// TestChannelConnTouchGating verifies channelConn only refreshes LastActivity
// after the pipe is marked authenticated (as PipeStartCallback would), so
// pre-auth/failed connects can't keep a tunnel alive.
func TestChannelConnTouchGating(t *testing.T) {
	reg := newRegistry(newMemoryStore())
	now := time.Unix(2_000_000_000, 0).UTC()
	reg.now = func() time.Time { return now }
	if err := reg.Put(mkRecord("g"), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	later := now.Add(time.Hour)
	reg.now = func() time.Time { return later }

	cc := &channelConn{reg: reg, guid: "g"}

	// Not authenticated yet: touch must be a no-op.
	cc.touch()
	if rec, _, _ := reg.Lookup("g"); !rec.LastActivity.Equal(now) {
		t.Fatalf("pre-auth touch refreshed LastActivity: got %v want %v", rec.LastActivity, now)
	}

	// After PipeStart marks it authed, touch refreshes LastActivity.
	cc.authed.Store(true)
	cc.touch()
	if rec, _, _ := reg.Lookup("g"); !rec.LastActivity.Equal(later) {
		t.Fatalf("authed touch did not refresh LastActivity: got %v want %v", rec.LastActivity, later)
	}
}

// TestReserveForwardPort verifies collision-free bind-port allocation: a fixed
// port in use is rejected, the same port on a different bind address is fine,
// and a zero request yields a synthesized port not already mapped.
func TestReserveForwardPort(t *testing.T) {
	h := &connHandler{forwards: make(map[string]string)}

	p, ok := h.reserveForwardPort("localhost", 4000)
	if !ok || p != 4000 {
		t.Fatalf("free fixed port: got %d, %v", p, ok)
	}
	h.forwards[forwardKey("localhost", 4000)] = "g1"

	if _, ok := h.reserveForwardPort("localhost", 4000); ok {
		t.Fatal("a fixed port already in use must be rejected")
	}
	if _, ok := h.reserveForwardPort("other", 4000); !ok {
		t.Fatal("the same port on a different bind address should be allowed")
	}

	sp, ok := h.reserveForwardPort("localhost", 0)
	if !ok || sp == 0 {
		t.Fatalf("synthesized port: got %d, %v", sp, ok)
	}
	if _, taken := h.forwards[forwardKey("localhost", sp)]; taken {
		t.Fatalf("synthesized port %d collides with an existing forward", sp)
	}
}

// TestRegistryMaxTotal verifies the global cap is enforced by Put itself
// (atomic with the insert) and that freeing a slot allows a new tunnel.
func TestRegistryMaxTotal(t *testing.T) {
	reg := newRegistry(newMemoryStore())
	reg.maxTotal = 2

	if err := reg.Put(mkRecord("a"), nil); err != nil {
		t.Fatalf("Put a: %v", err)
	}
	if err := reg.Put(mkRecord("b"), nil); err != nil {
		t.Fatalf("Put b: %v", err)
	}
	if err := reg.Put(mkRecord("c"), nil); err == nil {
		t.Fatal("Put beyond maxTotal must be rejected")
	}

	reg.Delete("a")
	if err := reg.Put(mkRecord("c"), nil); err != nil {
		t.Fatalf("Put after freeing a slot should succeed: %v", err)
	}
}

// TestCountLiveForwardsPrunes verifies that per-connection bookkeeping for
// sweeper-evicted tunnels is pruned so the quota reflects only live forwards.
func TestCountLiveForwardsPrunes(t *testing.T) {
	reg := newRegistry(newMemoryStore())
	if err := reg.Put(mkRecord("a"), nil); err != nil {
		t.Fatalf("Put a: %v", err)
	}
	if err := reg.Put(mkRecord("b"), nil); err != nil {
		t.Fatalf("Put b: %v", err)
	}
	h := &connHandler{
		reg:      reg,
		srv:      &registerServer{maxPerConn: 0}, // unlimited still must prune
		forwards: make(map[string]string),
	}
	h.guids = []string{"a", "b"}
	h.forwards[forwardKey("x", 1)] = "a"
	h.forwards[forwardKey("x", 2)] = "b"

	// Simulate the sweeper evicting "a" from the registry.
	reg.Remove("a")

	if h.perConnLimitReached() {
		t.Fatal("unlimited per-connection mode must not report its limit reached")
	}
	if len(h.guids) != 1 || h.guids[0] != "b" {
		t.Fatalf("stale guid not pruned: %v", h.guids)
	}
	if _, ok := h.forwards[forwardKey("x", 1)]; ok {
		t.Fatal("stale forward mapping for a not pruned")
	}
	if _, ok := h.forwards[forwardKey("x", 2)]; !ok {
		t.Fatal("live forward mapping for b must remain")
	}
}

// TestSessionEnvIsolation verifies env overrides are scoped to the session that
// set them: a later session on the same connection does not inherit a previous
// session's ALLOWPASSWORD.
func TestSessionEnvIsolation(t *testing.T) {
	reg := newRegistry(newMemoryStore())
	h := &connHandler{reg: reg}
	if err := reg.Put(mkRecord("g1"), nil); err != nil {
		t.Fatalf("Put g1: %v", err)
	}
	if err := reg.Put(mkRecord("g2"), nil); err != nil {
		t.Fatalf("Put g2: %v", err)
	}

	sessA := newRegSession()
	sessA.envAllowPassword = true
	if err := h.applyEnvOverrides(sessA, "g1"); err != nil {
		t.Fatalf("applyEnvOverrides A: %v", err)
	}

	sessB := newRegSession() // fresh session, no ALLOWPASSWORD
	if err := h.applyEnvOverrides(sessB, "g2"); err != nil {
		t.Fatalf("applyEnvOverrides B: %v", err)
	}

	if rec, _, _ := reg.Lookup("g1"); !rec.AllowPassword {
		t.Fatal("g1 (session A) should have password auth enabled")
	}
	if rec, _, _ := reg.Lookup("g2"); rec.AllowPassword {
		t.Fatal("g2 (session B) must not inherit session A's ALLOWPASSWORD")
	}
}
