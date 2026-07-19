//go:build full || e2e

package main

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

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
}
