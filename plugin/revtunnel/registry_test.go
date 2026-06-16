//go:build full || e2e

package main

import (
	"sync"
	"testing"
	"time"
)

func mkRecord(guid string) record {
	return record{
		Guid:                guid,
		TargetUser:          "alice",
		BindAddr:            "0.0.0.0",
		BindPort:            0,
		PublicKeyWire:       []byte{0x01, 0x02},
		PublicKeyAuthorized: "ssh-ed25519 AAAA...",
		PrivateKeyPEM:       []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n..."),
		CreatedAt:           time.Unix(1_700_000_000, 0).UTC(),
	}
}

func TestRegistryPutLookupTouchDelete(t *testing.T) {
	reg := newRegistry(newMemoryStore())
	now := time.Unix(2_000_000_000, 0).UTC()
	reg.now = func() time.Time { return now }

	if err := reg.Put(mkRecord("guid-1"), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	rec, _, ok := reg.Lookup("guid-1")
	if !ok {
		t.Fatalf("Lookup missed live entry")
	}
	if !rec.LastActivity.Equal(now) {
		t.Fatalf("Lookup should refresh LastActivity, got %v want %v", rec.LastActivity, now)
	}

	// Double-Put on the same guid must fail.
	if err := reg.Put(mkRecord("guid-1"), nil); err == nil {
		t.Fatalf("duplicate Put should error")
	}

	// Touch should bump activity even after lookup.
	later := now.Add(30 * time.Second)
	reg.now = func() time.Time { return later }
	reg.Touch("guid-1")
	rec, _, _ = reg.Lookup("guid-1")
	if !rec.LastActivity.Equal(later) {
		t.Fatalf("Touch did not advance LastActivity, got %v want %v", rec.LastActivity, later)
	}

	reg.Delete("guid-1")
	if _, _, ok := reg.Lookup("guid-1"); ok {
		t.Fatalf("Delete did not evict live entry")
	}
	if _, ok, _ := reg.LookupPersisted("guid-1"); ok {
		t.Fatalf("Delete did not evict persisted entry")
	}
}

func TestRegistryEvictIdle(t *testing.T) {
	reg := newRegistry(newMemoryStore())
	t0 := time.Unix(1_000_000_000, 0).UTC()
	reg.now = func() time.Time { return t0 }

	for _, g := range []string{"a", "b", "c"} {
		if err := reg.Put(mkRecord(g), nil); err != nil {
			t.Fatalf("Put %s: %v", g, err)
		}
	}

	// Advance time; touch only "b" so "a" and "c" go idle.
	reg.now = func() time.Time { return t0.Add(90 * time.Minute) }
	reg.Touch("b")

	reg.now = func() time.Time { return t0.Add(3 * time.Hour) }
	evicted := reg.EvictIdle(2 * time.Hour)

	got := map[string]bool{}
	for _, g := range evicted {
		got[g] = true
	}
	if got["b"] {
		t.Fatalf("b should not have been evicted, got %v", evicted)
	}
	if !got["a"] || !got["c"] {
		t.Fatalf("a and c should have been evicted, got %v", evicted)
	}
	if _, _, ok := reg.Lookup("b"); !ok {
		t.Fatalf("b should still be live")
	}
}

func TestRegistryLookupPersistedAfterRestart(t *testing.T) {
	store := newMemoryStore()
	reg := newRegistry(store)
	if err := reg.Put(mkRecord("only-persisted"), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Simulate restart: build a fresh registry that shares the store but has
	// no live entries — connect-side lookups should still find the record.
	fresh := newRegistry(store)
	rec, ok, err := fresh.LookupPersisted("only-persisted")
	if err != nil {
		t.Fatalf("LookupPersisted: %v", err)
	}
	if !ok {
		t.Fatalf("persisted record lost after restart")
	}
	if rec.TargetUser != "alice" {
		t.Fatalf("persisted record corrupted, got %+v", rec)
	}

	// And a live Lookup on the fresh registry should miss (no live conn).
	if _, _, ok := fresh.Lookup("only-persisted"); ok {
		t.Fatalf("Lookup must not return persisted-only records")
	}
}

func TestRegistryConcurrentTouchEvict(t *testing.T) {
	reg := newRegistry(newMemoryStore())
	if err := reg.Put(mkRecord("hot"), nil); err != nil {
		t.Fatalf("Put: %v", err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					reg.Touch("hot")
					_, _, _ = reg.Lookup("hot")
					_ = reg.EvictIdle(time.Nanosecond) // racy but safe
				}
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}
