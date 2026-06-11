package admin

import (
	"sync/atomic"
	"testing"
	"time"
)

type fakePipe struct{ closed atomic.Int32 }

func (f *fakePipe) Close() { f.closed.Add(1) }

func TestRegistry_AddListGetRemove(t *testing.T) {
	r := NewRegistry()
	if got := r.List(); len(got) != 0 {
		t.Fatalf("expected empty registry, got %d entries", len(got))
	}
	pipe := &fakePipe{}
	bc := r.Add(Session{ID: "abc", DownstreamUser: "alice", StartedAt: time.Now()}, pipe)
	if bc == nil {
		t.Fatal("Add returned nil broadcaster")
	}
	if got := r.List(); len(got) != 1 || got[0].ID != "abc" {
		t.Fatalf("List = %+v", got)
	}
	if _, _, ok := r.Get("missing"); ok {
		t.Fatal("Get should report ok=false for unknown id")
	}
	if info, gotBC, ok := r.Get("abc"); !ok || info.DownstreamUser != "alice" || gotBC != bc {
		t.Fatalf("Get returned info=%+v bc=%v ok=%v", info, gotBC, ok)
	}
	r.Remove("abc")
	if got := r.List(); len(got) != 0 {
		t.Fatalf("expected empty after remove, got %d", len(got))
	}
}

func TestRegistry_KillCallsCloseOnce(t *testing.T) {
	r := NewRegistry()
	pipe := &fakePipe{}
	r.Add(Session{ID: "k1"}, pipe)

	if !r.Kill("k1") {
		t.Fatal("Kill should return true for known id")
	}
	if r.Kill("k1") != true {
		// Still registered (daemon goroutine hasn't called Remove yet),
		// so a second Kill is allowed but the underlying Close must not
		// be invoked twice.
		t.Fatal("Kill should still succeed before Remove")
	}
	if got := pipe.closed.Load(); got != 1 {
		t.Fatalf("Close called %d times, want 1", got)
	}
	if r.Kill("missing") {
		t.Fatal("Kill should return false for unknown id")
	}
}

func TestRegistry_RemoveClosesBroadcaster(t *testing.T) {
	r := NewRegistry()
	bc := r.Add(Session{ID: "x"}, &fakePipe{})
	ch, cancel := bc.Subscribe(true)
	defer cancel()
	r.Remove("x")
	select {
	case _, open := <-ch:
		if open {
			t.Fatal("subscriber channel should be closed after Remove")
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber channel did not close after Remove")
	}
}

func TestRegistry_ListIsSortedByStartedAt(t *testing.T) {
	r := NewRegistry()
	t0 := time.Unix(1_700_000_000, 0)
	r.Add(Session{ID: "c", StartedAt: t0.Add(2 * time.Second)}, &fakePipe{})
	r.Add(Session{ID: "a", StartedAt: t0}, &fakePipe{})
	r.Add(Session{ID: "b", StartedAt: t0.Add(time.Second)}, &fakePipe{})

	out := r.List()
	if len(out) != 3 {
		t.Fatalf("len(List) = %d, want 3", len(out))
	}
	if out[0].ID != "a" || out[1].ID != "b" || out[2].ID != "c" {
		t.Fatalf("List = %+v, want sorted oldest-first a,b,c", out)
	}
}
