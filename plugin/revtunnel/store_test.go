//go:build full || e2e

package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestMemoryStoreRoundtrip(t *testing.T) {
	s := newMemoryStore()
	rec := mkRecord("g1")
	rec.LastActivity = time.Unix(123, 0).UTC()
	if err := s.Put(rec); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Get("g1")
	if err != nil || !ok {
		t.Fatalf("Get: ok=%v err=%v", ok, err)
	}
	if got.TargetUser != rec.TargetUser || !got.LastActivity.Equal(rec.LastActivity) {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", got, rec)
	}
	all, err := s.List()
	if err != nil || len(all) != 1 {
		t.Fatalf("List: %v err=%v", all, err)
	}
	if err := s.Delete("g1"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get("g1"); ok {
		t.Fatal("Delete did not remove record")
	}
}

func TestFileStoreRoundtripAndReload(t *testing.T) {
	dir := t.TempDir()
	s, err := newFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	rec := mkRecord("guid-abc")
	rec.LastActivity = time.Unix(42, 0).UTC()
	if err := s.Put(rec); err != nil {
		t.Fatal(err)
	}

	// New store instance pointed at the same dir must see the record.
	fresh, err := newFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := fresh.Get("guid-abc")
	if err != nil || !ok {
		t.Fatalf("Get on fresh store: ok=%v err=%v", ok, err)
	}
	if got.TargetUser != rec.TargetUser || got.BindPort != rec.BindPort {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", got, rec)
	}
	list, err := fresh.List()
	if err != nil || len(list) != 1 {
		t.Fatalf("List: %v err=%v", list, err)
	}

	if err := fresh.Delete("guid-abc"); err != nil {
		t.Fatal(err)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(matches) != 0 {
		t.Fatalf("Delete left files: %v", matches)
	}
	// Delete of missing record is a no-op.
	if err := fresh.Delete("guid-abc"); err != nil {
		t.Fatalf("idempotent Delete: %v", err)
	}
}

func TestFileStoreRejectsUnsafeGuid(t *testing.T) {
	dir := t.TempDir()
	s, _ := newFileStore(dir)
	for _, bad := range []string{"../escape", "", "with/slash", "dot.dot"} {
		if err := s.Put(record{Guid: bad}); err == nil {
			t.Fatalf("expected error for guid %q", bad)
		}
	}
}

func TestOpenSessionStore(t *testing.T) {
	for _, spec := range []string{"", "memory", "memory://"} {
		s, err := openSessionStore(spec)
		if err != nil {
			t.Fatalf("openSessionStore(%q): %v", spec, err)
		}
		if _, ok := s.(*memoryStore); !ok {
			t.Fatalf("openSessionStore(%q) -> %T want *memoryStore", spec, s)
		}
	}

	dir := t.TempDir()
	s, err := openSessionStore("file://" + dir)
	if err != nil {
		t.Fatalf("file scheme: %v", err)
	}
	if _, ok := s.(*fileStore); !ok {
		t.Fatalf("got %T want *fileStore", s)
	}

	if _, err := openSessionStore("redis://foo"); err == nil {
		t.Fatal("expected unsupported-scheme error")
	}
	if _, err := openSessionStore("file://"); err == nil {
		t.Fatal("expected missing-path error")
	}
}
