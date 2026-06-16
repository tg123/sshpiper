//go:build full || e2e

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

// fileStore persists each record as <dir>/<guid>.json. Writes are atomic via
// tmpfile+rename. Concurrency is serialised through a single mutex — the v1
// expected load (a handful of registrations) does not warrant per-guid locks.
type fileStore struct {
	mu  sync.Mutex
	dir string
}

// safeGuid allows only alphanumeric characters, hyphens, and underscores
// (max 128 chars). uuid.NewString() emits lowercase hex + dashes which is a
// subset of this pattern. The wider class guards against path traversal if a
// GUID is ever sourced from external input.
var safeGuid = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func newFileStore(dir string) (*fileStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("revtunnel: prepare session-store dir: %w", err)
	}
	return &fileStore{dir: dir}, nil
}

func (s *fileStore) path(guid string) (string, error) {
	if !safeGuid.MatchString(guid) {
		return "", fmt.Errorf("revtunnel: refusing unsafe guid %q", guid)
	}
	return filepath.Join(s.dir, guid+".json"), nil
}

func (s *fileStore) Put(rec record) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.path(rec.Guid)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".revtunnel-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, p); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func (s *fileStore) Get(guid string) (record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.path(guid)
	if err != nil {
		return record{}, false, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return record{}, false, nil
		}
		return record{}, false, err
	}
	var rec record
	if err := json.Unmarshal(data, &rec); err != nil {
		return record{}, false, err
	}
	return rec, true, nil
}

func (s *fileStore) Delete(guid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := s.path(guid)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *fileStore) List() ([]record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	out := make([]record, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, name))
		if err != nil {
			return nil, err
		}
		var rec record
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, nil
}
