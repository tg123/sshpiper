//go:build full || e2e

package main

import "sync"

// memoryStore is the default sessionStore implementation. It keeps every
// record in process memory; everything is lost on restart.
type memoryStore struct {
	mu      sync.Mutex
	records map[string]record
}

func newMemoryStore() *memoryStore {
	return &memoryStore{records: make(map[string]record)}
}

func (s *memoryStore) Put(rec record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[rec.Guid] = rec
	return nil
}

func (s *memoryStore) Get(guid string) (record, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[guid]
	return r, ok, nil
}

func (s *memoryStore) Delete(guid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, guid)
	return nil
}

func (s *memoryStore) List() ([]record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]record, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	return out, nil
}
