//go:build full || e2e

package main

import (
	"context"
	"net/netip"
	"sync"
	"time"

	gocache "github.com/patrickmn/go-cache"
)

// store keeps per-ip auth failure counters.
//
// Implementations must be safe for concurrent use. The failure window starts
// with the first recorded failure of an ip and lasts for the configured ttl.
type store interface {
	// Failures returns the current failure count of ip, 0 if unknown.
	Failures(ctx context.Context, ip netip.Addr) (int, error)
	// Incr atomically increments the failure count of ip and returns the new
	// value. The expiry is set when the counter is created.
	Incr(ctx context.Context, ip netip.Addr) (int, error)
	// Reset removes all failure counters.
	Reset(ctx context.Context) error
}

// ipKey returns the canonical string form of ip used as store key.
// IPv4-mapped IPv6 addresses are unmapped and zones are dropped, so that the
// same client cannot be tracked under multiple keys.
func ipKey(ip netip.Addr) string {
	return ip.WithZone("").Unmap().String()
}

// memoryStore is a process local store, the default.
type memoryStore struct {
	mu    sync.Mutex
	cache *gocache.Cache
	ttl   time.Duration
}

func newMemoryStore(ttl time.Duration) *memoryStore {
	return &memoryStore{
		cache: gocache.New(ttl, ttl/2*3),
		ttl:   ttl,
	}
}

func (m *memoryStore) Failures(_ context.Context, ip netip.Addr) (int, error) {
	v, found := m.cache.Get(ipKey(ip))
	if !found {
		return 0, nil
	}

	return v.(int), nil
}

func (m *memoryStore) Incr(_ context.Context, ip netip.Addr) (int, error) {
	key := ipKey(ip)

	m.mu.Lock()
	defer m.mu.Unlock()

	// IncrementInt keeps the original expiration of the entry
	n, err := m.cache.IncrementInt(key, 1)
	if err == nil {
		return n, nil
	}

	// not found or expired, start a new window
	m.cache.Set(key, 1, m.ttl)
	return 1, nil
}

func (m *memoryStore) Reset(_ context.Context) error {
	m.cache.Flush()
	return nil
}
