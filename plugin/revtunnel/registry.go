//go:build full || e2e

package main

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// record is the persisted half of a tunnel registration. The live ssh.Conn is
// tracked separately in registry.live because it cannot be marshalled.
type record struct {
	Guid              string    `json:"guid"`
	TargetUser        string    `json:"target_user"`
	BindAddr          string    `json:"bind_addr"`
	BindPort          uint32    `json:"bind_port"`
	DownstreamKeyWire []byte    `json:"downstream_key_wire"` // SSH wire format of the registrar's public key — used for connect-side identity check
	UpstreamKeyPEM    []byte    `json:"upstream_key_pem"`    // Internal ed25519 private key for upstream auth to the target
	UpstreamKeyPub    string    `json:"upstream_key_pub"`    // "ssh-ed25519 …" authorized_keys line to install on the target
	CreatedAt         time.Time `json:"created_at"`
	LastActivity      time.Time `json:"last_activity"`
}

// sessionStore persists the non-live fields of record across plugin restarts.
// Implementations must be safe for concurrent use.
type sessionStore interface {
	Put(rec record) error
	Get(guid string) (record, bool, error)
	Delete(guid string) error
	List() ([]record, error)
}

// registry tracks both the persisted records and the live ssh.Conn keyed by
// guid. Live entries are lost on restart; persisted entries survive but become
// inert (their CreateConn lookups fail with errTunnelOffline) until the
// registrar reconnects with the same guid — out of scope for v1, so v1 simply
// returns the error.
type registry struct {
	mu    sync.Mutex
	live  map[string]*liveEntry
	store sessionStore
	now   func() time.Time
}

type liveEntry struct {
	rec  record
	conn ssh.Conn
}

func newRegistry(store sessionStore) *registry {
	return &registry{
		live:  make(map[string]*liveEntry),
		store: store,
		now:   time.Now,
	}
}

// Put records a brand-new tunnel. The registrar's live ssh.Conn is held until
// Delete is called or the sweeper evicts it. The persisted half is written via
// the configured sessionStore.
func (r *registry) Put(rec record, conn ssh.Conn) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.live[rec.Guid]; ok {
		return fmt.Errorf("revtunnel: guid %q already registered", rec.Guid)
	}
	rec.LastActivity = r.now()
	r.live[rec.Guid] = &liveEntry{rec: rec, conn: conn}
	if r.store != nil {
		if err := r.store.Put(rec); err != nil {
			delete(r.live, rec.Guid)
			return err
		}
	}
	return nil
}

// Lookup returns the live entry for the guid, refreshing LastActivity. The
// boolean is false when the guid is unknown or known but not currently live.
func (r *registry) Lookup(guid string) (record, ssh.Conn, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	e, ok := r.live[guid]
	if !ok {
		return record{}, nil, false
	}
	e.rec.LastActivity = r.now()
	if r.store != nil {
		_ = r.store.Put(e.rec)
	}
	return e.rec, e.conn, true
}

// LookupPersisted returns the persisted record for the guid even when no live
// conn is bound — useful for distinguishing "unknown guid" from "tunnel
// offline" in the connect path.
func (r *registry) LookupPersisted(guid string) (record, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if e, ok := r.live[guid]; ok {
		return e.rec, true, nil
	}
	if r.store == nil {
		return record{}, false, nil
	}
	return r.store.Get(guid)
}

// Touch bumps LastActivity for a live entry. No-op when the guid is not live.
func (r *registry) Touch(guid string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	e, ok := r.live[guid]
	if !ok {
		return
	}
	e.rec.LastActivity = r.now()
	if r.store != nil {
		_ = r.store.Put(e.rec)
	}
}

// Delete tears down the live entry (closing the registrar conn if present)
// and removes the persisted record.
func (r *registry) Delete(guid string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if e, ok := r.live[guid]; ok {
		if e.conn != nil {
			_ = e.conn.Close()
		}
		delete(r.live, guid)
	}
	if r.store != nil {
		_ = r.store.Delete(guid)
	}
}

// EvictIdle deletes every live entry whose LastActivity is older than now-idle.
// Returns the guids that were evicted.
func (r *registry) EvictIdle(idle time.Duration) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := r.now().Add(-idle)
	var evicted []string
	for guid, e := range r.live {
		if e.rec.LastActivity.Before(cutoff) {
			if e.conn != nil {
				_ = e.conn.Close()
			}
			delete(r.live, guid)
			if r.store != nil {
				_ = r.store.Delete(guid)
			}
			evicted = append(evicted, guid)
		}
	}
	return evicted
}
