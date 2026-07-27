//go:build full || e2e

package main

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// record is the persisted half of a tunnel registration. The live ssh.Conn is
// tracked separately in registry.live because it cannot be marshalled.
type record struct {
	Guid             string    `json:"guid"`
	TargetUser       string    `json:"target_user"`
	BindAddr         string    `json:"bind_addr"`
	BindPort         uint32    `json:"bind_port"`
	ConnectorKeyWire []byte    `json:"connector_key_wire"` // SSH wire format of the issued connector public key — used for connect-side authentication
	UpstreamKeyPEM   []byte    `json:"upstream_key_pem"`   // Internal ed25519 private key for upstream auth to the target
	UpstreamKeyPub   string    `json:"upstream_key_pub"`   // "ssh-ed25519 …" authorized_keys line to install on the target
	AllowPassword    bool      `json:"allow_password"`     // connect-side password auth is accepted (registrar sent ALLOWPASSWORD)
	CreatedAt        time.Time `json:"created_at"`
	LastActivity     time.Time `json:"last_activity"`
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
	mu       sync.Mutex
	live     map[string]*liveEntry
	channels map[string]map[*channelConn]struct{}
	store    sessionStore
	now      func() time.Time
	maxTotal int // global active-tunnel cap enforced atomically in Put (0 = unlimited)
}

type liveEntry struct {
	rec  record
	conn ssh.Conn
}

func newRegistry(store sessionStore) *registry {
	return &registry{
		live:     make(map[string]*liveEntry),
		channels: make(map[string]map[*channelConn]struct{}),
		store:    store,
		now:      time.Now,
	}
}

func (r *registry) TrackChannel(guid string, conn *channelConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.channels[guid] == nil {
		r.channels[guid] = make(map[*channelConn]struct{})
	}
	r.channels[guid][conn] = struct{}{}
}

func (r *registry) UntrackChannel(guid string, conn *channelConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.channels[guid], conn)
	if len(r.channels[guid]) == 0 {
		delete(r.channels, guid)
	}
}

func (r *registry) takeChannelsLocked(guid string) []*channelConn {
	tracked := r.channels[guid]
	delete(r.channels, guid)
	channels := make([]*channelConn, 0, len(tracked))
	for conn := range tracked {
		channels = append(channels, conn)
	}
	return channels
}

// errTooManyTunnels is returned by Put when the global active-tunnel cap is
// reached; the check and the insert share one lock so the bound holds under
// concurrent registrations.
var errTooManyTunnels = fmt.Errorf("revtunnel: global tunnel limit reached")

// Count returns the number of live tunnels.
func (r *registry) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.live)
}

// IsLive reports whether a guid currently has a live entry.
func (r *registry) IsLive(guid string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.live[guid]
	return ok
}

// Put records a brand-new tunnel. The registrar's live ssh.Conn is held until
// Delete is called or the sweeper evicts it. The persisted half is written via
// the configured sessionStore. The global cap is enforced under the same lock
// as the insert, so concurrent registrations cannot race past maxTotal.
func (r *registry) Put(rec record, conn ssh.Conn) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.maxTotal > 0 && len(r.live) >= r.maxTotal {
		return errTooManyTunnels
	}
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

// Lookup returns the live entry for the guid without mutating LastActivity.
// Callers that represent genuine, authenticated activity must call Touch
// explicitly, so that unauthenticated probes (e.g. connect attempts with a
// wrong key) cannot reset the idle timer. The boolean is false when the guid
// is unknown or known but not currently live.
func (r *registry) Lookup(guid string) (record, ssh.Conn, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	e, ok := r.live[guid]
	if !ok {
		return record{}, nil, false
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
// LastActivity is kept in-memory only; it is not persisted on every touch to
// avoid excessive I/O on file-backed stores.
func (r *registry) Touch(guid string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	e, ok := r.live[guid]
	if !ok {
		return
	}
	e.rec.LastActivity = r.now()
}

// Delete removes the live entry and the persisted record for guid. The
// registrar connection is closed only when no sibling forward on the same
// connection remains live, since several guids can share one ssh.Conn.
func (r *registry) Delete(guid string) {
	r.mu.Lock()
	e, ok := r.live[guid]
	if ok {
		delete(r.live, guid)
	}
	channels := r.takeChannelsLocked(guid)
	if r.store != nil {
		_ = r.store.Delete(guid)
	}
	closeConn := false
	if ok && e.conn != nil {
		closeConn = true
		for _, other := range r.live {
			if other.conn == e.conn {
				closeConn = false
				break
			}
		}
	}
	r.mu.Unlock()

	for _, channel := range channels {
		_ = channel.closeFromRegistry()
	}
	if closeConn {
		_ = e.conn.Close()
	}
}

// UpdateConnectorKeyWire atomically replaces the ConnectorKeyWire for a live
// entry. It also persists the updated record if a store is configured. Returns
// false when the guid is not currently live.
func (r *registry) UpdateConnectorKeyWire(guid string, key []byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	e, ok := r.live[guid]
	if !ok {
		return false
	}
	// Persist a copy first; only swap the live record in after the store
	// accepts it, so a failed Put leaves both halves on the old key.
	updated := e.rec
	updated.ConnectorKeyWire = key
	if r.store != nil {
		if err := r.store.Put(updated); err != nil {
			return false
		}
	}
	e.rec = updated
	return true
}

// UpdateAllowPassword atomically toggles connect-side password auth for a live
// entry, persisting the change first (see UpdateConnectorKeyWire). Returns
// false when the guid is not currently live.
func (r *registry) UpdateAllowPassword(guid string, allow bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	e, ok := r.live[guid]
	if !ok {
		return false
	}
	if e.rec.AllowPassword == allow {
		return true
	}
	updated := e.rec
	updated.AllowPassword = allow
	if r.store != nil {
		if err := r.store.Put(updated); err != nil {
			return false
		}
	}
	e.rec = updated
	return true
}

// Remove deletes a tunnel record (live + persisted). A shared registrar
// connection remains open while sibling forwards still reference it, but is
// closed when its final forward is removed so zero-forward sessions cannot
// retain transports/goroutines/file descriptors indefinitely.
func (r *registry) Remove(guid string) {
	r.mu.Lock()
	e, ok := r.live[guid]
	delete(r.live, guid)
	channels := r.takeChannelsLocked(guid)
	if r.store != nil {
		_ = r.store.Delete(guid)
	}
	closeConn := false
	if ok && e.conn != nil {
		closeConn = true
		for _, other := range r.live {
			if other.conn == e.conn {
				closeConn = false
				break
			}
		}
	}
	r.mu.Unlock()

	for _, channel := range channels {
		_ = channel.closeFromRegistry()
	}
	if closeConn {
		_ = e.conn.Close()
	}
}

// EvictIdle deletes every live entry whose LastActivity is older than now-idle.
// Returns the guids that were evicted.
func (r *registry) EvictIdle(idle time.Duration) []string {
	r.mu.Lock()

	cutoff := r.now().Add(-idle)
	var evicted []string
	var idleConns []ssh.Conn
	var idleChannels []*channelConn
	for guid, e := range r.live {
		if e.rec.LastActivity.Before(cutoff) {
			idleConns = append(idleConns, e.conn)
			idleChannels = append(idleChannels, r.takeChannelsLocked(guid)...)
			delete(r.live, guid)
			if r.store != nil {
				_ = r.store.Delete(guid)
			}
			evicted = append(evicted, guid)
		}
	}
	// Close a registrar connection only once none of its forwards remain live;
	// several guids can share one ssh.Conn and a busy sibling must not be
	// dropped just because another forward went idle. Deduplicate first so a
	// shared connection is closed at most once.
	closeConns := make(map[ssh.Conn]bool)
	for _, conn := range idleConns {
		if conn == nil || closeConns[conn] {
			continue
		}
		closeConns[conn] = true
		stillUsed := false
		for _, e := range r.live {
			if e.conn == conn {
				stillUsed = true
				break
			}
		}
		if stillUsed {
			delete(closeConns, conn)
		}
	}
	// Also expire persisted-only records left by an unclean restart or failed
	// connection cleanup. They are never present in r.live, but still contain
	// upstream private keys and otherwise accumulate forever on file stores.
	if r.store != nil {
		records, err := r.store.List()
		if err != nil {
			slog.Warn("revtunnel: list persisted records for idle eviction", "error", err)
		} else {
			for _, rec := range records {
				if _, live := r.live[rec.Guid]; live {
					continue
				}
				if rec.LastActivity.Before(cutoff) {
					if err := r.store.Delete(rec.Guid); err != nil {
						slog.Warn("revtunnel: delete expired persisted record", "guid", rec.Guid, "error", err)
						continue
					}
					evicted = append(evicted, rec.Guid)
				}
			}
		}
	}
	r.mu.Unlock()

	for _, channel := range idleChannels {
		_ = channel.closeFromRegistry()
	}
	for conn := range closeConns {
		_ = conn.Close()
	}
	return evicted
}
