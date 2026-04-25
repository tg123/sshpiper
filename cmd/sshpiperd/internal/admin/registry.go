// Package admin implements the sshpiperd-side of the SshPiperAdmin gRPC
// service. It owns:
//
//   - a process-wide Registry of live ssh.PiperConn pipes, plus a per-session
//     Broadcaster that fan-outs asciicast frames captured from the upstream
//     terminal channel; and
//
//   - the gRPC Server that exposes ListSessions / KillSession / StreamSession
//     to remote callers (typically the sshpiperd-webadmin aggregator).
//
// The registry is intentionally decoupled from the daemon: the daemon adds
// and removes entries via Add/Remove and routes packet hooks into the
// per-session Broadcaster; the gRPC server only ever reads from the registry.
package admin

import (
	"sync"
	"time"
)

// Session is the public view of a live piped SSH connection.
type Session struct {
	ID             string
	DownstreamUser string
	DownstreamAddr string
	UpstreamUser   string
	UpstreamAddr   string
	StartedAt      time.Time
}

// SessionPipe is the minimal subset of *ssh.PiperConn the registry needs.
// It is an interface to keep this package free of a hard ssh dependency in
// tests, and to let admin code be unit-tested without spinning up a full
// SSH pipe.
type SessionPipe interface {
	Close()
}

// sessionEntry is the registry's internal book-keeping for one session.
type sessionEntry struct {
	info        Session
	pipe        SessionPipe
	broadcaster *Broadcaster
	closeOnce   sync.Once
}

// Registry is a concurrency-safe collection of live sessions.
type Registry struct {
	mu       sync.RWMutex
	sessions map[string]*sessionEntry
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{sessions: make(map[string]*sessionEntry)}
}

// Add registers a new session and returns its broadcaster. The broadcaster
// is owned by the registry and is closed when Remove is called.
func (r *Registry) Add(info Session, pipe SessionPipe) *Broadcaster {
	b := NewBroadcaster()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[info.ID] = &sessionEntry{
		info:        info,
		pipe:        pipe,
		broadcaster: b,
	}
	return b
}

// Remove deletes the session identified by id, closing its broadcaster.
// It is safe to call Remove on an unknown id.
func (r *Registry) Remove(id string) {
	r.mu.Lock()
	entry, ok := r.sessions[id]
	if ok {
		delete(r.sessions, id)
	}
	r.mu.Unlock()
	if ok {
		entry.broadcaster.Close()
	}
}

// List returns a snapshot of all currently registered sessions, sorted by
// start time (oldest first). The returned slice is safe for the caller to
// retain.
func (r *Registry) List() []Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Session, 0, len(r.sessions))
	for _, e := range r.sessions {
		out = append(out, e.info)
	}
	return out
}

// Get returns the session info, broadcaster, and ok=true if the id is
// registered. The returned broadcaster may be subscribed to immediately.
func (r *Registry) Get(id string) (Session, *Broadcaster, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.sessions[id]
	if !ok {
		return Session{}, nil, false
	}
	return entry.info, entry.broadcaster, true
}

// Kill closes the pipe associated with id, which causes the daemon's
// connection goroutine to unwind and Remove the session. The pipe close is
// guarded by sync.Once so concurrent kills (or kill+natural-disconnect)
// are safe. Returns true if the id was found.
func (r *Registry) Kill(id string) bool {
	r.mu.RLock()
	entry, ok := r.sessions[id]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	entry.closeOnce.Do(func() {
		entry.pipe.Close()
	})
	return true
}
