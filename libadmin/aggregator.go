package libadmin

import (
	"context"
	"fmt"
	"io"
	"sync"
)

// AggregatedSession is one session as seen by the aggregator: it carries
// the underlying Session plus the InstanceID of the sshpiperd it lives on.
// The InstanceID is what the aggregator uses to route subsequent kill /
// stream calls back to the correct backend.
type AggregatedSession struct {
	InstanceID   string
	InstanceAddr string
	Session      *Session
}

// AggregatorError represents a per-instance failure during a fan-out call.
// It implements the error interface so that bulk operations can surface
// partial failures without losing per-instance attribution.
type AggregatorError struct {
	InstanceID   string
	InstanceAddr string
	Err          error
}

func (e *AggregatorError) Error() string {
	return fmt.Sprintf("admin instance %s (%s): %v", e.InstanceID, e.InstanceAddr, e.Err)
}

func (e *AggregatorError) Unwrap() error { return e.Err }

// Aggregator multiplexes admin operations across N sshpiperd instances
// returned by a Discovery. It maintains a per-address Client cache and
// refreshes it whenever Discovery returns a new set of endpoints.
//
// All exported methods are safe for concurrent use.
type Aggregator struct {
	discovery Discovery
	dialOpts  DialOptions

	mu      sync.Mutex
	clients map[string]*Client          // keyed by instance address
	infos   map[string]*ServerInfoCache // keyed by instance address
}

// ServerInfoCache stores a recent ServerInfo response together with the
// address it was fetched from. The aggregator uses ServerInfo.Id as the
// stable instance identifier so that operators can refer to instances by
// name rather than by transient network addresses.
type ServerInfoCache struct {
	Addr string
	Info *ServerInfoResponse
}

// NewAggregator returns an Aggregator backed by discovery. dialOpts is used
// for every backend Client opened by the aggregator.
func NewAggregator(discovery Discovery, dialOpts DialOptions) *Aggregator {
	return &Aggregator{
		discovery: discovery,
		dialOpts:  dialOpts,
		clients:   make(map[string]*Client),
		infos:     make(map[string]*ServerInfoCache),
	}
}

// Close releases all cached gRPC connections.
func (a *Aggregator) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	var firstErr error
	for addr, c := range a.clients {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		delete(a.clients, addr)
	}
	a.infos = make(map[string]*ServerInfoCache)
	return firstErr
}

// Refresh re-resolves the set of endpoints from Discovery, opening clients
// for any new ones and closing clients for any that have disappeared. The
// returned map is keyed by instance ID and contains every backend currently
// reachable; partial failures are reported as AggregatorErrors but do not
// stop the refresh.
func (a *Aggregator) Refresh(ctx context.Context) (map[string]*ServerInfoCache, []error) {
	addrs, err := a.discovery.Endpoints(ctx)
	if err != nil {
		return nil, []error{fmt.Errorf("discovery: %w", err)}
	}

	wanted := make(map[string]struct{}, len(addrs))
	for _, addr := range addrs {
		wanted[addr] = struct{}{}
	}

	a.mu.Lock()
	// Close clients that are no longer wanted.
	for addr, c := range a.clients {
		if _, ok := wanted[addr]; !ok {
			_ = c.Close()
			delete(a.clients, addr)
			delete(a.infos, addr)
		}
	}
	// Dial any new endpoints.
	toQuery := make([]*Client, 0, len(addrs))
	var errs []error
	for _, addr := range addrs {
		if _, ok := a.clients[addr]; ok {
			toQuery = append(toQuery, a.clients[addr])
			continue
		}
		c, err := NewClient(addr, a.dialOpts)
		if err != nil {
			errs = append(errs, &AggregatorError{InstanceAddr: addr, Err: err})
			continue
		}
		a.clients[addr] = c
		toQuery = append(toQuery, c)
	}
	a.mu.Unlock()

	// Refresh ServerInfo for all live clients in parallel.
	var (
		wg         sync.WaitGroup
		infoMu     sync.Mutex
		infoErrors []error
		infoMap    = make(map[string]*ServerInfoCache)
	)
	for _, c := range toQuery {
		wg.Add(1)
		go func(c *Client) {
			defer wg.Done()
			info, err := c.ServerInfo(ctx)
			if err != nil {
				infoMu.Lock()
				infoErrors = append(infoErrors, &AggregatorError{InstanceAddr: c.Addr, Err: err})
				infoMu.Unlock()
				return
			}
			cache := &ServerInfoCache{Addr: c.Addr, Info: info}
			infoMu.Lock()
			infoMap[info.GetId()] = cache
			infoMu.Unlock()
		}(c)
	}
	wg.Wait()

	a.mu.Lock()
	a.infos = make(map[string]*ServerInfoCache, len(infoMap))
	for id, c := range infoMap {
		a.infos[id] = c
	}
	a.mu.Unlock()

	return infoMap, append(errs, infoErrors...)
}

// Instances returns a snapshot of the currently-known instances, keyed by
// instance ID. Refresh must have been called at least once.
func (a *Aggregator) Instances() map[string]*ServerInfoCache {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]*ServerInfoCache, len(a.infos))
	for k, v := range a.infos {
		out[k] = v
	}
	return out
}

// ClientFor returns the Client for the given instance ID, or nil if the
// instance is not currently known.
func (a *Aggregator) ClientFor(instanceID string) *Client {
	a.mu.Lock()
	defer a.mu.Unlock()
	cache, ok := a.infos[instanceID]
	if !ok {
		return nil
	}
	return a.clients[cache.Addr]
}

// ListAllSessions queries every backend in parallel and returns the
// combined session list. Per-instance failures are returned as the second
// value but do not abort the call.
func (a *Aggregator) ListAllSessions(ctx context.Context) ([]AggregatedSession, []error) {
	a.mu.Lock()
	type job struct {
		id   string
		addr string
		c    *Client
	}
	jobs := make([]job, 0, len(a.infos))
	for id, cache := range a.infos {
		jobs = append(jobs, job{id: id, addr: cache.Addr, c: a.clients[cache.Addr]})
	}
	a.mu.Unlock()

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		out  []AggregatedSession
		errs []error
	)
	for _, j := range jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			sessions, err := j.c.ListSessions(ctx)
			if err != nil {
				mu.Lock()
				errs = append(errs, &AggregatorError{InstanceID: j.id, InstanceAddr: j.addr, Err: err})
				mu.Unlock()
				return
			}
			local := make([]AggregatedSession, 0, len(sessions))
			for _, s := range sessions {
				local = append(local, AggregatedSession{InstanceID: j.id, InstanceAddr: j.addr, Session: s})
			}
			mu.Lock()
			out = append(out, local...)
			mu.Unlock()
		}(j)
	}
	wg.Wait()

	return out, errs
}

// KillSession routes a kill request to the named instance.
func (a *Aggregator) KillSession(ctx context.Context, instanceID, sessionID string) (bool, error) {
	c := a.ClientFor(instanceID)
	if c == nil {
		return false, fmt.Errorf("unknown admin instance %q", instanceID)
	}
	return c.KillSession(ctx, sessionID)
}

// StreamSession opens a server-streaming RPC against the named instance
// and forwards frames to handler until either the stream ends, the context
// is cancelled, or handler returns an error.
func (a *Aggregator) StreamSession(ctx context.Context, instanceID, sessionID string, replay bool, handler func(*SessionFrame) error) error {
	c := a.ClientFor(instanceID)
	if c == nil {
		return fmt.Errorf("unknown admin instance %q", instanceID)
	}

	stream, err := c.RPC().StreamSession(ctx, &StreamSessionRequest{Id: sessionID, Replay: replay})
	if err != nil {
		return err
	}
	for {
		frame, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := handler(frame); err != nil {
			return err
		}
	}
}
