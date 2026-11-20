//go:build full || e2e

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	gocache "github.com/patrickmn/go-cache"
	"go4.org/netipx"
)

const (
	storeFailureModeLocal = "local"
	storeFailureModeDeny  = "deny"

	// how long a ban seen in a remote store is remembered locally, to avoid a
	// store round trip for every connection of an already banned ip
	defaultBanCacheTTL = 5 * time.Second

	storeWarnInterval = 10 * time.Second

	// how long a connection that reached the ssh auth stage is tracked, must
	// exceed sshpiperd --login-grace-time (default 30s)
	connTrackTTL = 10 * time.Minute
	resetTimeout = 30 * time.Second
)

var errStoreUnavailable = errors.New("failtoban: failure store unavailable, rejecting connection")

type jail struct {
	maxFailures int
	logOnly     bool
	whitelist   *netipx.IPSet
	// denylist is always rejected, regardless of failures, whitelist or
	// log-only mode
	denylist *netipx.IPSet

	// primary is the store holding the failure counters
	primary store
	// fallback is used when primary fails, nil means deny on store errors
	// (or primary is already local)
	fallback store
	// denyOnStoreError rejects new connections if the primary store fails
	denyOnStoreError bool

	// banCache remembers recently seen bans locally, nil if primary is local
	banCache    *gocache.Cache
	banCacheTTL time.Duration

	// conns tracks connections (remote ip:port) accepted by check on this
	// instance. Pipe create failures of other connections (e.g. tcp health
	// checks, port scans, already rejected connections) are not counted.
	conns *gocache.Cache

	lastStoreWarn atomic.Int64
}

func newConnTracker() *gocache.Cache {
	return gocache.New(connTrackTTL, connTrackTTL/2)
}

func newLocalJail(maxFailures int, banDuration time.Duration, logOnly bool, whitelist, denylist *netipx.IPSet) *jail {
	return &jail{
		maxFailures: maxFailures,
		logOnly:     logOnly,
		whitelist:   whitelist,
		denylist:    denylist,
		primary:     newMemoryStore(banDuration),
		conns:       newConnTracker(),
	}
}

func newSharedJail(maxFailures int, banDuration time.Duration, logOnly bool, whitelist, denylist *netipx.IPSet, shared store, failureMode string) (*jail, error) {
	j := &jail{
		maxFailures: maxFailures,
		logOnly:     logOnly,
		whitelist:   whitelist,
		denylist:    denylist,
		primary:     shared,
		banCacheTTL: min(defaultBanCacheTTL, banDuration),
		conns:       newConnTracker(),
	}

	j.banCache = gocache.New(j.banCacheTTL, j.banCacheTTL*2)

	switch failureMode {
	case storeFailureModeLocal:
		j.fallback = newMemoryStore(banDuration)
	case storeFailureModeDeny:
		j.denyOnStoreError = true
	default:
		return nil, fmt.Errorf("failtoban: unknown store failure mode %q, must be %q or %q", failureMode, storeFailureModeLocal, storeFailureModeDeny)
	}

	return j, nil
}

func parseRemoteIP(remoteAddr string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}

	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, err
	}

	return ip.WithZone("").Unmap(), nil
}

// check returns an error if the remote address must not connect.
func (j *jail) check(ctx context.Context, remoteAddr string) error {
	ip, err := parseRemoteIP(remoteAddr)
	if err != nil {
		if j.logOnly {
			return nil
		}

		// fail closed, every connection must be attributable to an ip
		slog.Warn("failtoban cannot parse remote address, rejecting", "remote_addr", remoteAddr, "error", err)
		return fmt.Errorf("failtoban: cannot parse remote address %q", remoteAddr)
	}

	// permanent deny list: wins over whitelist and log-only mode, checked
	// before any store lookup, denied connections are neither tracked nor
	// counted
	if j.denylist != nil && j.denylist.Contains(ip) {
		slog.Debug("failtoban ip is permanently denied", "ip", ip)
		return deniedError(ip)
	}

	if j.logOnly {
		j.track(remoteAddr)
		return nil
	}

	if j.whitelist != nil && j.whitelist.Contains(ip) {
		slog.Debug("failtoban whitelist ignored", "ip", ip)
		return nil
	}

	if j.banCache != nil {
		if _, banned := j.banCache.Get(ipKey(ip)); banned {
			return bannedError(ip)
		}
	}

	failed, err := j.primary.Failures(ctx, ip)
	if err != nil {
		j.warnStore("failtoban failure store lookup failed", ip, err)

		if j.denyOnStoreError {
			return errStoreUnavailable
		}
	}

	// bans collected locally while the primary store was unavailable stay
	// effective after it recovers
	if j.fallback != nil {
		if local, _ := j.fallback.Failures(ctx, ip); local > failed {
			failed = local
		}
	}

	if failed >= j.maxFailures {
		j.rememberBan(ip)
		return bannedError(ip)
	}

	j.track(remoteAddr)
	return nil
}

// track marks an accepted connection, its pipe create failure counts from now
// on. Connections rejected by check are not tracked: counting them again adds
// no information but costs a store write per connection of a banned flood.
func (j *jail) track(remoteAddr string) {
	j.conns.Set(remoteAddr, struct{}{}, gocache.DefaultExpiration)
}

// recordFailure counts one failure of remoteAddr.
func (j *jail) recordFailure(ctx context.Context, remoteAddr string, msg string, attrs ...any) {
	ip, err := parseRemoteIP(remoteAddr)
	if err != nil {
		slog.Warn("failtoban cannot parse remote address", "remote_addr", remoteAddr, "error", err)
		return
	}

	if j.whitelist != nil && j.whitelist.Contains(ip) {
		slog.Debug("failtoban whitelist ignored", "ip", ip)
		return
	}

	failed, err := j.primary.Incr(ctx, ip)
	if err != nil {
		j.warnStore("failtoban failure store increment failed", ip, err)

		if j.fallback == nil {
			slog.Error("failtoban failure not recorded", "ip", ip, "error", err)
			return
		}

		failed, _ = j.fallback.Incr(ctx, ip)
	}

	if failed >= j.maxFailures {
		j.rememberBan(ip)
	}

	attrs = append([]any{"ip", ip, "fail_count", failed, "max_failures", j.maxFailures}, attrs...)
	slog.Warn(msg, attrs...)
}

// recordPipeCreateFailure counts a failed pipe creation, but only for
// connections accepted by check, i.e. that reached the ssh auth stage.
// Connections failing earlier (tcp health checks of load balancers or kubelet,
// port scans, ...) are not counted, otherwise the source ip of health checks
// gets banned. Connections rejected by check are not counted either.
func (j *jail) recordPipeCreateFailure(ctx context.Context, remoteAddr string, reason error) {
	if _, tracked := j.conns.Get(remoteAddr); !tracked {
		slog.Debug("failtoban pipe create failed, connection not tracked, not counted", "remote_addr", remoteAddr, "reason", reason)
		return
	}

	j.conns.Delete(remoteAddr)
	j.recordFailure(ctx, remoteAddr, "failtoban pipe create failed", "reason", reason)
}

// reset clears all failure counters, including the shared ones.
func (j *jail) reset() {
	if j.banCache != nil {
		j.banCache.Flush()
	}

	if j.fallback != nil {
		_ = j.fallback.Reset(context.Background())
	}

	ctx, cancel := context.WithTimeout(context.Background(), resetTimeout)
	defer cancel()

	if err := j.primary.Reset(ctx); err != nil {
		slog.Error("failtoban failed to reset failure store", "error", err)
		return
	}

	slog.Info("failtoban cache reset due to SIGHUP")
}

func (j *jail) rememberBan(ip netip.Addr) {
	if j.banCache != nil {
		j.banCache.Set(ipKey(ip), true, j.banCacheTTL)
	}
}

// warnStore logs store errors, rate limited to avoid log flooding by attackers
// while the store is down.
func (j *jail) warnStore(msg string, ip netip.Addr, err error) {
	now := time.Now().UnixNano()
	last := j.lastStoreWarn.Load()

	if now-last >= int64(storeWarnInterval) && j.lastStoreWarn.CompareAndSwap(last, now) {
		slog.Warn(msg, "ip", ip, "error", err, "deny_on_store_error", j.denyOnStoreError)
		return
	}

	slog.Debug(msg, "ip", ip, "error", err)
}

func deniedError(ip netip.Addr) error {
	return fmt.Errorf("failtoban: ip %v is permanently denied", ip)
}

func bannedError(ip netip.Addr) error {
	return fmt.Errorf("failtoban: ip %v too many auth failures", ip)
}
