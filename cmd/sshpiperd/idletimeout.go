package main

import (
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSH message numbers we consider "user activity". Only channel data packets
// count: keepalives, window adjustments, etc. are intentionally ignored so
// that an SSH client (or sshd) sending periodic keepalives does not defeat
// inactivity detection. See RFC 4254.
const (
	idleMsgChannelData         = 94
	idleMsgChannelExtendedData = 95
)

// idleTracker watches packets flowing through a ssh.PiperConn and triggers a
// callback when no channel data has been observed (in either direction) for
// longer than the configured timeout.
//
// A zero or negative timeout disables the tracker; newIdleTracker returns nil
// in that case so callers can write `if t := newIdleTracker(d); t != nil { ... }`.
type idleTracker struct {
	timeout  time.Duration
	lastNano atomic.Int64 // most recent channel-data activity, time.UnixNano()
	stopCh   chan struct{}
	stopOnce sync.Once
}

// newIdleTracker returns a tracker with the given idle timeout, or nil when
// timeout <= 0 (idle timeout disabled).
func newIdleTracker(timeout time.Duration) *idleTracker {
	if timeout <= 0 {
		return nil
	}
	t := &idleTracker{
		timeout: timeout,
		stopCh:  make(chan struct{}),
	}
	t.lastNano.Store(time.Now().UnixNano())
	return t
}

// hook returns a ssh.PipePacketHook that records channel data activity. The
// hook never modifies the packet and never returns an error.
func (t *idleTracker) hook() ssh.PipePacketHook {
	return func(packet []byte) (ssh.PipePacketHookMethod, []byte, error) {
		if len(packet) > 0 {
			switch packet[0] {
			case idleMsgChannelData, idleMsgChannelExtendedData:
				t.lastNano.Store(time.Now().UnixNano())
			}
		}
		return ssh.PipePacketHookTransform, packet, nil
	}
}

// idle reports whether the tracker has not seen any channel-data activity
// within its timeout window relative to now.
func (t *idleTracker) idle(now time.Time) bool {
	last := time.Unix(0, t.lastNano.Load())
	return now.Sub(last) >= t.timeout
}

// run starts a goroutine that invokes onTimeout the first time the connection
// has been idle for the configured timeout. The goroutine exits when stop()
// is called or when onTimeout has fired. Must be called at most once.
func (t *idleTracker) run(onTimeout func()) {
	// Sample roughly four times per timeout window with a 1s floor so we
	// neither busy-poll for very long timeouts nor lag for short ones.
	interval := t.timeout / 4
	if interval < time.Second {
		interval = time.Second
	}
	if interval > t.timeout {
		interval = t.timeout
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-t.stopCh:
				return
			case now := <-ticker.C:
				if t.idle(now) {
					onTimeout()
					return
				}
			}
		}
	}()
}

// stop terminates the monitoring goroutine started by run. Safe to call
// multiple times and safe to call when run was never invoked.
func (t *idleTracker) stop() {
	t.stopOnce.Do(func() { close(t.stopCh) })
}
