//go:build full || e2e

package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/crypto/ssh"
)

const (
	registerScheme = "revtunnel-register"
	connectScheme  = "revtunnel"
)

// regSessionEntry holds per-registration staging state: which registerServer
// to dial and the public key wire bytes the registrar used to authenticate to
// sshpiper (used as the default connector key).
type regSessionEntry struct {
	srv         *registerServer
	authKeyWire []byte // wire-format public key offered during sshpiper auth
}

func buildPluginConfig(reg *registry, srv *registerServer) *libplugin.SshPiperPluginConfig {
	// regSessions holds the per-Uri staging data. We assign a fresh uri for
	// every registration so that PublicKeyCallback retries on the same
	// downstream do not reuse a stale connection.
	regSessions := atomicMap{}

	return &libplugin.SshPiperPluginConfig{
		PublicKeyCallback: func(conn libplugin.ConnMetadata, key []byte) (*libplugin.Upstream, error) {
			user := conn.User()

			// --- connect path: user is a known GUID ---
			if rec, _, ok := reg.Lookup(user); ok {
				if !bytes.Equal(rec.ConnectorKeyWire, key) {
					slog.Debug("revtunnel: key mismatch",
						"guid", user,
						"stored_len", len(rec.ConnectorKeyWire),
						"offered_len", len(key),
					)
					return nil, fmt.Errorf("revtunnel: public key mismatch for guid %q", user)
				}
				slog.Info("revtunnel: routing connect", "guid", user, "target_user", rec.TargetUser)
				return &libplugin.Upstream{
					UserName: rec.TargetUser,
					Uri:      fmt.Sprintf("%s://%s", connectScheme, user),
					Auth:     libplugin.CreatePrivateKeyAuth(rec.UpstreamKeyPEM),
				}, nil
			}

			// --- register path: any other username triggers registration ---
			id := uuid.NewString()
			regSessions.Store(id, &regSessionEntry{srv: srv, authKeyWire: key})
			slog.Info("revtunnel: opening registration session", "user", user, "id", id)
			return &libplugin.Upstream{
				UserName: user,
				Uri:      fmt.Sprintf("%s://%s/%s", registerScheme, url.PathEscape(user), id),
				Auth:     libplugin.CreateNoneAuth(),
			}, nil
		},

		CreateConnCallback: func(uri string) (net.Conn, error) {
			u, err := url.Parse(uri)
			if err != nil {
				return nil, fmt.Errorf("revtunnel: bad uri %q: %w", uri, err)
			}
			switch u.Scheme {
			case registerScheme:
				id := ""
				if len(u.Path) > 1 {
					id = u.Path[1:]
				}
				if id == "" {
					return nil, fmt.Errorf("revtunnel: register uri missing session id: %q", uri)
				}
				v, ok := regSessions.LoadAndDelete(id)
				if !ok {
					return nil, fmt.Errorf("revtunnel: unknown register session %q", id)
				}
				entry := v.(*regSessionEntry)
				return entry.srv.dialConn(entry.authKeyWire)

			case connectScheme:
				guid := u.Host
				rec, sshConn, ok := reg.Lookup(guid)
				if !ok {
					return nil, fmt.Errorf("revtunnel: tunnel for guid %q is offline", guid)
				}
				return openForwardedTcpip(sshConn, rec, reg)

			default:
				return nil, fmt.Errorf("revtunnel: unsupported uri scheme %q", u.Scheme)
			}
		},
	}
}

// forwardedTcpipPayload is RFC 4254 §7.2.
type forwardedTcpipPayload struct {
	BindAddr   string
	BindPort   uint32
	OriginAddr string
	OriginPort uint32
}

func openForwardedTcpip(sshConn ssh.Conn, rec record, reg *registry) (net.Conn, error) {
	payload := ssh.Marshal(forwardedTcpipPayload{
		BindAddr:   rec.BindAddr,
		BindPort:   rec.BindPort,
		OriginAddr: "127.0.0.1",
		OriginPort: 0,
	})
	ch, reqs, err := sshConn.OpenChannel("forwarded-tcpip", payload)
	if err != nil {
		return nil, fmt.Errorf("revtunnel: open forwarded-tcpip on tunnel %q: %w", rec.Guid, err)
	}
	go ssh.DiscardRequests(reqs)

	return &channelConn{
		ch:    ch,
		reg:   reg,
		guid:  rec.Guid,
		laddr: &fakeAddr{net: "revtunnel", addr: fmt.Sprintf("%s:%d", rec.BindAddr, rec.BindPort)},
		raddr: &fakeAddr{net: "revtunnel", addr: rec.Guid},
	}, nil
}

// channelConn wraps an ssh.Channel so it satisfies net.Conn. Reads and writes
// also bump the tunnel's LastActivity so a busy session keeps the record
// alive past the idle sweeper. Touches are throttled to avoid mutex contention
// on high-throughput sessions (30s granularity is fine given the 2h idle timeout).
type channelConn struct {
	ch        ssh.Channel
	reg       *registry
	guid      string
	laddr     net.Addr
	raddr     net.Addr
	lastTouch atomic.Int64 // unix seconds of last Touch call
}

func (c *channelConn) touch() {
	now := time.Now().Unix()
	if now-c.lastTouch.Load() < 30 {
		return
	}
	c.lastTouch.Store(now)
	c.reg.Touch(c.guid)
}

func (c *channelConn) Read(b []byte) (int, error) {
	n, err := c.ch.Read(b)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *channelConn) Write(b []byte) (int, error) {
	n, err := c.ch.Write(b)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *channelConn) Close() error                     { return c.ch.Close() }
func (c *channelConn) LocalAddr() net.Addr              { return c.laddr }
func (c *channelConn) RemoteAddr() net.Addr             { return c.raddr }
func (c *channelConn) SetDeadline(time.Time) error      { return nil }
func (c *channelConn) SetReadDeadline(time.Time) error  { return nil }
func (c *channelConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr struct{ net, addr string }

func (a *fakeAddr) Network() string { return a.net }
func (a *fakeAddr) String() string  { return a.addr }

// atomicMap is a small typed wrapper around sync.Map for the register session
// staging area. Kept here (rather than registry.go) because it is callback-
// internal state with no test surface.
type atomicMap struct {
	v atomic.Pointer[mapSnapshot]
}

type mapSnapshot map[string]any

func (m *atomicMap) Store(k string, v any) {
	for {
		old := m.v.Load()
		nm := mapSnapshot{}
		if old != nil {
			for kk, vv := range *old {
				nm[kk] = vv
			}
		}
		nm[k] = v
		if m.v.CompareAndSwap(old, &nm) {
			return
		}
	}
}

func (m *atomicMap) LoadAndDelete(k string) (any, bool) {
	for {
		old := m.v.Load()
		if old == nil {
			return nil, false
		}
		v, ok := (*old)[k]
		if !ok {
			return nil, false
		}
		nm := mapSnapshot{}
		for kk, vv := range *old {
			if kk == k {
				continue
			}
			nm[kk] = vv
		}
		if m.v.CompareAndSwap(old, &nm) {
			return v, true
		}
	}
}
