//go:build full || e2e

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
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

func buildPluginConfig(reg *registry, srv *registerServer) *libplugin.SshPiperPluginConfig {
	// pipeConns bridges a connect-side downstream connection (keyed by its
	// UniqueID) to the channelConn created for it, so PipeStartCallback can
	// mark the pipe authenticated once upstream auth succeeds. Entries are
	// removed on PipeStart or on channelConn.Close, so it stays bounded by the
	// number of in-flight connects.
	var pipeConns sync.Map // uniqueID string → *channelConn

	config := &libplugin.SshPiperPluginConfig{
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
					Uri:      connectURI(user, conn.UniqueID()),
					Auth:     libplugin.CreatePrivateKeyAuth(rec.UpstreamKeyPEM),
				}, nil
			}

			// --- offline guid: a persisted-but-not-live GUID must be refused as
			// "offline" rather than mistaken for a registration username. Only
			// query the store for canonical generated GUIDs: arbitrary valid SSH
			// usernames (for example alice@example.com) are registration names,
			// and fileStore intentionally rejects them as unsafe path keys. ---
			if isGeneratedGUID(user) {
				if _, ok, err := reg.LookupPersisted(user); err != nil {
					return nil, fmt.Errorf("revtunnel: lookup guid %q: %w", user, err)
				} else if ok {
					return nil, fmt.Errorf("revtunnel: tunnel for guid %q is offline", user)
				}
				// Canonical GUIDs belong exclusively to the connect namespace.
				// An unknown/expired GUID must never fall through and become a
				// registration username.
				return nil, fmt.Errorf("revtunnel: tunnel for guid %q is unknown or offline", user)
			}

			// --- register path: any other username triggers registration ---
			// Carry the (public) auth key in the URI itself rather than a
			// server-side staging map, so abandoned auth attempts / pubkey
			// probes leave no per-attempt state to leak. The key is a public
			// key and the URI is internal (plugin↔daemon).
			slog.Info("revtunnel: opening registration session", "user", user)
			return &libplugin.Upstream{
				UserName: user,
				Uri:      fmt.Sprintf("%s://session/%s", registerScheme, base64.RawURLEncoding.EncodeToString(key)),
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
				enc := strings.TrimPrefix(u.Path, "/")
				if enc == "" {
					return nil, fmt.Errorf("revtunnel: register uri missing auth key: %q", uri)
				}
				authKeyWire, err := base64.RawURLEncoding.DecodeString(enc)
				if err != nil {
					return nil, fmt.Errorf("revtunnel: bad register uri key: %w", err)
				}
				return srv.dialConn(authKeyWire)

			case connectScheme:
				guid := u.Host
				rec, sshConn, ok := reg.Lookup(guid)
				if !ok {
					return nil, fmt.Errorf("revtunnel: tunnel for guid %q is offline", guid)
				}
				cc, err := openForwardedTcpip(sshConn, rec, reg)
				if err != nil {
					return nil, err
				}
				// Register the pipe so PipeStartCallback (post-auth) can mark it
				// authenticated; until then channelConn does not refresh the
				// idle timer, so pre-auth handshake bytes / failed probes cannot
				// keep the tunnel alive.
				if uid, _ := url.PathUnescape(strings.TrimPrefix(u.Path, "/")); uid != "" {
					cc.uid = uid
					cc.pipeConns = &pipeConns
					pipeConns.Store(uid, cc)
				}
				return cc, nil

			default:
				return nil, fmt.Errorf("revtunnel: unsupported uri scheme %q", u.Scheme)
			}
		},

		// PipeStartCallback fires only after upstream authentication succeeds,
		// so it is the point at which a connect becomes real activity: mark the
		// pipe authenticated and record the initial touch.
		PipeStartCallback: func(conn libplugin.ConnMetadata) {
			if v, ok := pipeConns.LoadAndDelete(conn.UniqueID()); ok {
				cc := v.(*channelConn)
				cc.authed.Store(true)
				cc.reg.Touch(cc.guid)
			}
		},
	}

	// Password auth is opt-in per tunnel: the registrar enables it by sending
	// ALLOWPASSWORD=1 during registration (see server.go). When enabled for a
	// GUID, a connector may authenticate with the target's own password, which
	// is forwarded upstream unchanged — letting password-only targets be
	// reached without installing the tunnel's upstream key. Registration still
	// requires publickey, so this callback only ever handles the connect path.
	config.PasswordCallback = func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
		user := conn.User()
		rec, _, ok := reg.Lookup(user)
		if !ok {
			return nil, fmt.Errorf("revtunnel: password auth requires a live tunnel guid; %q is unknown or offline", user)
		}
		if !rec.AllowPassword {
			return nil, fmt.Errorf("revtunnel: password auth not enabled for guid %q (registrar did not send ALLOWPASSWORD)", user)
		}
		// Do not Touch here: the password is verified by the upstream target,
		// not by this callback. PipeStartCallback marks the pipe authenticated
		// once upstream auth succeeds, after which piped traffic refreshes the
		// idle timer — so failed password probes never keep the tunnel alive.
		slog.Info("revtunnel: routing connect (password)", "guid", user, "target_user", rec.TargetUser)
		return &libplugin.Upstream{
			UserName: rec.TargetUser,
			Uri:      connectURI(user, conn.UniqueID()),
			Auth:     libplugin.CreatePasswordAuth(password),
		}, nil
	}

	return config
}

func isGeneratedGUID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id.String() == s
}

// connectURI builds the connect-side upstream URI: the GUID in the host and
// the downstream connection's UniqueID in the path so CreateConnCallback can
// tag the channelConn and PipeStartCallback can find it after auth.
func connectURI(guid, uniqueID string) string {
	return fmt.Sprintf("%s://%s/%s", connectScheme, guid, url.PathEscape(uniqueID))
}

// forwardedTcpipPayload is RFC 4254 §7.2.
type forwardedTcpipPayload struct {
	BindAddr   string
	BindPort   uint32
	OriginAddr string
	OriginPort uint32
}

func openForwardedTcpip(sshConn ssh.Conn, rec record, reg *registry) (*channelConn, error) {
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
// bump the tunnel's LastActivity so a busy session keeps the record alive past
// the idle sweeper — but only after the pipe is authenticated (authed is set
// by PipeStartCallback once upstream auth succeeds). Pre-auth handshake bytes
// and failed connects (e.g. wrong-password probes) therefore never refresh the
// timer. Touches are throttled to 30s to avoid mutex contention.
type channelConn struct {
	ch        ssh.Channel
	reg       *registry
	guid      string
	laddr     net.Addr
	raddr     net.Addr
	uid       string       // downstream UniqueID; key into pipeConns
	pipeConns *sync.Map    // uniqueID → *channelConn, for cleanup on Close
	authed    atomic.Bool  // set by PipeStartCallback after upstream auth
	lastTouch atomic.Int64 // unix seconds of last Touch call
}

func (c *channelConn) touch() {
	if !c.authed.Load() {
		return
	}
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

func (c *channelConn) Close() error {
	// Drop any pending pipeConns entry so a connect that never authenticated
	// (no PipeStart) does not leak.
	if c.pipeConns != nil && c.uid != "" {
		c.pipeConns.Delete(c.uid)
	}
	return c.ch.Close()
}
func (c *channelConn) LocalAddr() net.Addr              { return c.laddr }
func (c *channelConn) RemoteAddr() net.Addr             { return c.raddr }
func (c *channelConn) SetDeadline(time.Time) error      { return nil }
func (c *channelConn) SetReadDeadline(time.Time) error  { return nil }
func (c *channelConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr struct{ net, addr string }

func (a *fakeAddr) Network() string { return a.net }
func (a *fakeAddr) String() string  { return a.addr }
