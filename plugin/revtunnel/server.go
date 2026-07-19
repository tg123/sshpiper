//go:build full || e2e

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// registerServer hosts an in-process ssh.ServerConfig used to terminate the
// SSH protocol speaking with each downstream `ssh -R` registrant. Each
// registration session is plumbed in via a 127.0.0.1 listener rather than
// net.Pipe — net.Pipe has zero buffering and deadlocks the SSH version
// exchange, where both sides Write before Read.
type registerServer struct {
	reg    *registry
	cfg    *ssh.ServerConfig
	signer ssh.Signer

	ln net.Listener

	piperHost string
	piperPort int
}

func newRegisterServer(reg *registry, hostKeyPath string) (*registerServer, error) {
	signer, err := loadOrGenerateHostKey(hostKeyPath)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ServerConfig{
		NoClientAuth:  true,
		ServerVersion: "SSH-2.0-sshpiper-revtunnel",
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("revtunnel: bind loopback listener: %w", err)
	}

	s := &registerServer{reg: reg, cfg: cfg, signer: signer, ln: ln}
	go s.acceptLoop()
	return s, nil
}

func (s *registerServer) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.HandleConn(c)
	}
}

func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			signer, err := ssh.ParsePrivateKey(data)
			if err != nil {
				return nil, fmt.Errorf("revtunnel: parse host key %q: %w", path, err)
			}
			return signer, nil
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("revtunnel: read host key %q: %w", path, err)
		}
		// File doesn't exist — generate and persist.
		signer, pemData, err := generateHostKey()
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, pemData, 0o600); err != nil {
			return nil, fmt.Errorf("revtunnel: write generated host key %q: %w", path, err)
		}
		slog.Info("revtunnel: generated and saved host key", "path", path)
		return signer, nil
	}
	// No path — ephemeral key (not persisted).
	signer, _, err := generateHostKey()
	return signer, err
}

func generateHostKey() (ssh.Signer, []byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "revtunnel-host")
	if err != nil {
		return nil, nil, err
	}
	pemData := pem.EncodeToMemory(pemBlock)
	signer, err := ssh.ParsePrivateKey(pemData)
	if err != nil {
		return nil, nil, err
	}
	return signer, pemData, nil
}

// dialConn dials the loopback register server and writes the registrar's auth
// key as a length-prefixed header on the connection itself, before returning
// it to sshpiperd (which only starts the SSH handshake afterwards). Carrying
// the key on the connection pairs it unambiguously with THIS session, with no
// dependence on accept/dial ordering across concurrent registrations.
func (s *registerServer) dialConn(authKeyWire []byte) (net.Conn, error) {
	c, err := net.Dial("tcp", s.ln.Addr().String())
	if err != nil {
		return nil, err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(authKeyWire)))
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(append(hdr[:], authKeyWire...)); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("revtunnel: write auth header: %w", err)
	}
	_ = c.SetWriteDeadline(time.Time{})
	return c, nil
}

// readAuthHeader reads the length-prefixed auth key that dialConn wrote onto
// the connection before the SSH handshake.
func readAuthHeader(c net.Conn) ([]byte, error) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	var lenBuf [4]byte
	if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > 8192 {
		return nil, fmt.Errorf("revtunnel: invalid auth header length %d", n)
	}
	key := make([]byte, n)
	if _, err := io.ReadFull(c, key); err != nil {
		return nil, err
	}
	return key, nil
}

// HandleConn drives one registration session end-to-end. It blocks until the
// connection is closed by either side. Any tunnels registered on this
// connection are evicted when the connection terminates.
func (s *registerServer) HandleConn(c net.Conn) {
	// Read the auth key that dialConn framed onto this exact connection.
	authKeyWire, err := readAuthHeader(c)
	if err != nil {
		slog.Warn("revtunnel: read registration auth header", "err", err, "remote", c.RemoteAddr())
		_ = c.Close()
		return
	}

	sc, chans, reqs, err := ssh.NewServerConn(c, s.cfg)
	if err != nil {
		slog.Warn("revtunnel: register handshake failed", "err", err)
		_ = c.Close()
		return
	}
	slog.Debug("revtunnel: registration handshake complete", "user", sc.User())

	h := &connHandler{
		reg:                s.reg,
		srv:                s,
		sc:                 sc,
		guidCh:             make(chan registrationNotif, 4),
		defaultConnKeyWire: authKeyWire,
		shellCh:            make(chan struct{}),
		forwards:           make(map[string]string),
	}
	defer h.cleanup()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); h.handleGlobalRequests(reqs) }()
	go func() { defer wg.Done(); h.handleChannels(chans) }()
	_ = sc.Wait()
	_ = sc.Close()
	wg.Wait()
	close(h.guidCh)
}

// connHandler holds per-connection state for a registration session: the
// list of guids it owns (so we can evict them on disconnect) and a fan-out
// channel that wakes the session writer once a tcpip-forward has produced a
// guid.
type connHandler struct {
	reg *registry
	srv *registerServer
	sc  *ssh.ServerConn

	mu                 sync.Mutex
	guids              []string          // tunnels created by this connection; evicted on disconnect
	forwards           map[string]string // "bindaddr:bindport" → guid, for cancel-tcpip-forward revocation
	envConnKeyWire     []byte            // connector key from CONNECTOR_PUBKEY env (nil if not provided)
	envConnKeyInvalid  bool              // CONNECTOR_PUBKEY was sent but failed to parse — revoke rather than fall back
	envAllowPassword   bool              // connect-side password auth requested via ALLOWPASSWORD env
	defaultConnKeyWire []byte            // connector key from the registrar's sshpiper auth key

	shellCh   chan struct{} // closed once when shell/exec is received
	shellOnce sync.Once     // guards the single close of shellCh across all sessions

	guidCh chan registrationNotif // newly-registered tunnel → session writer
}

// registrationNotif carries a newly registered GUID to the session writer
// goroutine.
type registrationNotif struct {
	guid string
}

// applyEnvRequest inspects an SSH env channel request. "CONNECTOR_PUBKEY" is
// parsed as an authorized-keys line and stored as the overriding connector
// public key (first valid occurrence wins). "ALLOWPASSWORD" enables connect-
// side password auth for this connection's tunnels when its value is truthy.
func (h *connHandler) applyEnvRequest(req *ssh.Request) {
	var envReq struct {
		Name  string
		Value string
	}
	if err := ssh.Unmarshal(req.Payload, &envReq); err != nil {
		return
	}
	switch envReq.Name {
	case "CONNECTOR_PUBKEY":
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(envReq.Value))
		if err != nil {
			// Record the failure so registration is revoked rather than
			// silently falling back to the registrar's default key (which would
			// authorize an unintended key — a fail-open access-control bug).
			slog.Warn("revtunnel: invalid CONNECTOR_PUBKEY env value", "error", err)
			h.mu.Lock()
			h.envConnKeyInvalid = true
			h.mu.Unlock()
			return
		}
		h.mu.Lock()
		if h.envConnKeyWire == nil {
			h.envConnKeyWire = pub.Marshal()
			slog.Debug("revtunnel: connector key set from CONNECTOR_PUBKEY env", "key_len", len(h.envConnKeyWire))
		}
		h.mu.Unlock()
	case "ALLOWPASSWORD":
		if envTruthy(envReq.Value) {
			h.mu.Lock()
			h.envAllowPassword = true
			h.mu.Unlock()
			slog.Debug("revtunnel: connect-side password auth enabled via ALLOWPASSWORD env")
		}
	}
}

// envTruthy reports whether an env value means "on". Empty (the bare
// `SendEnv=ALLOWPASSWORD` form) counts as true so that simply forwarding the
// variable enables the feature.
func envTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// applyEnvOverrides applies every env-driven override (connector key and
// password toggle) to the registry record for guid. Must be called after
// shell/exec is received so that all env channel requests have been processed.
// It returns an error when an override cannot be persisted so the caller can
// revoke the tunnel rather than fall back (open) to the default key.
func (h *connHandler) applyEnvOverrides(guid string) error {
	h.mu.Lock()
	envKey := make([]byte, len(h.envConnKeyWire))
	copy(envKey, h.envConnKeyWire)
	allowPassword := h.envAllowPassword
	connKeyInvalid := h.envConnKeyInvalid
	h.mu.Unlock()

	if connKeyInvalid {
		return fmt.Errorf("invalid CONNECTOR_PUBKEY supplied for guid %s", guid)
	}
	if len(envKey) > 0 {
		if !h.reg.UpdateConnectorKeyWire(guid, envKey) {
			return fmt.Errorf("could not apply CONNECTOR_PUBKEY for guid %s", guid)
		}
	}
	if allowPassword {
		if !h.reg.UpdateAllowPassword(guid, true) {
			return fmt.Errorf("could not enable password auth for guid %s", guid)
		}
	}
	return nil
}

// handleRegistration applies env overrides for a freshly registered guid and
// writes its registration block. If an override fails to persist, the tunnel
// is revoked (so it never becomes usable with the wrong key) and an error is
// reported to the registrar's session instead.
func (h *connHandler) handleRegistration(ch ssh.Channel, guid string) {
	if err := h.applyEnvOverrides(guid); err != nil {
		slog.Error("revtunnel: registration overrides failed; revoking tunnel", "guid", guid, "error", err)
		h.revokeGuid(guid)
		fmt.Fprintf(ch, "ERROR: %v; tunnel revoked\r\n", err)
		return
	}
	rec, _, found := h.reg.Lookup(guid)
	if !found {
		return
	}
	writeRegistrationBlock(ch, rec, h.srv.piperHost, h.srv.piperPort)
}

// revokeGuid removes a single tunnel from this connection's bookkeeping and the
// registry, without disturbing sibling forwards or the registrar's session.
func (h *connHandler) revokeGuid(guid string) {
	h.mu.Lock()
	remaining := h.guids[:0]
	for _, g := range h.guids {
		if g != guid {
			remaining = append(remaining, g)
		}
	}
	h.guids = remaining
	for k, g := range h.forwards {
		if g == guid {
			delete(h.forwards, k)
		}
	}
	h.mu.Unlock()
	h.reg.Remove(guid)
}

func (h *connHandler) cleanup() {
	h.mu.Lock()
	guids := append([]string(nil), h.guids...)
	h.mu.Unlock()
	for _, g := range guids {
		h.reg.Delete(g)
	}
}

// tcpipForwardPayload is RFC 4254 §7.1.
type tcpipForwardPayload struct {
	BindAddr string
	BindPort uint32
}

func (h *connHandler) handleGlobalRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			h.handleTcpipForward(req)
		case "cancel-tcpip-forward":
			h.handleCancelTcpipForward(req)
		default:
			slog.Debug("revtunnel: rejecting unknown global request", "type", req.Type, "want_reply", req.WantReply)
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (h *connHandler) handleTcpipForward(req *ssh.Request) {
	var payload tcpipForwardPayload
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		slog.Error("revtunnel: failed to unmarshal tcpip-forward", "error", err)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	slog.Debug("revtunnel: received tcpip-forward", "bind_addr", payload.BindAddr, "bind_port", payload.BindPort)

	if len(h.defaultConnKeyWire) == 0 {
		slog.Error("revtunnel: no connector key available (registrar auth key missing)")
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	// Generate an internal keypair used for upstream auth to the target.
	_, upstreamPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		slog.Error("revtunnel: ed25519.GenerateKey (upstream) failed", "error", err)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	upstreamBlock, err := ssh.MarshalPrivateKey(upstreamPriv, "revtunnel")
	if err != nil {
		slog.Error("revtunnel: MarshalPrivateKey (upstream) failed", "error", err)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	upstreamPub, err := ssh.NewPublicKey(upstreamPriv.Public())
	if err != nil {
		slog.Error("revtunnel: NewPublicKey (upstream) failed", "error", err)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	// RFC 4254 §7.1 — when bind_port is 0 the server allocates a port and
	// returns it. We don't actually listen anywhere, but OpenSSH stores the
	// allocated port and uses it to match incoming forwarded-tcpip channels;
	// returning 0 makes it drop our channel as "unknown listen_port 0".
	// Synthesize a unique pseudo-port in the dynamic range instead.
	boundPort := payload.BindPort
	if boundPort == 0 {
		boundPort = allocPseudoPort()
	}

	guid := uuid.NewString()
	now := time.Now().UTC()
	rec := record{
		Guid:             guid,
		TargetUser:       h.sc.User(),
		BindAddr:         payload.BindAddr,
		BindPort:         boundPort,
		ConnectorKeyWire: h.defaultConnKeyWire, // overridable via CONNECTOR_PUBKEY env
		UpstreamKeyPEM:   pem.EncodeToMemory(upstreamBlock),
		UpstreamKeyPub:   string(ssh.MarshalAuthorizedKey(upstreamPub)),
		CreatedAt:        now,
		LastActivity:     now,
	}
	slog.Debug("revtunnel: storing record", "guid", guid)
	if err := h.reg.Put(rec, h.sc); err != nil {
		slog.Error("revtunnel: reg.Put failed", "error", err)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	h.mu.Lock()
	h.guids = append(h.guids, guid)
	h.forwards[forwardKey(payload.BindAddr, boundPort)] = guid
	h.mu.Unlock()

	if req.WantReply {
		// RFC 4254 §7.1: the allocated-port reply payload is included only when
		// the requested bind port was 0. For a fixed nonzero port, reply with an
		// empty payload so strict clients don't reject trailing bytes.
		var replyPayload []byte
		if payload.BindPort == 0 {
			replyPayload = ssh.Marshal(struct{ Port uint32 }{boundPort})
		}
		if err := req.Reply(true, replyPayload); err != nil {
			slog.Error("revtunnel: req.Reply failed", "error", err)
		}
	}

	// Send registration notification to session writer. Use non-blocking send
	// so we don't hang if the session has already exited (e.g., Ctrl+C).
	select {
	case h.guidCh <- registrationNotif{guid: guid}:
	default:
		slog.Warn("revtunnel: guidCh full or closed, discarding guid", "guid", guid)
	}
}

// forwardKey is the map key used to correlate a bind address/port with the
// guid it created, for cancel-tcpip-forward revocation.
func forwardKey(bindAddr string, bindPort uint32) string {
	return fmt.Sprintf("%s:%d", bindAddr, bindPort)
}

// handleCancelTcpipForward revokes the tunnel(s) that a cancel-tcpip-forward
// request refers to, so a forward the registrar believes it cancelled can no
// longer be connected to.
func (h *connHandler) handleCancelTcpipForward(req *ssh.Request) {
	var payload tcpipForwardPayload
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		slog.Error("revtunnel: failed to unmarshal cancel-tcpip-forward", "error", err)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	h.revokeForward(payload.BindAddr, payload.BindPort)
	if req.WantReply {
		_ = req.Reply(true, nil)
	}
}

// revokeForward removes the tunnel record(s) matching bindAddr/bindPort on this
// connection without tearing down the registrar's SSH session (other forwards
// on the same connection stay alive). When the port is unknown (a bare `-R 0`
// cancel), every forward sharing the bind address is revoked.
func (h *connHandler) revokeForward(bindAddr string, bindPort uint32) {
	h.mu.Lock()
	var guids []string
	if bindPort != 0 {
		// A specific port cancel revokes only the exact forward; an unmatched
		// specific cancel is a no-op (do NOT fall back to the bind-address
		// sweep, which would revoke unrelated tunnels).
		key := forwardKey(bindAddr, bindPort)
		if g, ok := h.forwards[key]; ok {
			guids = append(guids, g)
			delete(h.forwards, key)
		}
	} else {
		// A bare `-R 0` cancel carries no usable port, so revoke every forward
		// sharing the bind address.
		prefix := bindAddr + ":"
		for key, g := range h.forwards {
			if strings.HasPrefix(key, prefix) {
				guids = append(guids, g)
				delete(h.forwards, key)
			}
		}
	}
	if len(guids) > 0 {
		gone := make(map[string]bool, len(guids))
		for _, g := range guids {
			gone[g] = true
		}
		remaining := h.guids[:0]
		for _, g := range h.guids {
			if !gone[g] {
				remaining = append(remaining, g)
			}
		}
		h.guids = remaining
	}
	h.mu.Unlock()

	for _, g := range guids {
		slog.Info("revtunnel: revoking tunnel on cancel-tcpip-forward", "guid", g)
		h.reg.Remove(g)
	}
}

// allocPseudoPort returns a unique high port number for use as the "bound"
// port advertised in tcpip-forward replies. The port is never actually
// opened on the host; it is just a token used by RFC 4254 to match
// forwarded-tcpip channels.
var pseudoPortCounter atomic.Uint32

func allocPseudoPort() uint32 {
	const base = 40000
	const span = 20000
	n := pseudoPortCounter.Add(1)
	return base + (n % span)
}

func (h *connHandler) handleChannels(chans <-chan ssh.NewChannel) {
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "revtunnel only accepts session channels")
			continue
		}
		ch, reqs, err := newCh.Accept()
		if err != nil {
			continue
		}
		go h.serveSession(ch, reqs)
	}
}

// serveSession waits for the registrant's shell/exec request (which signals
// that all env requests — including CONNECTOR_PUBKEY — have been sent), then
// streams every guid registered on this connection (newline-separated blocks
// of guid + upstream authorized_keys line) to the session's stdout. Detects
// Ctrl+C (ETX byte or INT signal) to close gracefully.
func (h *connHandler) serveSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	done := make(chan struct{})
	closeDone := sync.OnceFunc(func() { close(done) })
	// shellCh is connection-scoped and shared by every session goroutine on
	// this connection, so the close must be guarded by a connection-scoped
	// Once — a per-session sync.OnceFunc would let a second session channel
	// close an already-closed channel and panic.
	signalShell := func() { h.shellOnce.Do(func() { close(h.shellCh) }) }

	go func() {
		for req := range reqs {
			switch req.Type {
			case "env":
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				h.applyEnvRequest(req)
			case "shell", "exec", "pty-req":
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				if req.Type == "shell" || req.Type == "exec" {
					signalShell()
				}
			case "signal":
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				// Any signal (INT, TERM, etc.) stops the session.
				closeDone()
				return
			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
	}()

	// Scan stdin for ETX (Ctrl+C with a PTY) to stop forwarding. EOF on the
	// read side only ends this scanner — the session itself stays open (a
	// no-stdin client legitimately half-closes here) until a signal request
	// arrives or the SSH connection closes.
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := ch.Read(buf)
			for i := range n {
				if buf[i] == 0x03 { // ETX = Ctrl+C
					closeDone()
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// Wait for shell/exec before consuming guidCh. This ensures all env
	// requests (specifically CONNECTOR_PUBKEY) have been processed by the
	// goroutine above before we apply the override and write the block.
	select {
	case <-h.shellCh:
	case <-done:
		_ = ch.Close()
		return
	case <-time.After(30 * time.Second):
		fmt.Fprintf(ch, "ERROR: no shell/exec received within 30s\r\n")
		_ = ch.CloseWrite()
		_ = ch.Close()
		return
	}

	// Wait for the first GUID (arrives when client sends tcpip-forward via -R).
	// If nothing arrives within 5s, the client likely forgot -R.
	select {
	case notif, ok := <-h.guidCh:
		if !ok {
			return
		}
		h.handleRegistration(ch, notif.guid)
	case <-done:
		_ = ch.Close()
		return
	case <-time.After(5 * time.Second):
		fmt.Fprintf(ch, "ERROR: no -R forward received. Usage:\r\n")
		fmt.Fprintf(ch, "  ssh -R 0:<host>:<port> <user>@sshpiper\r\n")
		_ = ch.CloseWrite()
		_ = ch.Close()
		return
	}

	// Continue streaming any additional registrations on this connection.
	for {
		select {
		case notif, ok := <-h.guidCh:
			if !ok {
				goto cleanup
			}
			h.handleRegistration(ch, notif.guid)
		case <-done:
			goto cleanup
		}
	}

cleanup:
	_ = ch.CloseWrite()
	_ = ch.Close()
}

func writeRegistrationBlock(w io.Writer, rec record, piperHost string, piperPort int) {
	portFlag := ""
	if piperPort > 0 && piperPort != 22 {
		portFlag = fmt.Sprintf(" -p %d", piperPort)
	}

	fmt.Fprintf(w, "%s\r\n", rec.Guid)
	fmt.Fprintf(w, "\r\n")
	if rec.AllowPassword {
		// Password auth is enabled: no key needs to be installed on the target.
		fmt.Fprintf(w, "# password auth enabled — connect as %s with the target's password:\r\n", rec.TargetUser)
		fmt.Fprintf(w, "ssh %s@%s%s  # prompts for the target password\r\n", rec.Guid, piperHost, portFlag)
		fmt.Fprintf(w, "\r\n")
	}
	fmt.Fprintf(w, "# add to target's authorized_keys:\r\n")
	fmt.Fprintf(w, "echo '%s' >> ~/.ssh/authorized_keys\r\n", trimRight(rec.UpstreamKeyPub))
	fmt.Fprintf(w, "\r\n")
	fmt.Fprintf(w, "# connect as %s (use the same key you registered with, or the CONNECTOR_PUBKEY key):\r\n", rec.TargetUser)
	fmt.Fprintf(w, "ssh -i <your-key> %s@%s%s\r\n", rec.Guid, piperHost, portFlag)
	fmt.Fprintf(w, "\r\n")
	fmt.Fprintf(w, "# press Ctrl+C to stop forwarding\r\n")
}

func trimRight(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
