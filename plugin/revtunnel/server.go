//go:build full || e2e

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
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

	// pendingKeys receives the downstream public key for each new registration
	// dial. dialConnWithKey pushes, HandleConn pops. Buffered to avoid blocking.
	pendingKeys chan []byte
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

	s := &registerServer{reg: reg, cfg: cfg, signer: signer, ln: ln, pendingKeys: make(chan []byte, 16)}
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
		if err != nil {
			return nil, fmt.Errorf("revtunnel: read host key %q: %w", path, err)
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			return nil, fmt.Errorf("revtunnel: parse host key %q: %w", path, err)
		}
		return signer, nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "revtunnel-host")
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(pem.EncodeToMemory(pemBlock))
	if err != nil {
		return nil, err
	}
	return signer, nil
}

// dialConnWithKey stores the downstream public key then dials the embedded
// server. HandleConn retrieves the key after accepting.
func (s *registerServer) dialConnWithKey(pubKeyWire []byte) (net.Conn, error) {
	s.pendingKeys <- pubKeyWire
	return net.Dial("tcp", s.ln.Addr().String())
}

// HandleConn drives one registration session end-to-end. It blocks until the
// connection is closed by either side. Any tunnels registered on this
// connection are evicted when the connection terminates.
func (s *registerServer) HandleConn(c net.Conn) {
	// Pop the downstream public key queued by dialConnWithKey.
	var downstreamKey []byte
	select {
	case downstreamKey = <-s.pendingKeys:
	default:
	}

	sc, chans, reqs, err := ssh.NewServerConn(c, s.cfg)
	if err != nil {
		slog.Warn("revtunnel: register handshake failed", "err", err)
		_ = c.Close()
		return
	}
	slog.Debug("revtunnel: registration handshake complete", "user", sc.User())

	h := &connHandler{
		reg:           s.reg,
		srv:           s,
		sc:            sc,
		guidCh:        make(chan string, 4),
		downstreamKey: downstreamKey,
	}
	defer h.cleanup()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); h.handleGlobalRequests(reqs) }()
	go func() { defer wg.Done(); h.handleChannels(chans) }()
	_ = sc.Wait()
	_ = sc.Close()
	wg.Wait()
}

// connHandler holds per-connection state for a registration session: the
// list of guids it owns (so we can evict them on disconnect) and a fan-out
// channel that wakes the session writer once a tcpip-forward has produced a
// guid.
type connHandler struct {
	reg *registry
	srv *registerServer
	sc  *ssh.ServerConn

	downstreamKey []byte // SSH wire format of the registrar's public key

	mu    sync.Mutex
	guids []string // tunnels created by this connection; evicted on disconnect

	guidCh chan string // newly-registered guid → session writer
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
			// We don't actually listen anywhere; just ack so OpenSSH is happy.
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
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

	// Generate an internal keypair used for upstream auth to the target.
	_, upstreamPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		slog.Error("revtunnel: ed25519.GenerateKey failed", "error", err)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	pemBlock, err := ssh.MarshalPrivateKey(upstreamPriv, "revtunnel")
	if err != nil {
		slog.Error("revtunnel: MarshalPrivateKey failed", "error", err)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	upstreamPub, err := ssh.NewPublicKey(upstreamPriv.Public())
	if err != nil {
		slog.Error("revtunnel: NewPublicKey failed", "error", err)
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
		Guid:              guid,
		TargetUser:        h.sc.User(),
		BindAddr:          payload.BindAddr,
		BindPort:          boundPort,
		DownstreamKeyWire: h.downstreamKey,
		UpstreamKeyPEM:    pem.EncodeToMemory(pemBlock),
		UpstreamKeyPub:    string(ssh.MarshalAuthorizedKey(upstreamPub)),
		CreatedAt:         now,
		LastActivity:      now,
	}
	slog.Debug("revtunnel: storing record", "guid", guid, "downstream_key_len", len(h.downstreamKey))
	if err := h.reg.Put(rec, h.sc); err != nil {
		slog.Error("revtunnel: reg.Put failed", "error", err)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	h.mu.Lock()
	h.guids = append(h.guids, guid)
	h.mu.Unlock()

	if req.WantReply {
		replyPayload := ssh.Marshal(struct{ Port uint32 }{boundPort})
		if err := req.Reply(true, replyPayload); err != nil {
			slog.Error("revtunnel: req.Reply failed", "error", err)
		}
	}

	// Non-blocking fan-out — if no session is reading, the next session
	// open will drain.
	select {
	case h.guidCh <- guid:
	default:
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

// serveSession waits for the registrant's shell/exec/pty requests, then
// streams every guid registered on this connection (newline-separated blocks
// of guid + authorized_keys line + private key PEM) to the session's
// stdout. Detects Ctrl+C (ETX byte or INT signal) to close gracefully.
func (h *connHandler) serveSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	done := make(chan struct{})
	closeDone := sync.OnceFunc(func() { close(done) })

	go func() {
		for req := range reqs {
			switch req.Type {
			case "shell", "exec", "pty-req", "env":
				if req.WantReply {
					_ = req.Reply(true, nil)
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

	// Read stdin; close on ETX (Ctrl+C with PTY) or EOF.
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

	// Wait for the first GUID (arrives when client sends tcpip-forward via -R).
	// If nothing arrives within 5s, the client likely forgot -R.
	select {
	case guid, ok := <-h.guidCh:
		if !ok {
			return
		}
		rec, _, found := h.reg.Lookup(guid)
		if found {
			writeRegistrationBlock(ch, rec, h.srv.piperHost, h.srv.piperPort)
		}
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
		case guid, ok := <-h.guidCh:
			if !ok {
				goto cleanup
			}
			rec, _, found := h.reg.Lookup(guid)
			if !found {
				continue
			}
			writeRegistrationBlock(ch, rec, h.srv.piperHost, h.srv.piperPort)
		case <-done:
			goto cleanup
		}
	}

cleanup:
	_ = ch.CloseWrite()
	_ = ch.Close()
}

func writeRegistrationBlock(w io.Writer, rec record, piperHost string, piperPort int) {
	fmt.Fprintf(w, "%s\r\n", rec.Guid)
	fmt.Fprintf(w, "\r\n")
	fmt.Fprintf(w, "# add to target's authorized_keys:\r\n")
	fmt.Fprintf(w, "echo '%s' >> ~/.ssh/authorized_keys\r\n", trimRight(rec.UpstreamKeyPub))
	fmt.Fprintf(w, "\r\n")
	fmt.Fprintf(w, "# connect with:\r\n")
	if piperPort > 0 && piperPort != 22 {
		fmt.Fprintf(w, "ssh %s@%s -p %d  # -> %s@%s:%d\r\n", rec.Guid, piperHost, piperPort, rec.TargetUser, rec.BindAddr, rec.BindPort)
	} else {
		fmt.Fprintf(w, "ssh %s@%s  # -> %s@%s:%d\r\n", rec.Guid, piperHost, rec.TargetUser, rec.BindAddr, rec.BindPort)
	}
	fmt.Fprintf(w, "\r\n")
	fmt.Fprintf(w, "# press Ctrl+C to stop forwarding\r\n")
}

func trimRight(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
