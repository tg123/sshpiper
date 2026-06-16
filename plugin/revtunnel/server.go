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

// dialConn returns a fresh client-side net.Conn connected to our embedded
// ssh.Server via the loopback listener.
func (s *registerServer) dialConn() (net.Conn, error) {
	return net.Dial("tcp", s.ln.Addr().String())
}

// HandleConn drives one registration session end-to-end. It blocks until the
// connection is closed by either side. Any tunnels registered on this
// connection are evicted when the connection terminates.
func (s *registerServer) HandleConn(c net.Conn) {
	sc, chans, reqs, err := ssh.NewServerConn(c, s.cfg)
	if err != nil {
		slog.Warn("revtunnel: register handshake failed", "err", err)
		_ = c.Close()
		return
	}
	slog.Debug("revtunnel: registration handshake complete", "user", sc.User())

	h := &connHandler{
		reg:    s.reg,
		sc:     sc,
		guidCh: make(chan string, 4),
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
	sc  *ssh.ServerConn

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
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (h *connHandler) handleTcpipForward(req *ssh.Request) {
	var payload tcpipForwardPayload
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "revtunnel")
	if err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
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
		Guid:                guid,
		TargetUser:          h.sc.User(),
		BindAddr:            payload.BindAddr,
		BindPort:            boundPort,
		PublicKeyWire:       sshPub.Marshal(),
		PublicKeyAuthorized: string(ssh.MarshalAuthorizedKey(sshPub)),
		PrivateKeyPEM:       pem.EncodeToMemory(pemBlock),
		CreatedAt:           now,
		LastActivity:        now,
	}
	if err := h.reg.Put(rec, h.sc); err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	h.mu.Lock()
	h.guids = append(h.guids, guid)
	h.mu.Unlock()

	if req.WantReply {
		if payload.BindPort == 0 {
			_ = req.Reply(true, ssh.Marshal(struct{ Port uint32 }{boundPort}))
		} else {
			_ = req.Reply(true, nil)
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
// stdout. Stdin is drained but ignored.
func (h *connHandler) serveSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	go func() {
		for req := range reqs {
			switch req.Type {
			case "shell", "exec", "pty-req", "env":
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
	}()
	go io.Copy(io.Discard, ch)

	for guid := range h.guidCh {
		rec, _, ok := h.reg.Lookup(guid)
		if !ok {
			continue
		}
		writeRegistrationBlock(ch, rec)
	}
	_ = ch.CloseWrite()
	_ = ch.Close()
}

func writeRegistrationBlock(w io.Writer, rec record) {
	fmt.Fprintf(w, "# revtunnel registration\r\n")
	fmt.Fprintf(w, "GUID=%s\r\n", rec.Guid)
	fmt.Fprintf(w, "BIND=%s:%d\r\n", rec.BindAddr, rec.BindPort)
	fmt.Fprintf(w, "TARGET_USER=%s\r\n", rec.TargetUser)
	fmt.Fprintf(w, "# add the following line to authorized_keys on the target host\r\n")
	// PublicKeyAuthorized already ends with a newline; normalise to CRLF
	fmt.Fprintf(w, "PUBLIC_KEY=%s\r\n", trimRight(rec.PublicKeyAuthorized))
	fmt.Fprintf(w, "# use the following private key when running ssh -i <file> %s@sshpiper\r\n", rec.Guid)
	fmt.Fprintf(w, "-----BEGIN REVTUNNEL PRIVATE KEY-----\r\n")
	_, _ = w.Write(rec.PrivateKeyPEM)
	fmt.Fprintf(w, "-----END REVTUNNEL PRIVATE KEY-----\r\n")
}

func trimRight(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
