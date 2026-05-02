// SSH `serve` mode. Starts an SSH server that lets remote operators run
// the same `list`/`kill`/`stream` admin subcommands by SSHing into this
// binary, e.g.
//
//	# server (local box):
//	sshpiperd-admin --sshpiperd 127.0.0.1:8082 \
//	    serve --listen :2222 --authorized-keys ~/.ssh/authorized_keys
//
//	# operator workstation:
//	ssh -p 2222 admin@server list
//	ssh -p 2222 admin@server stream <session-id>
//	ssh -p 2222 admin@server          # interactive REPL
//
// Each accepted SSH "session" channel is dispatched to a fresh urfave/cli
// App whose Writer/ErrWriter are the channel itself; the global flags
// (`--sshpiperd`, TLS bits, `--timeout`, …) are inherited from the parent
// `serve` invocation so the remote user only types subcommand names and
// per-subcommand flags (`list --json`, `kill <id>`, `stream <id>`).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func serveCommand() *cli.Command {
	return &cli.Command{
		Name:        "serve",
		Usage:       "start an SSH server that lets ssh clients run admin commands",
		Description: "Accepts SSH connections and dispatches each session's exec request (or interactive shell) to the same `list`, `kill`, and `stream` subcommands. The global flags (--sshpiperd, --insecure, TLS, --timeout) configured on the parent invocation are inherited by every remote command.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "listen",
				Value:   ":2222",
				Usage:   "address to listen on for ssh connections",
				EnvVars: []string{"SSHPIPERD_ADMIN_SERVE_LISTEN"},
			},
			&cli.StringFlag{
				Name:    "host-key",
				Usage:   "path to OpenSSH-format host private key (an ephemeral ed25519 key is generated when empty)",
				EnvVars: []string{"SSHPIPERD_ADMIN_SERVE_HOST_KEY"},
			},
			&cli.StringFlag{
				Name:    "authorized-keys",
				Usage:   "path to an OpenSSH authorized_keys file used to authenticate ssh clients",
				EnvVars: []string{"SSHPIPERD_ADMIN_SERVE_AUTHORIZED_KEYS"},
			},
			&cli.BoolFlag{
				Name:    "no-auth",
				Usage:   "DANGEROUS: accept any ssh client without authentication. Only use on a trusted local socket.",
				EnvVars: []string{"SSHPIPERD_ADMIN_SERVE_NO_AUTH"},
			},
		},
		Action: serveAction,
	}
}

func serveAction(ctx *cli.Context) error {
	hostSigner, err := loadOrGenerateHostKey(ctx.String("host-key"))
	if err != nil {
		return fmt.Errorf("host key: %w", err)
	}

	authzPath := ctx.String("authorized-keys")
	noAuth := ctx.Bool("no-auth")
	if !noAuth && authzPath == "" {
		return fmt.Errorf("--authorized-keys is required (or pass --no-auth to opt out, NOT recommended)")
	}

	cfg := &ssh.ServerConfig{ServerVersion: "SSH-2.0-sshpiperd-admin"}
	if noAuth {
		cfg.NoClientAuth = true
		log.Warnf("serve: --no-auth set, accepting any ssh client without authentication")
	} else {
		auth, err := newAuthorizedKeysChecker(authzPath)
		if err != nil {
			return fmt.Errorf("authorized_keys: %w", err)
		}
		cfg.PublicKeyCallback = auth.callback
	}
	cfg.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", ctx.String("listen"))
	if err != nil {
		return fmt.Errorf("listen %s: %w", ctx.String("listen"), err)
	}
	defer listener.Close()

	log.Infof("serve: ssh admin listening on %s", listener.Addr())

	// Snapshot the inherited global flag values once at startup; every
	// per-session sub-app uses these as its baseline argv prefix.
	inherited := inheritedGlobalArgs(ctx)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Warnf("serve: accept: %v", err)
			continue
		}
		go handleConn(ctx, conn, cfg, inherited)
	}
}

// inheritedGlobalArgs serializes the global flags from the parent serve
// context so we can prepend them to each sub-app invocation. Only flags
// that were explicitly set or differ from the urfave/cli default are
// emitted, which keeps the remote-side argv compact and matches the
// standard CLI experience.
func inheritedGlobalArgs(ctx *cli.Context) []string {
	var out []string
	for _, ep := range ctx.StringSlice("sshpiperd") {
		out = append(out, "--sshpiperd", ep)
	}
	// --insecure defaults to true; pass through whichever value was set.
	out = append(out, "--insecure="+strconv.FormatBool(ctx.Bool("insecure")))
	if v := ctx.String("tls-cacert"); v != "" {
		out = append(out, "--tls-cacert", v)
	}
	if v := ctx.String("tls-cert"); v != "" {
		out = append(out, "--tls-cert", v)
	}
	if v := ctx.String("tls-key"); v != "" {
		out = append(out, "--tls-key", v)
	}
	if v := ctx.String("tls-server-name"); v != "" {
		out = append(out, "--tls-server-name", v)
	}
	if v := ctx.Duration("timeout"); v != 0 {
		out = append(out, "--timeout", v.String())
	}
	if v := ctx.String("log-level"); v != "" {
		out = append(out, "--log-level", v)
	}
	return out
}

// loadOrGenerateHostKey returns a signer for `path` if it points at a
// readable OpenSSH-format private key, otherwise it generates an
// ephemeral ed25519 key (logged so the operator can pin it).
func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return ssh.ParsePrivateKey(b)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}
	log.Warnf("serve: using ephemeral host key (fingerprint %s); pass --host-key to pin a stable key", ssh.FingerprintSHA256(signer.PublicKey()))
	return signer, nil
}

// authorizedKeysChecker authenticates ssh clients against an
// OpenSSH authorized_keys file (loaded once at startup).
type authorizedKeysChecker struct {
	mu   sync.Mutex
	path string
	keys [][]byte
}

func newAuthorizedKeysChecker(path string) (*authorizedKeysChecker, error) {
	c := &authorizedKeysChecker{path: path}
	if err := c.reload(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *authorizedKeysChecker) reload() error {
	b, err := os.ReadFile(c.path)
	if err != nil {
		return err
	}

	var keys [][]byte
	rest := b
	for len(rest) > 0 {
		var k ssh.PublicKey
		k, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
		if err != nil {
			// Skip blank/comment lines: ParseAuthorizedKey returns an
			// error once the buffer holds nothing parsable.
			break
		}
		keys = append(keys, k.Marshal())
	}
	if len(keys) == 0 {
		return fmt.Errorf("no public keys parsed from %s", c.path)
	}

	c.mu.Lock()
	c.keys = keys
	c.mu.Unlock()
	return nil
}

func (c *authorizedKeysChecker) callback(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	marshaled := key.Marshal()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range c.keys {
		if subtle.ConstantTimeCompare(k, marshaled) == 1 {
			return nil, nil
		}
	}
	return nil, fmt.Errorf("public key not authorized")
}

func handleConn(parent *cli.Context, c net.Conn, cfg *ssh.ServerConfig, inherited []string) {
	defer c.Close()

	sconn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		log.Debugf("serve: handshake from %s failed: %v", c.RemoteAddr(), err)
		return
	}
	defer sconn.Close()

	log.Infof("serve: ssh client %s@%s connected", sconn.User(), c.RemoteAddr())
	defer log.Infof("serve: ssh client %s@%s disconnected", sconn.User(), c.RemoteAddr())

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		ch, chReqs, err := newCh.Accept()
		if err != nil {
			log.Warnf("serve: accept channel: %v", err)
			continue
		}
		go handleSession(parent, ch, chReqs, inherited)
	}
}

// handleSession dispatches a single SSH "session" channel: an `exec`
// request runs the parsed command once and exits; a `shell` request
// drops the user into a small line-based REPL.
func handleSession(parent *cli.Context, ch ssh.Channel, reqs <-chan *ssh.Request, inherited []string) {
	defer ch.Close()

	hasPTY := false
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			hasPTY = true
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "env", "window-change":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "exec":
			cmd := parseStringPayload(req.Payload)
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			status := runRemoteCommand(parent, ch, inherited, cmd)
			sendExitStatus(ch, status)
			return
		case "shell":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			runRemoteShell(parent, ch, inherited, hasPTY)
			sendExitStatus(ch, 0)
			return
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// parseStringPayload extracts the SSH "string" payload of an exec
// request (uint32 length prefix + bytes).
func parseStringPayload(p []byte) string {
	if len(p) < 4 {
		return ""
	}
	n := int(uint32(p[0])<<24 | uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3]))
	if 4+n > len(p) {
		return ""
	}
	return string(p[4 : 4+n])
}

// runRemoteCommand parses `cmd` with shell-quote-aware splitting and
// dispatches it to a fresh sub-app whose Writer/ErrWriter are the SSH
// channel `ch`. Returns the SSH exit status to send back to the client.
func runRemoteCommand(parent *cli.Context, ch ssh.Channel, inherited []string, cmd string) uint32 {
	args, err := splitArgs(cmd)
	if err != nil {
		fmt.Fprintf(ch.Stderr(), "sshpiperd-admin: %v\n", err)
		return 2
	}
	if len(args) == 0 {
		fmt.Fprintln(ch.Stderr(), "sshpiperd-admin: no command provided")
		return 2
	}
	return runSubApp(parent.Context, ch, inherited, args)
}

// runRemoteShell runs an interactive REPL on the SSH channel. Each line
// is split with `splitArgs` and dispatched to a fresh sub-app, exactly
// as if the user had run `ssh host <line>`.
func runRemoteShell(parent *cli.Context, ch ssh.Channel, inherited []string, hasPTY bool) {
	const banner = "sshpiperd-admin: type 'help' for commands, 'exit' to quit\n"
	_, _ = io.WriteString(ch, banner)

	if hasPTY {
		t := term.NewTerminal(ch, "sshpiperd-admin> ")
		for {
			line, err := t.ReadLine()
			if err != nil {
				return
			}
			if !runShellLine(parent, ch, inherited, line) {
				return
			}
		}
	}

	// Non-PTY shell: read newline-delimited input from the channel.
	buf := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	for {
		n, err := ch.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			for {
				idx := bytesIndex(buf, '\n')
				if idx < 0 {
					break
				}
				line := strings.TrimRight(string(buf[:idx]), "\r")
				buf = buf[idx+1:]
				if !runShellLine(parent, ch, inherited, line) {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func bytesIndex(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// runShellLine handles a single REPL line. Returns false when the user
// asked to exit (so the caller closes the session).
func runShellLine(parent *cli.Context, ch ssh.Channel, inherited []string, line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return true
	}
	switch line {
	case "exit", "quit":
		return false
	case "help", "?":
		fmt.Fprintln(ch, "available commands: list, kill <session-id>, stream <session-id>, help, exit")
		fmt.Fprintln(ch, "global flags (--sshpiperd, TLS, --timeout, --log-level) are inherited from the server invocation")
		return true
	}
	args, err := splitArgs(line)
	if err != nil {
		fmt.Fprintf(ch, "sshpiperd-admin: %v\n", err)
		return true
	}
	_ = runSubApp(parent.Context, ch, inherited, args)
	return true
}

// runSubApp builds a fresh top-level App (without `serve`, to avoid
// recursive servers) and runs it with `args`, prepending the inherited
// global flags. The App's writers point at the SSH channel so command
// output is delivered straight to the remote operator.
func runSubApp(parentCtx context.Context, ch ssh.Channel, inherited, args []string) uint32 {
	app := newApp(false)
	app.Writer = ch
	app.ErrWriter = ch.Stderr()
	app.ExitErrHandler = func(*cli.Context, error) {} // we manage exit codes ourselves

	full := make([]string, 0, 1+len(inherited)+len(args))
	full = append(full, "sshpiperd-admin")
	full = append(full, inherited...)
	full = append(full, args...)

	if err := app.RunContext(parentCtx, full); err != nil {
		fmt.Fprintf(ch.Stderr(), "sshpiperd-admin: %v\n", err)
		return 1
	}
	return 0
}

// sendExitStatus replies to the client with an SSH exit-status request
// so that `ssh host cmd` propagates the correct shell exit code.
func sendExitStatus(ch ssh.Channel, status uint32) {
	payload := []byte{
		byte(status >> 24), byte(status >> 16), byte(status >> 8), byte(status),
	}
	_, _ = ch.SendRequest("exit-status", false, payload)
}

// splitArgs is a tiny POSIX-shell-ish word splitter: whitespace
// separates fields, single quotes preserve their content verbatim, and
// double quotes preserve content while honouring backslash escapes.
// This is enough to parse the small admin command surface
// (`list --json`, `kill <id>`, `stream <id> --format asciicast`) without
// pulling in a shlex dependency.
func splitArgs(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	in := false
	quote := byte(0)
	escape := false
	flush := func() {
		if in {
			out = append(out, cur.String())
			cur.Reset()
			in = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escape {
			cur.WriteByte(c)
			escape = false
			in = true
			continue
		}
		switch quote {
		case '\'':
			if c == '\'' {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
			in = true
		case '"':
			switch c {
			case '"':
				quote = 0
			case '\\':
				escape = true
			default:
				cur.WriteByte(c)
			}
			in = true
		default:
			switch c {
			case ' ', '\t':
				flush()
			case '\'', '"':
				quote = c
				in = true
			case '\\':
				escape = true
			default:
				cur.WriteByte(c)
				in = true
			}
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated %c quote", quote)
	}
	if escape {
		return nil, fmt.Errorf("trailing backslash at end of input")
	}
	flush()
	return out, nil
}
