package main

import (
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tg123/sshpiper/cmd/sshpiperd/internal/admin"
	"github.com/tg123/sshpiper/cmd/sshpiperd/internal/plugin"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

type daemon struct {
	config         *plugin.GrpcPluginConfig
	lis            net.Listener
	loginGraceTime time.Duration

	recorddir             string
	recordfmt             string
	usernameAsRecorddir   bool
	filterHostkeysReqeust bool
	replyPing             bool
	disableLocalForward   bool
	disableRemoteForward  bool

	// recordRoot is an os.Root scoped to recorddir, opened by
	// initScreenRecording. All per-connection recording directories and
	// files are created/opened through it (see setupScreenRecording),
	// since os.Root refuses to resolve any path component -- including
	// through a symlink -- outside of the directory it was opened on. This
	// is the actual containment boundary for screen recording; the lexical
	// checks in safeJoinUserRecordDir are only a defense-in-depth measure.
	recordRoot *os.Root

	// injectEnv is merged into every upstream session's env-injection.
	// Plugin-provided env (Upstream.Env) takes precedence on key
	// collisions. Empty (nil/zero-length) means no global injection.
	injectEnv map[string]string

	// adminRegistry tracks live ssh.PiperConn pipes for the admin gRPC API.
	// Set by main.go when --admin-grpc-port is enabled; nil otherwise, in
	// which case the daemon path is unchanged.
	adminRegistry *admin.Registry
}

func generateSshKey(keyfile string) error {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	privateKeyPEM, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return err
	}

	privateKeyBytes := pem.EncodeToMemory(privateKeyPEM)

	return os.WriteFile(keyfile, privateKeyBytes, 0o600)
}

// certSignerFromBytes parses raw authorized-key bytes into a host certificate
// signer paired with the given private key. source is used in error messages.
func certSignerFromBytes(private ssh.Signer, certBytes []byte, source string) (ssh.Signer, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, err
	}

	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("not a valid ssh certificate: %v", source)
	}

	if cert.CertType != ssh.HostCert {
		return nil, fmt.Errorf("certificate %v is not a host certificate (got type %d)", source, cert.CertType)
	}

	return ssh.NewCertSigner(cert, private)
}

func loadCertSigner(private ssh.Signer, certFile string) (ssh.Signer, error) {
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	return certSignerFromBytes(private, certBytes, certFile)
}

// findMatchingCert finds the first host certificate whose embedded public key
// matches the private key's fingerprint. Non-host certificates (e.g. user
// certificates) are skipped so that a valid host cert later in the list is
// still found.
func findMatchingCert(private ssh.Signer, certFiles []string) string {
	keyFP := ssh.FingerprintSHA256(private.PublicKey())
	for _, certFile := range certFiles {
		certBytes, err := os.ReadFile(certFile)
		if err != nil {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
		if err != nil {
			continue
		}
		cert, ok := pub.(*ssh.Certificate)
		if !ok {
			continue
		}
		if cert.CertType != ssh.HostCert {
			continue
		}
		if ssh.FingerprintSHA256(cert.Key) == keyFP {
			return certFile
		}
	}
	return ""
}

func loadHostKeys(ctx *cli.Context) ([]ssh.Signer, error) {
	keybase64 := ctx.String("server-key-data")
	certPattern := ctx.String("server-cert")
	certBase64 := ctx.String("server-cert-data")

	var certBytes []byte
	certFiles := []string{}

	// --server-cert-data takes priority over --server-cert similar to --server-key-data
	if certBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(certBase64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode --server-cert-data: %w", err)
		}

		certBytes = decoded
	} else if certPattern != "" {
		var err error
		certFiles, err = filepath.Glob(certPattern)
		if err != nil {
			return nil, err
		}

		if len(certFiles) == 0 {
			return nil, fmt.Errorf("--server-cert %q matched no files", certPattern)
		}
	}

	if keybase64 != "" {
		slog.Info("parsing host key in base64 params")

		privateBytes, err := base64.StdEncoding.DecodeString(keybase64)
		if err != nil {
			return nil, err
		}

		private, err := ssh.ParsePrivateKey([]byte(privateBytes))
		if err != nil {
			return nil, err
		}

		if certBytes != nil {
			certSigner, err := certSignerFromBytes(private, certBytes, "--server-cert-data")
			if err != nil {
				return nil, fmt.Errorf("failed to load host certificate from --server-cert-data: %w", err)
			}

			private = certSigner
			slog.Info("loaded host certificate from --server-cert-data")
		} else if len(certFiles) > 0 {
			match := findMatchingCert(private, certFiles)
			if match == "" {
				return nil, fmt.Errorf("no host certificate in %v matched the provided key fingerprint", certFiles)
			}

			certSigner, err := loadCertSigner(private, match)
			if err != nil {
				return nil, fmt.Errorf("failed to load host certificate %v: %w", match, err)
			}

			private = certSigner
			slog.Info("loaded host certificate matched by fingerprint", "certificate", match)
		}

		return []ssh.Signer{private}, nil
	}

	keyfile := ctx.String("server-key")
	privateKeyFiles, err := filepath.Glob(keyfile)
	if err != nil {
		return nil, err
	}

	generate := false

	switch ctx.String("server-key-generate-mode") {
	case "notexist":
		generate = len(privateKeyFiles) == 0
	case "always":
		generate = true
	case "disable":
	default:
		return nil, fmt.Errorf("unknown server-key-generate-mode %v", ctx.String("server-key-generate-mode"))
	}

	if generate {
		slog.Info("generating host key", "keyfile", keyfile)
		if err := generateSshKey(keyfile); err != nil {
			return nil, err
		}

		privateKeyFiles = []string{keyfile}
	}

	if len(privateKeyFiles) == 0 {
		return nil, fmt.Errorf("no server key found")
	}

	if certBytes != nil && len(privateKeyFiles) > 1 {
		return nil, fmt.Errorf("--server-cert-data provides a single certificate but %d server keys were found; use --server-cert with a glob pattern for multi-key setups", len(privateKeyFiles))
	}

	signers := make([]ssh.Signer, 0, len(privateKeyFiles))

	slog.Info("found host keys", "private_keys", privateKeyFiles)
	for _, privateKey := range privateKeyFiles {
		slog.Info("loading host key", "keyfile", privateKey)
		privateBytes, err := os.ReadFile(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read server key %v: %w", privateKey, err)
		}

		private, err := ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse server key %v: %w", privateKey, err)
		}

		if certBytes != nil {
			certSigner, err := certSignerFromBytes(private, certBytes, "--server-cert-data")
			if err != nil {
				return nil, fmt.Errorf("failed to load host certificate from --server-cert-data for key %v: %w", privateKey, err)
			}

			private = certSigner
			slog.Info("loaded host certificate from --server-cert-data for key", "keyfile", privateKey)
		} else if certPattern != "" && len(certFiles) > 0 {
			certFile := findMatchingCert(private, certFiles)
			if certFile == "" {
				return nil, fmt.Errorf("no host certificate in %v matched key %v", certFiles, privateKey)
			}

			certSigner, err := loadCertSigner(private, certFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load host certificate %v: %w", certFile, err)
			}

			private = certSigner
			slog.Info("loaded host certificate matched by fingerprint", "certificate", certFile)
		}

		signers = append(signers, private)
	}

	return signers, nil
}

// safeJoinUserRecordDir joins base with the (attacker-controlled) SSH
// username to build the per-user recording directory name, and verifies
// that the resulting path does not lexically escape base. A malicious
// username such as "../../etc" or containing path separators must not be
// able to make the recording directory land outside of base. On success it
// returns that directory's name relative to base (e.g. "alice"), for use as
// a subdirectory of the os.Root opened on base (see daemon.recordRoot).
//
// This lexical check is only a defense-in-depth measure: it rejects
// malicious usernames early with a clear error, but it cannot detect a
// symlink placed under base (before or during the daemon's lifetime) that
// would cause the resulting path to be resolved outside of base. The actual
// containment boundary is the os.Root the returned name is subsequently
// used with, which refuses to follow such a symlink out of the root.
func safeJoinUserRecordDir(base, user string) (string, error) {
	dir := filepath.Join(base, user)

	rel, err := filepath.Rel(base, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("resulting recording dir %q escapes recording root %q", dir, base)
	}

	return rel, nil
}

func newDaemon(ctx *cli.Context) (*daemon, error) {
	config := &plugin.GrpcPluginConfig{}

	config.Ciphers = ctx.StringSlice("allowed-downstream-ciphers-algos")
	config.MACs = ctx.StringSlice("allowed-downstream-macs-algos")
	config.KeyExchanges = ctx.StringSlice("allowed-downstream-keyexchange-algos")
	config.PublicKeyAuthAlgorithms = ctx.StringSlice("allowed-downstream-pubkey-algos")

	config.SetDefaults()

	// tricky, call SetDefaults, in first call, Cipers, Macs, Kex will be nil if [] and the second call will set the default values
	// this can be ignored because sshpiper.go will call SetDefaults again before use it
	// however, this is to make sure that the default values are set no matter sshiper.go calls SetDefaults or not
	config.SetDefaults()

	signers, err := loadHostKeys(ctx)
	if err != nil {
		return nil, err
	}
	for _, signer := range signers {
		config.AddHostKey(signer)
	}

	lis, err := net.Listen("tcp", net.JoinHostPort(ctx.String("address"), ctx.String("port")))
	if err != nil {
		return nil, fmt.Errorf("failed to listen for connection: %v", err)
	}

	bannertext := ctx.String("banner-text")
	bannerfile := ctx.String("banner-file")

	if bannertext != "" || bannerfile != "" {
		config.DownstreamBannerCallback = func(_ ssh.ConnMetadata, _ ssh.ChallengeContext) string {
			if bannerfile != "" {
				text, err := os.ReadFile(bannerfile)
				if err != nil {
					slog.Warn("cannot read banner file", "bannerfile", bannerfile, "error", err)
				} else {
					return string(text)
				}
			}
			return bannertext
		}
	}

	switch ctx.String("upstream-banner-mode") {
	case "passthrough":
		// library will handle the banner to client
	case "ignore":
		config.UpstreamBannerCallback = func(_ ssh.ServerPreAuthConn, _ string, _ ssh.ChallengeContext) error {
			return nil
		}
	case "dedup":
		config.UpstreamBannerCallback = func(downstream ssh.ServerPreAuthConn, banner string, ctx ssh.ChallengeContext) error {
			meta, ok := ctx.Meta().(*plugin.PluginConnMeta)
			if !ok {
				// should not happen, but just in case
				slog.Warn("upstream banner deduplication failed: plugin connection meta unavailable in challenge context")
				return nil
			}

			hash := fmt.Sprintf("%x", md5.Sum([]byte(banner)))
			key := fmt.Sprintf("sshpiperd.upstream.banner.%s", hash)

			if meta.Metadata[key] == "true" {
				return nil
			}

			meta.Metadata[key] = "true"

			return downstream.SendAuthBanner(banner)
		}
	case "first-only":
		config.UpstreamBannerCallback = func(downstream ssh.ServerPreAuthConn, banner string, ctx ssh.ChallengeContext) error {
			meta, ok := ctx.Meta().(*plugin.PluginConnMeta)
			if !ok {
				// should not happen, but just in case
				slog.Warn("upstream banner first-only failed: plugin connection meta unavailable in challenge context")
				return nil
			}

			if meta.Metadata["sshpiperd.upstream.banner.sent"] == "true" {
				return nil
			}

			meta.Metadata["sshpiperd.upstream.banner.sent"] = "true"
			return downstream.SendAuthBanner(banner)
		}
	default:
		return nil, fmt.Errorf("unknown upstream banner mode %q; allowed: 'passthrough' or 'ignore'", ctx.String("upstream-banner-mode"))
	}

	return &daemon{
		config:         config,
		lis:            lis,
		loginGraceTime: ctx.Duration("login-grace-time"),
	}, nil
}

func (d *daemon) install(plugins ...*plugin.GrpcPlugin) error {
	if len(plugins) == 0 {
		return fmt.Errorf("no plugins found")
	}

	if len(plugins) == 1 {
		return plugins[0].InstallPiperConfig(d.config)
	}

	m := plugin.ChainPlugins{}

	for _, p := range plugins {
		if err := m.Append(p); err != nil {
			return err
		}
	}

	return m.InstallPiperConfig(d.config)
}

// initScreenRecording prepares screen recording, if enabled via
// --screen-recording-dir: it ensures the configured recording root exists
// and opens an os.Root scoped to it. Every per-connection recording
// directory/file is subsequently created/opened through that root (see
// setupScreenRecording), so a symlink placed under the recording root --
// whether pre-existing or planted while the daemon is running -- cannot be
// used to escape it. It is a no-op if recording is disabled.
func (d *daemon) initScreenRecording() error {
	if d.recorddir == "" {
		return nil
	}

	if err := os.MkdirAll(d.recorddir, 0o700); err != nil {
		return fmt.Errorf("cannot create screen recording root %q: %w", d.recorddir, err)
	}

	root, err := os.OpenRoot(d.recorddir)
	if err != nil {
		return fmt.Errorf("cannot open screen recording root %q: %w", d.recorddir, err)
	}

	d.recordRoot = root
	return nil
}

// setupScreenRecording wires the screen-recording packet-inspection hooks
// for a single piped connection into uphookchain/downhookchain.
//
// ok reports whether the caller should proceed with the connection. It is
// true when screen recording is disabled (d.recordRoot == nil, closer is
// nil) or was set up successfully (closer releases the recorder's resources
// and must be called once the connection ends, if non-nil). It is false
// when screen recording is enabled but this particular connection must be
// rejected -- e.g. the downstream username fails the
// --username-as-recorddir path-traversal guard, or the recording
// directory/files could not be created -- in which case the caller must
// abort the connection entirely, matching sshpiperd's historical
// fail-closed behavior for screen recording.
func (d *daemon) setupScreenRecording(p *ssh.PiperConn, uphookchain, downhookchain *hookChain) (closer func() error, ok bool) {
	if d.recordRoot == nil {
		return nil, true
	}

	var subdir string
	if d.usernameAsRecorddir {
		user := p.DownstreamConnMeta().User()
		rel, err := safeJoinUserRecordDir(d.recorddir, user)
		if err != nil {
			slog.Error("invalid username for screen recording dir", "user", user, "error", err)
			return nil, false
		}
		subdir = rel
	} else {
		subdir = plugin.GetUniqueID(p.ChallengeContext())
	}

	if err := d.recordRoot.MkdirAll(subdir, 0o700); err != nil {
		slog.Error("cannot create screen recording dir", "recorddir", subdir, "error", err)
		return nil, false
	}

	switch d.recordfmt {
	case "asciicast":
		prefix := ""
		if d.usernameAsRecorddir {
			// add prefix to avoid conflict
			prefix = fmt.Sprintf("%d-", time.Now().Unix())
		}
		recorder := newAsciicastLogger(d.recordRoot, subdir, prefix)

		uphookchain.append(ssh.InspectPacketHook(recorder.uphook))
		downhookchain.append(ssh.InspectPacketHook(recorder.downhook))

		return recorder.Close, true
	case "typescript":
		recorder, err := newFilePtyLogger(d.recordRoot, subdir)
		if err != nil {
			slog.Error("cannot create screen recording logger", "error", err)
			return nil, false
		}

		uphookchain.append(ssh.InspectPacketHook(recorder.loggingTty))

		return recorder.Close, true
	}

	return nil, true
}

func (d *daemon) run() error {
	defer d.lis.Close()
	slog.Info("sshpiperd is listening", "address", d.lis.Addr().String())

	if err := d.initScreenRecording(); err != nil {
		return err
	}
	if d.recordRoot != nil {
		defer d.recordRoot.Close()
	}

	for {
		conn, err := d.lis.Accept()
		if err != nil {
			slog.Debug("failed to accept connection", "error", err)
			continue
		}

		slog.Debug("connection accepted", "remote_addr", conn.RemoteAddr())

		go func(c net.Conn) {
			defer c.Close()

			pipec := make(chan *ssh.PiperConn)
			errorc := make(chan error)

			go func() {
				p, err := ssh.NewSSHPiperConn(c, &d.config.PiperConfig)
				if err != nil {
					errorc <- err
					return
				}

				pipec <- p
			}()

			var p *ssh.PiperConn

			select {
			case p = <-pipec:
			case err := <-errorc:
				slog.Debug("connection establishing failed", "remote_addr", c.RemoteAddr(), "error", err)
				if d.config.PipeCreateErrorCallback != nil {
					d.config.PipeCreateErrorCallback(c, err)
				}

				return
			case <-time.After(d.loginGraceTime):
				slog.Debug("pipe establishing timeout, disconnected connection", "remote_addr", c.RemoteAddr())
				if d.config.PipeCreateErrorCallback != nil {
					d.config.PipeCreateErrorCallback(c, fmt.Errorf("pipe establishing timeout"))
				}

				return
			}

			defer p.Close()

			slog.Info(
				"ssh connection pipe created",
				"downstream_addr", p.DownstreamConnMeta().RemoteAddr(),
				"downstream_user", p.DownstreamConnMeta().User(),
				"upstream_addr", p.UpstreamConnMeta().RemoteAddr(),
				"upstream_user", p.UpstreamConnMeta().User(),
			)

			uphookchain := &hookChain{}
			downhookchain := &hookChain{}

			// Register the live pipe with the admin registry (if enabled) so
			// the admin gRPC service can list/kill/stream this session. The
			// streaming hook is appended to the existing hook chains so it
			// shares packet inspection cost with the recorder.
			if d.adminRegistry != nil {
				uniqID := plugin.GetUniqueID(p.ChallengeContext())
				bc := d.adminRegistry.Add(admin.Session{
					ID:             uniqID,
					DownstreamUser: p.DownstreamConnMeta().User(),
					DownstreamAddr: p.DownstreamConnMeta().RemoteAddr().String(),
					UpstreamUser:   p.UpstreamConnMeta().User(),
					UpstreamAddr:   p.UpstreamConnMeta().RemoteAddr().String(),
					StartedAt:      time.Now(),
				}, p)
				defer d.adminRegistry.Remove(uniqID)

				sh := admin.NewStreamHook(bc)
				uphookchain.append(sh.Up)
				downhookchain.append(sh.Down)
			}

			closeRecorder, ok := d.setupScreenRecording(p, uphookchain, downhookchain)
			if !ok {
				return
			}
			if closeRecorder != nil {
				defer closeRecorder()
			}

			if d.filterHostkeysReqeust {
				uphookchain.append(func(b []byte) (ssh.PipePacketHookMethod, []byte, error) {
					if b[0] == 80 {
						var x struct {
							RequestName string `sshtype:"80"`
						}
						_ = ssh.Unmarshal(b, &x)
						if x.RequestName == "hostkeys-prove-00@openssh.com" || x.RequestName == "hostkeys-00@openssh.com" {
							return ssh.PipePacketHookTransform, nil, nil
						}
					}

					return ssh.PipePacketHookTransform, b, nil
				})
			}

			if d.replyPing {
				downhookchain.append(ssh.PingPacketReply)
			}

			if d.disableLocalForward || d.disableRemoteForward {
				filter := newForwardingFilter(d.disableLocalForward, d.disableRemoteForward)
				downhookchain.append(filter.down)
				if d.disableRemoteForward {
					// Only needed when down can generate its own reply to a
					// blocked global request: up must observe genuine
					// upstream replies to earlier requests so those local
					// replies can be released in the same order the client
					// sent the requests. See forwardingFilter's docs.
					uphookchain.append(filter.up)
				}
			}

			env := plugin.UpstreamEnv(p.ChallengeContext())
			if len(d.injectEnv) > 0 {
				merged := make(map[string]string, len(d.injectEnv)+len(env))
				for k, v := range d.injectEnv {
					merged[k] = v
				}
				// Plugin-provided env wins on collision.
				for k, v := range env {
					merged[k] = v
				}
				env = merged
			}
			if len(env) > 0 {
				slog.Debug("installing env injector", "count", len(env), "remote_addr", p.UpstreamConnMeta().RemoteAddr())
				inj := newEnvInjector(p, env)
				downhookchain.append(inj.down)
			}

			if d.config.PipeStartCallback != nil {
				d.config.PipeStartCallback(p.DownstreamConnMeta(), p.ChallengeContext())
			}

			err = p.WaitWithHook(uphookchain.hook(), downhookchain.hook())

			if d.config.PipeErrorCallback != nil {
				d.config.PipeErrorCallback(p.DownstreamConnMeta(), p.ChallengeContext(), err)
			}

			slog.Info("connection closed", "remote_addr", c.RemoteAddr(), "reason", err)
		}(conn)
	}
}
