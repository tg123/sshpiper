package main

import (
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
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

	// quit tracks and propagates exit errors from plugins.
	quit chan error

	// pendingPlugins holds configurations for plugins
	// that have not yet been initialized and installed.
	// It is set to nil once all plugins have been initialized and installed.
	pendingPlugins []*pluginConfig
}

type pluginConfig struct {
	// command line args to start the plugin.
	args []string
	// plugin is set once initialized.
	// any given plugin is initialized exactly once.
	plugin *plugin.GrpcPlugin
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
		log.Infof("parsing host key in base64 params")

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
			log.Infof("loaded host certificate from --server-cert-data")
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
			log.Infof("loaded host certificate %v (matched by fingerprint)", match)
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
		log.Infof("generating host key %v", keyfile)
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

	log.Infof("found host keys %v", privateKeyFiles)
	for _, privateKey := range privateKeyFiles {
		log.Infof("loading host key %v", privateKey)
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
			log.Infof("loaded host certificate from --server-cert-data for key %v", privateKey)
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
			log.Infof("loaded host certificate %v (matched by fingerprint)", certFile)
		}

		signers = append(signers, private)
	}

	return signers, nil
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
					log.Warnf("cannot read banner file %v: %v", bannerfile, err)
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
				log.Warnf("upstream banner deduplication failed, cannot get plugin connection meta from challenge context")
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
				log.Warnf("upstream banner first-only failed, cannot get plugin connection meta from challenge context")
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

// startPlugin starts a plugin from args.
// The caller is responsible for ensuring len(args) > 0.
// Plugin exit errors will be sent to quit channel.
func startPlugin(args []string, quit chan error) (*plugin.GrpcPlugin, error) {
	var p *plugin.GrpcPlugin

	switch args[0] {
	case "grpc":
		log.Info("starting net grpc plugin: ")

		grpcplugin, err := createNetGrpcPlugin(args)
		if err != nil {
			return nil, err
		}

		p = grpcplugin

	default:
		cmdplugin, err := createCmdPlugin(args)
		if err != nil {
			return nil, err
		}

		go func() {
			quit <- <-cmdplugin.Quit
		}()

		p = &cmdplugin.GrpcPlugin
	}

	go func() {
		if err := p.RecvLogs(log.StandardLogger().Out); err != nil {
			log.Errorf("plugin %v recv logs error: %v", p.Name, err)
		}
	}()

	return p, nil
}

// setPluginsArgs sets the pending plugins to be started (with the given args).
func (d *daemon) setPluginsArgs(configs [][]string) {
	d.pendingPlugins = make([]*pluginConfig, len(configs))
	for i := range d.pendingPlugins {
		d.pendingPlugins[i] = &pluginConfig{args: configs[i]}
	}
}

func (d *daemon) initializePlugins() error {
	// Start any plugins that haven't started yet.
	for _, rp := range d.pendingPlugins {
		if rp.plugin != nil {
			// already started, skip
			continue
		}
		p, err := startPlugin(rp.args, d.quit)
		if err != nil {
			return fmt.Errorf("failed to start plugin (%q): %v", rp.args, err)
		}
		// mark as started, to prevent future retries
		rp.plugin = p
	}

	// All plugins have started. Install them.
	var plugins []*plugin.GrpcPlugin
	for _, rp := range d.pendingPlugins {
		plugins = append(plugins, rp.plugin)
	}
	if err := d.install(plugins...); err != nil {
		return err
	}

	// Clear pending plugins, so the "fully started and installed?" fast path succeeds.
	d.pendingPlugins = nil
	return nil
}

func (d *daemon) run() error {
	defer d.lis.Close()
	tcpAddr, ok := d.lis.Addr().(*net.TCPAddr)
	port := 0
	if ok {
		port = tcpAddr.Port
	}
	log.WithFields(log.Fields{
		"port": port,
		"addr": d.lis.Addr().String(),
	}).Info("sshpiperd is listening")

	for {
		conn, err := d.lis.Accept()
		if err != nil {
			log.Debugf("failed to accept connection: %v", err)
			continue
		}
		if len(d.pendingPlugins) > 0 {
			err := d.initializePlugins()
			if err != nil {
				log.Errorf("on accept: %v", err)
				conn.Close()
				continue
			}
		}

		log.Debugf("connection accepted: %v", conn.RemoteAddr())

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
				log.Debugf("connection from %v establishing failed reason: %v", c.RemoteAddr(), err)
				if d.config.PipeCreateErrorCallback != nil {
					d.config.PipeCreateErrorCallback(c, err)
				}

				return
			case <-time.After(d.loginGraceTime):
				log.Debugf("pipe establishing timeout, disconnected connection from %v", c.RemoteAddr())
				if d.config.PipeCreateErrorCallback != nil {
					d.config.PipeCreateErrorCallback(c, fmt.Errorf("pipe establishing timeout"))
				}

				return
			}

			defer p.Close()

			log.Infof("ssh connection pipe created %v (username [%v]) -> %v (username [%v])", p.DownstreamConnMeta().RemoteAddr(), p.DownstreamConnMeta().User(), p.UpstreamConnMeta().RemoteAddr(), p.UpstreamConnMeta().User())

			uphookchain := &hookChain{}
			downhookchain := &hookChain{}

			if d.recorddir != "" {
				var recorddir string
				if d.usernameAsRecorddir {
					recorddir = path.Join(d.recorddir, p.DownstreamConnMeta().User())
				} else {
					uniqID := plugin.GetUniqueID(p.ChallengeContext())
					recorddir = path.Join(d.recorddir, uniqID)
				}
				err = os.MkdirAll(recorddir, 0o700)
				if err != nil {
					log.Errorf("cannot create screen recording dir %v: %v", recorddir, err)
					return
				}

				switch d.recordfmt {
				case "asciicast":
					prefix := ""
					if d.usernameAsRecorddir {
						// add prefix to avoid conflict
						prefix = fmt.Sprintf("%d-", time.Now().Unix())
					}
					recorder := newAsciicastLogger(recorddir, prefix)
					defer recorder.Close()

					uphookchain.append(ssh.InspectPacketHook(recorder.uphook))
					downhookchain.append(ssh.InspectPacketHook(recorder.downhook))
				case "typescript":
					recorder, err := newFilePtyLogger(recorddir)
					if err != nil {
						log.Errorf("cannot create screen recording logger: %v", err)
						return
					}
					defer recorder.Close()

					uphookchain.append(ssh.InspectPacketHook(recorder.loggingTty))
				}
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

			if d.config.PipeStartCallback != nil {
				d.config.PipeStartCallback(p.DownstreamConnMeta(), p.ChallengeContext())
			}

			err = p.WaitWithHook(uphookchain.hook(), downhookchain.hook())

			if d.config.PipeErrorCallback != nil {
				d.config.PipeErrorCallback(p.DownstreamConnMeta(), p.ChallengeContext(), err)
			}

			log.Infof("connection from %v closed reason: %v", c.RemoteAddr(), err)
		}(conn)
	}
}
