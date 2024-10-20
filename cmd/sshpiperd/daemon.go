package main

import (
	"crypto/ed25519"
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

	return os.WriteFile(keyfile, privateKeyBytes, 0600)
}

func newDaemon(ctx *cli.Context) (*daemon, error) {
	config := &plugin.GrpcPluginConfig{}
	config.SetDefaults()

	keybase64 := ctx.String("server-key-data")
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

		config.AddHostKey(private)
	} else {
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

		log.Infof("found host keys %v", privateKeyFiles)
		for _, privateKey := range privateKeyFiles {
			log.Infof("loading host key %v", privateKey)
			privateBytes, err := os.ReadFile(privateKey)
			if err != nil {
				return nil, err
			}

			private, err := ssh.ParsePrivateKey(privateBytes)
			if err != nil {
				return nil, err
			}

			config.AddHostKey(private)
		}
	}

	lis, err := net.Listen("tcp", net.JoinHostPort(ctx.String("address"), ctx.String("port")))
	if err != nil {
		return nil, fmt.Errorf("failed to listen for connection: %v", err)
	}

	bannertext := ctx.String("banner-text")
	bannerfile := ctx.String("banner-file")

	if bannertext != "" || bannerfile != "" {
		config.BannerCallback = func(_ ssh.ConnMetadata, _ ssh.ChallengeContext) string {
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

func (d *daemon) run() error {
	defer d.lis.Close()
	log.Infof("sshpiperd is listening on: %v", d.lis.Addr().String())

	for {
		conn, err := d.lis.Accept()
		if err != nil {
			log.Debugf("failed to accept connection: %v", err)
			continue
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

			var uphook func([]byte) ([]byte, error)
			var downhook func([]byte) ([]byte, error)

			if d.recorddir != "" {
				var recorddir string
				if d.usernameAsRecorddir {
					recorddir = path.Join(d.recorddir, p.DownstreamConnMeta().User())
				} else {
					uniqID := plugin.GetUniqueID(p.ChallengeContext())
					recorddir = path.Join(d.recorddir, uniqID)
				}
				err = os.MkdirAll(recorddir, 0700)
				if err != nil {
					log.Errorf("cannot create screen recording dir %v: %v", recorddir, err)
					return
				}
				if d.recordfmt == "asciicast" {
					prefix := ""
					if d.usernameAsRecorddir {
						// add prefix to avoid conflict
						prefix = fmt.Sprintf("%d-", time.Now().Unix())
					}
					recorder := newAsciicastLogger(recorddir, prefix)
					defer recorder.Close()

					uphook = recorder.uphook
					downhook = recorder.downhook
				} else if d.recordfmt == "typescript" {
					recorder, err := newFilePtyLogger(recorddir)
					if err != nil {
						log.Errorf("cannot create screen recording logger: %v", err)
						return
					}
					defer recorder.Close()

					uphook = recorder.loggingTty
				}
			}

			if d.filterHostkeysReqeust {
				nextUpHook := uphook
				uphook = func(b []byte) ([]byte, error) {
					if b[0] == 80 {
						var x struct {
							RequestName string `sshtype:"80"`
						}
						_ = ssh.Unmarshal(b, &x)
						if x.RequestName == "hostkeys-prove-00@openssh.com" || x.RequestName == "hostkeys-00@openssh.com" {
							return nil, nil
						}
					}
					if nextUpHook != nil {
						return nextUpHook(b)
					}
					return b, nil
				}
			}

			if d.config.PipeStartCallback != nil {
				d.config.PipeStartCallback(p.DownstreamConnMeta(), p.ChallengeContext())
			}

			err = p.WaitWithHook(uphook, downhook)

			if d.config.PipeErrorCallback != nil {
				d.config.PipeErrorCallback(p.DownstreamConnMeta(), p.ChallengeContext(), err)
			}

			log.Infof("connection from %v closed reason: %v", c.RemoteAddr(), err)
		}(conn)
	}
}
