package main

import (
	"fmt"
	"io/ioutil"
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
	config         *ssh.PiperConfig
	lis            net.Listener
	loginGraceTime time.Duration

	recorddir string
}

func newDaemon(ctx *cli.Context) (*daemon, error) {
	config := &ssh.PiperConfig{}
	config.SetDefaults()

	privateKeys, err := filepath.Glob(ctx.String("server-key"))
	if err != nil {
		return nil, err
	}

	if len(privateKeys) == 0 {
		return nil, fmt.Errorf("no server key found")
	}

	log.Infof("found host keys %v", privateKeys)
	for _, privateKey := range privateKeys {
		log.Infof("loading host key %v", privateKey)
		privateBytes, err := ioutil.ReadFile(privateKey)
		if err != nil {
			return nil, err
		}

		private, err := ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			return nil, err
		}

		config.AddHostKey(private)
	}

	lis, err := net.Listen("tcp", net.JoinHostPort(ctx.String("address"), ctx.String("port")))
	if err != nil {
		return nil, fmt.Errorf("failed to listen for connection: %v", err)
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
				p, err := ssh.NewSSHPiperConn(c, d.config)

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
				return
			case <-time.After(d.loginGraceTime):
				log.Debugf("pipe establishing timeout, disconnected connection from %v", c.RemoteAddr())
				return
			}

			defer p.Close()

			log.Infof("ssh connection pipe created %v -> %v", p.DownstreamConnMeta().RemoteAddr(), p.UpstreamConnMeta().RemoteAddr().String())

			var uphook func([]byte) ([]byte, error)
			if d.recorddir != "" {
				recorddir := path.Join(d.recorddir, p.DownstreamConnMeta().User())
				err = os.MkdirAll(recorddir, 0700)
				if err != nil {
					log.Errorf("cannot create screen recording dir %v: %v", recorddir, err)
					return
				}

				recorder, err := newFilePtyLogger(recorddir)
				if err != nil {
					log.Errorf("cannot create screen recording logger: %v", err)
					return
				}

				uphook = recorder.loggingTty
			}

			err = p.WaitWithHook(uphook, nil)

			log.Infof("connection from %v closed reason: %v", c.RemoteAddr(), err)
		}(conn)
	}
}
