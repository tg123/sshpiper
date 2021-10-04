package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	"log"

	"github.com/tg123/sshpiper/sshpiperd/auditor"
	"github.com/tg123/sshpiper/sshpiperd/challenger"
	"github.com/tg123/sshpiper/sshpiperd/registry"
	"github.com/tg123/sshpiper/sshpiperd/upstream"
)

type piperdConfig struct {
	ListenAddr     string        `short:"l" long:"listen" description:"Listening Address" default:"0.0.0.0" env:"SSHPIPERD_LISTENADDR" ini-name:"listen-address"`
	Port           uint          `short:"p" long:"port" description:"Listening Port" default:"2222" env:"SSHPIPERD_PORT" ini-name:"listen-port"`
	PiperKeyFile   string        `short:"i" long:"server-key" description:"Server key file for SSH Piper" default:"/etc/ssh/ssh_host_rsa_key" env:"SSHPIPERD_SERVER_KEY" ini-name:"server-key"`
	LoginGraceTime time.Duration `long:"login-grace-time" description:"Piper disconnects after this time if the pipe has not successfully established" default:"30s" env:"SSHPIPERD_LOGIN_GRACETIME" ini-name:"login-grace-time"`

	UpstreamDriver   string `short:"u" long:"upstream-driver" description:"Upstream provider driver" default:"workingdir" env:"SSHPIPERD_UPSTREAM_DRIVER" ini-name:"upstream-driver"`
	ChallengerDriver string `short:"c" long:"challenger-driver" description:"Additional challenger name, e.g. pam, empty for no additional challenge" env:"SSHPIPERD_CHALLENGER" ini-name:"challenger-driver"`
	AuditorDriver    string `long:"auditor-driver" description:"Auditor for ssh connections piped by SSH Piper" env:"SSHPIPERD_AUDITOR" ini-name:"auditor-driver"`

	BannerText string `long:"banner-text" description:"Display a banner before authentication, would be ignored if banner file was set" env:"SSHPIPERD_BANNERTEXT" ini-name:"banner-text" `
	BannerFile string `long:"banner-file" description:"Display a banner from file before authentication" env:"SSHPIPERD_BANNERFILE" ini-name:"banner-file" `
}

func getAndInstall(reg, name string, get func(n string) registry.Plugin, install func(plugin registry.Plugin) error, logger *log.Logger) error {
	if name == "" {
		return nil
	}

	p := get(name)

	if p == nil {
		return fmt.Errorf("%v driver %v not found", reg, name)
	}

	err := p.Init(logger)
	if err != nil {
		return err
	}
	return install(p)
}

func installDrivers(piper *ssh.PiperConfig, config *piperdConfig, logger *log.Logger) (auditor.Provider, error) {

	// install upstreamProvider driver
	if config.UpstreamDriver == "" {
		return nil, fmt.Errorf("must provider upstream driver")
	}

	var bigbro auditor.Provider

	for _, d := range []struct {
		reg     string
		name    string
		get     func(n string) registry.Plugin
		install func(plugin registry.Plugin) error
	}{
		// upstream driver
		{
			"Upstream",
			config.UpstreamDriver,
			func(n string) registry.Plugin {
				return upstream.Get(n)
			},
			func(plugin registry.Plugin) error {
				handler := plugin.(upstream.Provider).GetHandler()

				if handler == nil {
					return fmt.Errorf("upstream driver return nil handler")
				}

				piper.FindUpstream = handler
				return nil
			},
		},
		// challenger driver
		{
			"Challenger",
			config.ChallengerDriver,
			func(n string) registry.Plugin {
				return challenger.Get(n)
			},
			func(plugin registry.Plugin) error {
				handler := plugin.(challenger.Provider).GetHandler()

				if handler == nil {
					return fmt.Errorf("challenger driver return nil handler")
				}

				piper.AdditionalChallenge = handler
				return nil
			},
		},
		// auditor driver
		{
			"Auditor",
			config.AuditorDriver,
			func(n string) registry.Plugin {
				return auditor.Get(n)
			},
			func(plugin registry.Plugin) error {
				bigbro = plugin.(auditor.Provider)
				return nil
			},
		},
	} {
		err := getAndInstall(d.reg, d.name, d.get, d.install, logger)
		if err != nil {
			return nil, err
		}
	}

	return bigbro, nil
}

func startPiper(config *piperdConfig, logger *log.Logger) error {

	logger.Println("sshpiper is about to start")

	piper := &ssh.PiperConfig{}

	// drivers
	bigbro, err := installDrivers(piper, config, logger)
	if err != nil {
		return err
	}

	// listeners
	privateKeys, err := filepath.Glob(config.PiperKeyFile)
	if err != nil {
		return err
	}

	logger.Println("Found host keys", privateKeys)
	for _, privateKey := range privateKeys {
		logger.Println("Loading host key", privateKey)
		privateBytes, err := ioutil.ReadFile(privateKey)
		if err != nil {
			return err
		}

		private, err := ssh.ParsePrivateKey(privateBytes)
		if err != nil {
			return err
		}

		piper.AddHostKey(private)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.ListenAddr, config.Port))
	if err != nil {
		return fmt.Errorf("failed to listen for connection: %v", err)
	}
	defer listener.Close()

	// banner
	if config.BannerFile != "" {

		piper.BannerCallback = func(conn ssh.ConnMetadata) string {

			msg, err := ioutil.ReadFile(config.BannerFile)

			if err != nil {
				logger.Printf("failed to read banner file: %v", err)
				return ""
			}

			return string(msg)
		}
	} else if config.BannerText != "" {
		piper.BannerCallback = func(conn ssh.ConnMetadata) string {
			return config.BannerText + "\n"
		}
	}

	logger.Printf("sshpiperd started")

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Printf("failed to accept connection: %v", err)
			continue
		}

		logger.Printf("connection accepted: %v", conn.RemoteAddr())

		go func(c net.Conn) {
			defer c.Close()

			pipec := make(chan *ssh.PiperConn)
			errorc := make(chan error)

			go func() {
				p, err := ssh.NewSSHPiperConn(c, piper)

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
				logger.Printf("connection from %v establishing failed reason: %v", c.RemoteAddr(), err)
				return
			case <-time.After(config.LoginGraceTime):
				logger.Printf("pipe establishing timeout, disconnected connection from %v", c.RemoteAddr())
				return
			}

			defer p.Close()

			if bigbro != nil {
				a, err := bigbro.Create(p.DownstreamConnMeta())
				if err != nil {
					logger.Printf("connection from %v failed to create auditor reason: %v", c.RemoteAddr(), err)
					return
				}
				defer a.Close()

				p.HookUpstreamMsg = a.GetUpstreamHook()
				p.HookDownstreamMsg = a.GetDownstreamHook()
			}

			err = p.Wait()
			logger.Printf("connection from %v closed reason: %v", c.RemoteAddr(), err)
		}(conn)
	}
}
