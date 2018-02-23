package main

import (
	"fmt"
	"io/ioutil"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/tg123/sshpiper/sshpiperd/auditor"
	"github.com/tg123/sshpiper/sshpiperd/challenger"
	"github.com/tg123/sshpiper/sshpiperd/registry"
	"github.com/tg123/sshpiper/sshpiperd/upstream"
)

type piperdConfig struct {
	ListenAddr   string `short:"l" long:"listen" description:"Listening Address" default:"0.0.0.0" env:"SSHPIPERD_LISTENADDR" ini-name:"listen-address"`
	Port         uint   `short:"p" long:"port" description:"Listening Port" default:"2222" env:"SSHPIPERD_PORT" ini-name:"listen-port"`
	PiperKeyFile string `short:"i" long:"server-key" description:"Server key file for SSH Piper" default:"/etc/ssh/ssh_host_rsa_key" env:"SSHPIPERD_SERVER_KEY" ini-name:"server-key"`

	UpstreamDriver   string `short:"u" long:"upstream-driver" description:"Upstream provider driver" default:"workingdir" env:"SSHPIPERD_UPSTREAM_DRIVER" ini-name:"upstream-driver"`
	ChallengerDriver string `short:"c" long:"challenger-driver" description:"Additional challenger name, e.g. pam, empty for no additional challenge" env:"SSHPIPERD_CHALLENGER" ini-name:"challenger-driver"`
	AuditorDriver    string `long:"auditor-driver" description:"Auditor for ssh connections piped by SSH Piper " env:"SSHPIPERD_AUDITOR" ini-name:"auditor-driver"`
}

func getAndInstall(name string, get func(n string) registry.Plugin, install func(plugin registry.Plugin) error) error {
	if name == "" {
		return nil
	}

	p := get(name)

	if p == nil {
		return fmt.Errorf("driver %v not found", name)
	}

	err := p.Init(logger)
	if err != nil {
		return err
	}
	return install(p)
}

func installDrivers(piper *ssh.SSHPiperConfig, config *piperdConfig) (auditor.Provider, error) {

	// install upstreamProvider driver
	if config.UpstreamDriver == "" {
		return nil, fmt.Errorf("must provider upstream driver")
	}

	var bigbro auditor.Provider

	for _, d := range []struct {
		name    string
		get     func(n string) registry.Plugin
		install func(plugin registry.Plugin) error
	}{
		// upstream driver
		{
			config.UpstreamDriver,
			func(n string) registry.Plugin {
				return upstream.Get(n)
			},
			func(plugin registry.Plugin) error {
				handler := plugin.(upstream.Provider).GetHandler()

				if handler == nil {
					return fmt.Errorf("driver return nil handler")
				}

				piper.FindUpstream = handler
				return nil
			},
		},
		// challenger driver
		{
			config.ChallengerDriver,
			func(n string) registry.Plugin {
				return challenger.Get(n)
			},
			func(plugin registry.Plugin) error {
				handler := plugin.(challenger.Provider).GetHandler()

				if handler == nil {
					return fmt.Errorf("driver return nil handler")
				}

				piper.AdditionalChallenge = handler
				return nil
			},
		},
		// auditor driver
		{
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
		err := getAndInstall(d.name, d.get, d.install)
		if err != nil {
			return nil, err
		}
	}

	return bigbro, nil
}

func startPiper(config *piperdConfig) error {

	logger.Println("sshpiper is about to start")

	piper := &ssh.SSHPiperConfig{}

	bigbro, err := installDrivers(piper, config)

	privateBytes, err := ioutil.ReadFile(config.PiperKeyFile)
	if err != nil {
		return err
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		return err
	}

	piper.AddHostKey(private)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.ListenAddr, config.Port))
	if err != nil {
		return fmt.Errorf("failed to listen for connection: %v", err)
	}
	defer listener.Close()

	logger.Printf("sshpiperd started")

	for {
		c, err := listener.Accept()
		if err != nil {
			logger.Printf("failed to accept connection: %v", err)
			continue
		}

		logger.Printf("connection accepted: %v", c.RemoteAddr())
		go func() {
			p, err := ssh.NewSSHPiperConn(c, piper)

			if err != nil {
				logger.Printf("connection from %v establishing failed reason: %v", c.RemoteAddr(), err)
				return
			}

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
		}()
	}

	return nil
}
