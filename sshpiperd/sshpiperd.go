package main

import (
	"fmt"
	"io/ioutil"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/tg123/sshpiper/sshpiperd/challenger"
	"github.com/tg123/sshpiper/sshpiperd/upstream"
)

type piperdConfig struct {
	ListenAddr   string `short:"l" long:"listen" description:"Listening Address" default:"0.0.0.0" env:"SSHPIPERD_LISTENADDR" ini-name:"listen-address"`
	Port         uint   `short:"p" long:"port" description:"Listening Port" default:"2222" env:"SSHPIPERD_PORT" ini-name:"listen-port"`
	PiperKeyFile string `short:"i" long:"server-key" description:"Server key file for SSH Piper" default:"/etc/ssh/ssh_host_rsa_key" env:"SSHPIPERD_SERVER_KEY" ini-name:"server-key"`

	UpstreamDriver   string `short:"d" long:"upstream-driver" description:"Upstream provider driver" default:"workingdir" env:"SSHPIPERD_UPSTREAM_DRIVER"`
	ChallengerDriver string `short:"c" long:"challenger-driver" description:"Additional challenger name, e.g. pam, empty for no additional challenge" env:"SSHPIPERD_CHALLENGER"`
}

func startPiper(config *piperdConfig) {

	logger.Println("sshpiper is about to start")

	// init upstream
	upstream := upstream.Get(config.UpstreamDriver)
	if upstream == nil {
		logger.Fatal("upstream driver %v not found", config.UpstreamDriver)
	}
	upstream.Init(logger)

	piper := &ssh.SSHPiperConfig{
		FindUpstream: upstream.GetFindUpstreamHandle(),
	}

	// TODO move to plugin
	if config.ChallengerDriver != "" {
		ac, err := challenger.GetChallenger(config.ChallengerDriver)
		if err != nil {
			logger.Fatalln("failed to load challenger", err)
		}

		logger.Printf("using additional challenger %s", config.ChallengerDriver)
		piper.AdditionalChallenge = ac
	}

	privateBytes, err := ioutil.ReadFile(config.PiperKeyFile)
	if err != nil {
		logger.Fatalln(err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		logger.Fatalln(err)
	}

	piper.AddHostKey(private)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.ListenAddr, config.Port))
	if err != nil {
		logger.Fatalln("failed to listen for connection: %v", err)
	}
	defer listener.Close()

	logger.Printf("SSHPiperd started")

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

			//if config.RecordTypescript {
			//	auditor, err := newFilePtyLogger(p.DownstreamConnMeta().User())

			//	if err != nil {
			//		logger.Printf("connection from %v failed to create auditor reason: %v", c.RemoteAddr(), err)
			//		return
			//	}

			//	defer auditor.Close()

			//	p.HookUpstreamMsg = auditor.loggingTty
			//}

			err = p.Wait()
			logger.Printf("connection from %v closed reason: %v", c.RemoteAddr(), err)
		}()
	}
}
