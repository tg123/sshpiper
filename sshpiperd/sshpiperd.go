// Copyright 2014, 2015 tgic<farmer1992@gmail.com>. All rights reserved.
// this file is governed by MIT-license
//
// https://github.com/tg123/sshpiper

package main

import (
	"flag"
	"fmt"
	"github.com/tg123/sshpiper/ssh"
	"github.com/tg123/sshpiper/sshpiperd/challenger"
	"io/ioutil"
	"log"
	"net"
	"os"
)

var (
	ListenAddr   string
	Port         uint
	WorkingDir   string
	PiperKeyFile string
	ShowHelp     bool
	Challenger   string

	logger = log.New(os.Stdout, "", log.Ldate|log.Ltime)
)

func init() {
	flag.StringVar(&ListenAddr, "l", "0.0.0.0", "Listening Address")
	flag.UintVar(&Port, "p", 2222, "Listening Port")
	flag.StringVar(&WorkingDir, "w", "/var/sshpiper", "Working Dir")
	flag.StringVar(&PiperKeyFile, "i", "/etc/ssh/ssh_host_rsa_key", "Key file for SSH Piper")
	flag.StringVar(&Challenger, "c", "", "Additional challenger name, e.g. pam, emtpy for no additional challenge")
	flag.BoolVar(&ShowHelp, "h", false, "Print help and exit")
	flag.Parse()
}

func main() {

	if ShowHelp {
		flag.PrintDefaults()
		return
	}

	// TODO make this pluggable
	piper := &ssh.SSHPiperConfig{
		FindUpstream: findUpstreamFromUserfile,
		MapPublicKey: mapPublicKeyFromUserfile,
	}

	if Challenger != "" {
		ac, err := challenger.GetChallenger(Challenger)
		if err != nil {
			logger.Fatalln(err)
		}

		logger.Printf("using additional challenger %s", Challenger)
		piper.AdditionalChallenge = ac
	}

	privateBytes, err := ioutil.ReadFile(PiperKeyFile)
	if err != nil {
		logger.Fatalln(err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		logger.Fatalln(err)
	}

	piper.AddHostKey(private)

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", ListenAddr, Port))
	if err != nil {
		logger.Fatalln("failed to listen for connection")
	}
	defer listener.Close()

	logger.Printf("listening at %s:%d, server key file %s, working dir %s", ListenAddr, Port, PiperKeyFile, WorkingDir)

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

			err = p.Wait()
			logger.Printf("connection from %v closed reason: %v", c.RemoteAddr(), err)
		}()
	}
}
