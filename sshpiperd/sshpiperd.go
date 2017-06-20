// Copyright 2014, 2015 tgic<farmer1992@gmail.com>. All rights reserved.
// this file is governed by MIT-license
//
// https://github.com/tg123/sshpiper

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"

	"github.com/tg123/sshpiper/ssh"
	"github.com/tg123/sshpiper/sshpiperd/challenger"
)

var (
	logger = log.New(os.Stdout, "", log.Ldate|log.Ltime)
)

func showHelpOrVersion() {
	if config.ShowHelp {
		showHelp()
		os.Exit(0)
	}

	if config.ShowVersion {
		os.Exit(0)
	}
}

func main() {
	initConfig()
	initTemplate()
	initLogger()

	showVersion()
	showHelpOrVersion()

	showConfig()

	// TODO make this pluggable
	piper := &ssh.SSHPiperConfig{
		FindUpstream:            findUpstreamFromUserfile,
		MapPublicKey:            mapPublicKeyFromUserfile,
		UpstreamHostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO should support by config
	}

	if config.Challenger != "" {
		ac, err := challenger.GetChallenger(config.Challenger)
		if err != nil {
			logger.Fatalln("failed to load challenger", err)
		}

		logger.Printf("using additional challenger %s", config.Challenger)
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

			if config.RecordTypescript {
				auditor, err := newFilePtyLogger(p.DownstreamConnMeta().User())

				if err != nil {
					logger.Printf("connection from %v failed to create auditor reason: %v", c.RemoteAddr(), err)
					return
				}

				defer auditor.Close()

				p.HookUpstreamMsg = auditor.loggingTty
			}

			err = p.Wait()
			logger.Printf("connection from %v closed reason: %v", c.RemoteAddr(), err)
		}()
	}
}
