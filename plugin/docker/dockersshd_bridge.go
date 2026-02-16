//go:build full || e2e

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/docker-sshd/pkg/bridge"
	"github.com/tg123/docker-sshd/pkg/dockersshd"
	"golang.org/x/crypto/ssh"
)

func (p *plugin) dockerSshdAddr(containerID string, privateKeyBase64, cmd string) (string, error) {
	priv, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return "", err
	}

	signer, err := ssh.ParsePrivateKey(priv)
	if err != nil {
		return "", err
	}

	pubKey := signer.PublicKey().Marshal()

	p.dockerSshdMu.Lock()
	addr, ok := p.dockerSshdAddrs[containerID]
	p.dockerSshdMu.Unlock()
	if ok {
		return addr, nil
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}

	addr = listener.Addr().String()

	p.dockerSshdMu.Lock()
	p.dockerSshdAddrs[containerID] = addr
	p.dockerSshdKeys[containerID] = pubKey
	if cmd != "" {
		p.dockerSshdCmds[containerID] = cmd
	}
	p.dockerSshdMu.Unlock()

	go p.startDockerSshdBridge(containerID, listener)

	return addr, nil
}

func (p *plugin) startDockerSshdBridge(containerID string, listener net.Listener) {
	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Warnf("failed to generate docker-sshd host key for %s: %v", containerID, err)
		return
	}

	hostSigner, err := ssh.NewSignerFromKey(hostPrivateKey)
	if err != nil {
		log.Warnf("failed to create docker-sshd host signer for %s: %v", containerID, err)
		return
	}

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			p.dockerSshdMu.Lock()
			allowed := p.dockerSshdKeys[containerID]
			p.dockerSshdMu.Unlock()

			if subtle.ConstantTimeCompare(allowed, key.Marshal()) != 1 {
				return nil, fmt.Errorf("unexpected public key for docker-sshd upstream")
			}

			return nil, nil
		},
	}
	serverConfig.AddHostKey(hostSigner)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Warnf("docker-sshd local bridge accept error for %s: %v", containerID, err)
			return
		}

		go func(conn net.Conn) {
			b, err := bridge.New(conn, serverConfig, &bridge.BridgeConfig{
				DefaultCmd: p.dockerSshdCmd(containerID),
			}, func(sc *ssh.ServerConn) (bridge.SessionProvider, error) {
				return dockersshd.New(p.dockerCli, containerID)
			})
			if err != nil {
				log.Warnf("failed to establish docker-sshd bridge for %s: %v", containerID, err)
				_ = conn.Close()
				return
			}

			b.Start()
		}(conn)
	}
}

func (p *plugin) dockerSshdCmd(containerID string) string {
	p.dockerSshdMu.Lock()
	cmd := p.dockerSshdCmds[containerID]
	p.dockerSshdMu.Unlock()
	if cmd == "" {
		return "/bin/sh"
	}
	return cmd
}
