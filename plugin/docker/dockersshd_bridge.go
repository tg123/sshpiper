//go:build full || e2e

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/docker-sshd/pkg/bridge"
	"github.com/tg123/docker-sshd/pkg/dockersshd"
	"golang.org/x/crypto/ssh"
)

const (
	defaultDockerSshdShell = "/bin/sh"
)

func (p *plugin) ensureDockerSshdBridge() (string, error) {
	p.dockerSshdMu.Lock()
	addr := p.dockerSshdBridgeAddr
	p.dockerSshdMu.Unlock()

	if addr != "" {
		return addr, nil
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}

	addr = listener.Addr().String()

	p.dockerSshdMu.Lock()
	if p.dockerSshdBridgeAddr == "" {
		p.dockerSshdBridgeAddr = addr
		p.dockerSshdMu.Unlock()
		go p.startDockerSshdBridge(listener)
		return addr, nil
	}

	addr = p.dockerSshdBridgeAddr
	p.dockerSshdMu.Unlock()
	_ = listener.Close()
	return addr, nil
}

func (p *plugin) registerDockerSshdContainer(containerID, cmd string) (string, error) {
	privateKeyBase64, err := generateDockerSshdPrivateKey()
	if err != nil {
		return "", err
	}

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
	p.dockerSshdKeys[containerID] = pubKey
	p.dockerSshdKeyToContainer[string(pubKey)] = containerID
	if cmd != "" {
		p.dockerSshdCmds[containerID] = cmd
	}
	p.dockerSshdMu.Unlock()

	return privateKeyBase64, nil
}

func (p *plugin) startDockerSshdBridge(listener net.Listener) {
	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Warnf("failed to generate docker-sshd host key: %v", err)
		return
	}

	hostSigner, err := ssh.NewSignerFromKey(hostPrivateKey)
	if err != nil {
		log.Warnf("failed to create docker-sshd host signer: %v", err)
		return
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Warnf("docker-sshd local bridge accept error: %v", err)
			return
		}

		go func(conn net.Conn) {
			selectedContainerID := ""
			stateMu := sync.Mutex{}
			bridgeConfig := &bridge.BridgeConfig{
				DefaultCmd: defaultDockerSshdShell,
			}

			serverConfig := &ssh.ServerConfig{
				PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
					p.dockerSshdMu.Lock()
					defer p.dockerSshdMu.Unlock()

					containerID, ok := p.dockerSshdKeyToContainer[string(key.Marshal())]
					if !ok {
						return nil, fmt.Errorf("unexpected public key for docker-sshd upstream")
					}

					cmd := p.dockerSshdCmds[containerID]
					if cmd == "" {
						cmd = defaultDockerSshdShell
					}

					stateMu.Lock()
					selectedContainerID = containerID
					bridgeConfig.DefaultCmd = cmd
					stateMu.Unlock()
					return nil, nil
				},
			}
			serverConfig.AddHostKey(hostSigner)

			b, err := bridge.New(conn, serverConfig, bridgeConfig, func(sc *ssh.ServerConn) (bridge.SessionProvider, error) {
				stateMu.Lock()
				containerID := selectedContainerID
				stateMu.Unlock()

				if containerID == "" {
					return nil, fmt.Errorf("missing container_id for docker-sshd bridge")
				}

				provider, err := dockersshd.New(p.dockerCli, containerID)
				if err != nil {
					return nil, err
				}
				return provider, nil
			})
			if err != nil {
				log.Warnf("failed to establish docker-sshd bridge: %v", err)
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
		return defaultDockerSshdShell
	}
	return cmd
}

func generateDockerSshdPrivateKey() (string, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return "", err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	return base64.StdEncoding.EncodeToString(pemBytes), nil
}
