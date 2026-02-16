//go:build full || e2e

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/docker-sshd/pkg/bridge"
	"github.com/tg123/docker-sshd/pkg/dockersshd"
	"golang.org/x/crypto/ssh"
)

const (
	dockerSshdCmdToken     = "__sshpiper_dockersshd_default_cmd__"
	defaultDockerSshdShell = "/bin/sh"
)

func (p *plugin) setupDockerSshdBridge(containerID string, privateKeyBase64, cmd string) (string, string, error) {
	var err error
	if privateKeyBase64 == "" {
		privateKeyBase64, err = generateDockerSshdPrivateKey()
		if err != nil {
			return "", "", err
		}
	}

	priv, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return "", "", err
	}

	signer, err := ssh.ParsePrivateKey(priv)
	if err != nil {
		return "", "", err
	}

	pubKey := signer.PublicKey().Marshal()

	var listener net.Listener
	var addr string

	p.dockerSshdMu.Lock()
	if p.dockerSshdBridgeAddr == "" {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			p.dockerSshdMu.Unlock()
			return "", "", err
		}
		p.dockerSshdBridgeAddr = listener.Addr().String()
	}

	addr = p.dockerSshdBridgeAddr
	p.dockerSshdKeys[containerID] = pubKey
	p.dockerSshdKeyToContainer[string(pubKey)] = containerID
	if cmd != "" {
		p.dockerSshdCmds[containerID] = cmd
	}
	p.dockerSshdMu.Unlock()

	if listener != nil {
		go p.startDockerSshdBridge(listener)
	}

	return addr, privateKeyBase64, nil
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

	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			p.dockerSshdMu.Lock()
			containerID, ok := p.dockerSshdKeyToContainer[string(key.Marshal())]
			cmd := p.dockerSshdCmd(containerID)
			p.dockerSshdMu.Unlock()

			if !ok {
				return nil, fmt.Errorf("unexpected public key for docker-sshd upstream")
			}

			return &ssh.Permissions{
				Extensions: map[string]string{
					"container_id": containerID,
					"default_cmd":  cmd,
				},
			}, nil
		},
	}
	serverConfig.AddHostKey(hostSigner)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Warnf("docker-sshd local bridge accept error: %v", err)
			return
		}

		go func(conn net.Conn) {
			b, err := bridge.New(conn, serverConfig, &bridge.BridgeConfig{
				DefaultCmd: dockerSshdCmdToken,
			}, func(sc *ssh.ServerConn) (bridge.SessionProvider, error) {
				if sc.Permissions == nil {
					return nil, fmt.Errorf("missing ssh permissions for docker-sshd bridge")
				}

				containerID := sc.Permissions.Extensions["container_id"]
				if containerID == "" {
					return nil, fmt.Errorf("missing container_id in ssh permissions")
				}
				defaultCmd := sc.Permissions.Extensions["default_cmd"]
				provider, err := dockersshd.New(p.dockerCli, containerID)
				if err != nil {
					return nil, err
				}

				return &dockerSshdSessionProvider{
					SessionProvider: provider,
					defaultCmd:      defaultCmd,
				}, nil
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

type dockerSshdSessionProvider struct {
	bridge.SessionProvider
	defaultCmd string
}

func (d *dockerSshdSessionProvider) Exec(ctx context.Context, execconfig bridge.ExecConfig) (<-chan bridge.ExecResult, error) {
	if len(execconfig.Cmd) == 1 && execconfig.Cmd[0] == dockerSshdCmdToken {
		// bridge passes DefaultCmd for shell requests; mutate command to the real container default command.
		if d.defaultCmd == "" {
			execconfig.Cmd = []string{defaultDockerSshdShell}
		} else {
			execconfig.Cmd = []string{defaultDockerSshdShell, "-c", d.defaultCmd}
		}
	}

	return d.SessionProvider.Exec(ctx, execconfig)
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
