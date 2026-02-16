//go:build full || e2e

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/docker-sshd/pkg/bridge"
	"golang.org/x/crypto/ssh"
)

const (
	dockerExecInspectTimeout       = 10 * time.Second
	dockerExecInspectRetryInterval = 100 * time.Millisecond
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
				return &dockerSshdSessionProvider{
					containerID: containerID,
					dockerCli:   p.dockerCli,
				}, nil
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

type dockerSshdSessionProvider struct {
	containerID string
	dockerCli   dockerExecClient
	execID      string
	initSize    bridge.ResizeOptions
}

type dockerExecClient interface {
	ContainerExecCreate(ctx context.Context, container string, options container.ExecOptions) (container.ExecCreateResponse, error)
	ContainerExecAttach(ctx context.Context, execID string, config container.ExecAttachOptions) (types.HijackedResponse, error)
	ContainerExecInspect(ctx context.Context, execID string) (container.ExecInspect, error)
	ContainerExecResize(ctx context.Context, execID string, options container.ResizeOptions) error
}

func (d *dockerSshdSessionProvider) Exec(ctx context.Context, execconfig bridge.ExecConfig) (<-chan bridge.ExecResult, error) {
	initialSize := d.initSize
	if initialSize.Width == 0 || initialSize.Height == 0 {
		initialSize = bridge.ResizeOptions{
			Width:  80,
			Height: 24,
		}
	}

	exec, err := d.dockerCli.ContainerExecCreate(ctx, d.containerID, container.ExecOptions{
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: !execconfig.Tty, // stderr is already merged in tty mode
		Tty:          execconfig.Tty,
		Env:          execconfig.Env,
		Cmd:          execconfig.Cmd,
		ConsoleSize:  &[2]uint{initialSize.Height, initialSize.Width},
	})
	if err != nil {
		return nil, err
	}

	d.execID = exec.ID
	attach, err := d.dockerCli.ContainerExecAttach(ctx, d.execID, container.ExecAttachOptions{
		Tty: execconfig.Tty,
	})
	if err != nil {
		return nil, err
	}

	r := make(chan bridge.ExecResult, 1)
	go func() {
		defer attach.Close()

		done := make(chan error, 1)
		go func() {
			_, err := io.Copy(execconfig.Output, attach.Reader)
			done <- err
		}()
		go func() {
			_, _ = io.Copy(attach.Conn, execconfig.Input)
		}()

		var ioErr error
		select {
		case ioErr = <-done:
		case <-ctx.Done():
			r <- bridge.ExecResult{ExitCode: -1, Error: ctx.Err()}
			return
		}

		exitCode := -1
		st := time.Now()
		for {
			select {
			case <-ctx.Done():
				r <- bridge.ExecResult{ExitCode: -1, Error: ctx.Err()}
				return
			default:
			}

			if time.Since(st) > dockerExecInspectTimeout {
				break
			}

			exec, err := d.dockerCli.ContainerExecInspect(ctx, d.execID)
			if err != nil {
				time.Sleep(dockerExecInspectRetryInterval)
				continue
			}
			if exec.Running {
				time.Sleep(dockerExecInspectRetryInterval)
				continue
			}
			exitCode = exec.ExitCode
			break
		}

		if exitCode == 0 && errors.Is(ioErr, io.EOF) {
			ioErr = nil
		}

		r <- bridge.ExecResult{ExitCode: exitCode, Error: ioErr}
	}()

	return r, nil
}

func (d *dockerSshdSessionProvider) Resize(ctx context.Context, size bridge.ResizeOptions) error {
	if d.execID == "" {
		d.initSize = size
		return nil
	}

	return d.dockerCli.ContainerExecResize(ctx, d.execID, container.ResizeOptions{
		Height: size.Height,
		Width:  size.Width,
	})
}
