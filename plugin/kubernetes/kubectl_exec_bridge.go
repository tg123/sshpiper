package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tg123/docker-sshd/pkg/bridge"
	"github.com/tg123/docker-sshd/pkg/kubesshd"
	piperv1beta1 "github.com/tg123/sshpiper/plugin/kubernetes/apis/sshpiper/v1beta1"
	"golang.org/x/crypto/ssh"
)

const (
	defaultKubectlExecShell = "/bin/sh"
)

type kubectlExecTarget struct {
	Namespace string
	Pod       string
	Container string
	Default   string
}

func kubectlExecPipeKey(pipe *piperv1beta1.Pipe) string {
	return fmt.Sprintf("%s/%s", pipe.Namespace, pipe.Name)
}

func isKubectlExecEnabled(pipe *piperv1beta1.Pipe) bool {
	anno := pipe.GetAnnotations()
	return strings.EqualFold(anno["sshpiper.com/kubectl_exec_cmd"], "true") || strings.EqualFold(anno["kubectl_exec_cmd"], "true")
}

func parseKubectlExecTarget(pipe *piperv1beta1.Pipe, to *piperv1beta1.ToSpec) (kubectlExecTarget, error) {
	anno := pipe.GetAnnotations()
	target := kubectlExecTarget{
		Namespace: pipe.Namespace,
		Default:   defaultKubectlExecShell,
	}

	if cmd := anno["sshpiper.com/kubectl_sshd_cmd"]; cmd != "" {
		target.Default = cmd
	} else if cmd := anno["kubectl_sshd_cmd"]; cmd != "" {
		target.Default = cmd
	}

	host := to.Host
	parts := strings.Split(host, "/")
	switch len(parts) {
	case 1:
		target.Pod = parts[0]
	case 2:
		target.Pod = parts[0]
		target.Container = parts[1]
	case 3:
		target.Namespace = parts[0]
		target.Pod = parts[1]
		target.Container = parts[2]
	default:
		return kubectlExecTarget{}, fmt.Errorf("invalid kubectl exec host format: %v", host)
	}

	if target.Pod == "" {
		return kubectlExecTarget{}, fmt.Errorf("empty pod in kubectl exec host: %v", host)
	}

	return target, nil
}

func (p *plugin) ensureKubectlExecBridge() (string, error) {
	p.kubeExecMu.Lock()
	addr := p.kubeExecBridgeAddr
	p.kubeExecMu.Unlock()
	if addr != "" {
		return addr, nil
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr = listener.Addr().String()

	p.kubeExecMu.Lock()
	if p.kubeExecBridgeAddr == "" {
		p.kubeExecBridgeAddr = addr
		p.kubeExecMu.Unlock()
		go p.startKubectlExecBridge(listener)
		return addr, nil
	}

	addr = p.kubeExecBridgeAddr
	p.kubeExecMu.Unlock()
	_ = listener.Close()
	return addr, nil
}

func (p *plugin) registerKubectlExecPipe(pipe *piperv1beta1.Pipe, to *piperv1beta1.ToSpec) (string, string, error) {
	target, err := parseKubectlExecTarget(pipe, to)
	if err != nil {
		return "", "", err
	}

	pipeKey := kubectlExecPipeKey(pipe)
	p.kubeExecMu.Lock()
	if privateKeyBase64 := p.kubeExecPrivateKeys[pipeKey]; privateKeyBase64 != "" {
		publicKey := p.kubeExecPipeToKey[pipeKey]
		p.kubeExecTargets[publicKey] = target
		p.kubeExecMu.Unlock()

		addr, err := p.ensureKubectlExecBridge()
		return privateKeyBase64, addr, err
	}
	p.kubeExecMu.Unlock()

	privateKeyBase64, err := generateKubectlExecPrivateKey()
	if err != nil {
		return "", "", err
	}

	priv, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return "", "", err
	}
	signer, err := ssh.ParsePrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	publicKey := string(signer.PublicKey().Marshal())

	p.kubeExecMu.Lock()
	if existing := p.kubeExecPrivateKeys[pipeKey]; existing != "" {
		publicKey = p.kubeExecPipeToKey[pipeKey]
		p.kubeExecTargets[publicKey] = target
		p.kubeExecMu.Unlock()

		addr, err := p.ensureKubectlExecBridge()
		return existing, addr, err
	}
	p.kubeExecPrivateKeys[pipeKey] = privateKeyBase64
	p.kubeExecPipeToKey[pipeKey] = publicKey
	p.kubeExecTargets[publicKey] = target
	p.kubeExecMu.Unlock()

	addr, err := p.ensureKubectlExecBridge()
	return privateKeyBase64, addr, err
}

func (p *plugin) syncKubectlExecState(pipes []*piperv1beta1.Pipe) {
	enabledPipes := make(map[string]*piperv1beta1.Pipe, len(pipes))
	for _, pipe := range pipes {
		if !isKubectlExecEnabled(pipe) {
			continue
		}
		enabledPipes[kubectlExecPipeKey(pipe)] = pipe
	}

	p.kubeExecMu.Lock()
	defer p.kubeExecMu.Unlock()

	for pipeKey, publicKey := range p.kubeExecPipeToKey {
		pipe := enabledPipes[pipeKey]
		if pipe == nil {
			delete(p.kubeExecPipeToKey, pipeKey)
			delete(p.kubeExecPrivateKeys, pipeKey)
			delete(p.kubeExecTargets, publicKey)
			continue
		}

		target, err := parseKubectlExecTarget(pipe, &pipe.Spec.To)
		if err != nil {
			log.Warnf("failed to parse kubectl-exec target for pipe %v: %v", pipeKey, err)
			delete(p.kubeExecPipeToKey, pipeKey)
			delete(p.kubeExecPrivateKeys, pipeKey)
			delete(p.kubeExecTargets, publicKey)
			continue
		}

		p.kubeExecTargets[publicKey] = target
	}
}

func (p *plugin) startKubectlExecBridge(listener net.Listener) {
	cleanup := func() {
		p.kubeExecMu.Lock()
		p.kubeExecBridgeAddr = ""
		p.kubeExecMu.Unlock()
		_ = listener.Close()
	}

	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Errorf("failed to generate kubectl-exec host key: %v", err)
		cleanup()
		return
	}

	hostSigner, err := ssh.NewSignerFromKey(hostPrivateKey)
	if err != nil {
		log.Errorf("failed to create kubectl-exec host signer: %v", err)
		cleanup()
		return
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			if err == net.ErrClosed {
				log.Errorf("kubectl-exec bridge listener closed: %v", err)
				cleanup()
				return
			}
			log.Warnf("kubectl-exec bridge accept error (retrying): %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		go func(conn net.Conn) {
			selected := kubectlExecTarget{}
			bridgeConfig := &bridge.BridgeConfig{
				DefaultCmd: defaultKubectlExecShell,
			}
			serverConfig := &ssh.ServerConfig{
				PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
					p.kubeExecMu.Lock()
					target, ok := p.kubeExecTargets[string(key.Marshal())]
					p.kubeExecMu.Unlock()
					if !ok {
						return nil, fmt.Errorf("unexpected public key for kubectl-exec bridge")
					}

					selected = target
					bridgeConfig.DefaultCmd = target.Default
					return nil, nil
				},
			}
			serverConfig.AddHostKey(hostSigner)

			b, err := bridge.New(conn, serverConfig, bridgeConfig, func(_ *ssh.ServerConn) (bridge.SessionProvider, error) {
				if selected.Pod == "" {
					return nil, fmt.Errorf("missing pod for kubectl-exec bridge")
				}
				return kubesshd.New(p.kubeCfg, selected.Namespace, selected.Pod, selected.Container)
			})
			if err != nil {
				log.Warnf("failed to establish kubectl-exec bridge: %v", err)
				_ = conn.Close()
				return
			}

			b.Start()
		}(conn)
	}
}

func generateKubectlExecPrivateKey() (string, error) {
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
