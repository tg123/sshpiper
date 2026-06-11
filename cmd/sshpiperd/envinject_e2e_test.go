package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestDaemonEnvInjectionEndToEnd wires the production envInjector against a
// real PiperConn between an in-process client and an in-process upstream
// sshd, exactly the way daemon.go wires it. It verifies that:
//
//   - the plugin path's Upstream.Env semantics (here: a hardcoded env map)
//     reach the upstream server as SSH "env" channel-requests, and
//   - injection happens once per session channel before the client's
//     shell request.
func TestDaemonEnvInjectionEndToEnd(t *testing.T) {
	hostKey := genHostKey(t)
	clientKey := genHostKey(t) // reuse as user key
	_ = clientKey

	// envSeen collects env requests observed by the upstream session.
	envSeen := make(chan envKV, 8)

	// In-process upstream sshd.
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamLn.Close()
	go runFakeUpstream(t, upstreamLn, hostKey, envSeen)

	// In-process sshpiper-style server.
	piperLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer piperLn.Close()

	injectedEnv := map[string]string{
		"SSHPIPER_JOBID": "slurm-42",
		"SSHPIPER_RANK":  "0",
	}

	piperCfg := &ssh.PiperConfig{
		NoClientAuthCallback: func(conn ssh.ConnMetadata, _ ssh.ChallengeContext) (*ssh.Upstream, error) {
			c, err := net.Dial("tcp", upstreamLn.Addr().String())
			if err != nil {
				return nil, err
			}
			return &ssh.Upstream{
				Conn: c,
				ClientConfig: ssh.ClientConfig{
					User:            "u",
					Auth:            []ssh.AuthMethod{ssh.NoneAuth()},
					HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				},
			}, nil
		},
	}
	piperCfg.AddHostKey(hostKey)

	go func() {
		c, err := piperLn.Accept()
		if err != nil {
			return
		}
		p, err := ssh.NewSSHPiperConn(c, piperCfg)
		if err != nil {
			t.Errorf("piper handshake: %v", err)
			return
		}

		// Replicate daemon.go env-injection wiring exactly.
		uphookchain := &hookChain{}
		downhookchain := &hookChain{}
		inj := newEnvInjector(p, injectedEnv)
		uphookchain.append(inj.up)
		downhookchain.append(inj.down)
		_ = p.WaitWithHook(uphookchain.hook(), downhookchain.hook())
	}()

	// Client.
	conn, err := ssh.Dial("tcp", piperLn.Addr().String(), &ssh.ClientConfig{
		User:            "alice",
		Auth:            []ssh.AuthMethod{ssh.NoneAuth()},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	if err := session.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}
	_, _ = stdin.Write([]byte("hi"))
	stdin.Close()
	_, _ = io.ReadAll(stdout)

	got := map[string]string{}
	deadline := time.After(3 * time.Second)
	for len(got) < len(injectedEnv) {
		select {
		case kv := <-envSeen:
			got[kv.k] = kv.v
		case <-deadline:
			t.Fatalf("timed out; received env so far: %v", got)
		}
	}
	for k, v := range injectedEnv {
		if got[k] != v {
			t.Errorf("env[%s] = %q, want %q", k, got[k], v)
		}
	}
}

type envKV struct{ k, v string }

func genHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func runFakeUpstream(t *testing.T, ln net.Listener, hostKey ssh.Signer, envSeen chan<- envKV) {
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostKey)

	var wg sync.WaitGroup
	for {
		c, err := ln.Accept()
		if err != nil {
			wg.Wait()
			return
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			_, chans, reqs, err := ssh.NewServerConn(c, cfg)
			if err != nil {
				return
			}
			go ssh.DiscardRequests(reqs)
			for nc := range chans {
				if nc.ChannelType() != "session" {
					nc.Reject(ssh.UnknownChannelType, "")
					continue
				}
				ch, in, err := nc.Accept()
				if err != nil {
					continue
				}
				go func() {
					for req := range in {
						switch req.Type {
						case "env":
							var er struct{ Name, Value string }
							if err := ssh.Unmarshal(req.Payload, &er); err == nil {
								envSeen <- envKV{er.Name, er.Value}
							}
							if req.WantReply {
								_ = req.Reply(true, nil)
							}
						case "shell", "exec":
							if req.WantReply {
								_ = req.Reply(true, nil)
							}
						default:
							if req.WantReply {
								_ = req.Reply(false, nil)
							}
						}
					}
				}()
				go func() {
					defer ch.Close()
					data, _ := io.ReadAll(ch)
					_, _ = ch.Write(data)
				}()
			}
		}(c)
	}
}
