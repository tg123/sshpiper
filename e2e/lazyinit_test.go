package e2e_test

import (
	crand "crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/tg123/sshpiper/libplugin"
	"google.golang.org/grpc"
)

// TestLazyPluginInit tests lazy plugin initialization.
//
// It checks that:
//  1. sshpiperd starts even when the plugin isn't running
//  2. Once the plugin starts, SSH connections succeed
func TestLazyPluginInit(t *testing.T) {
	// Reserve a port for the plugin server (but don't start it yet)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve plugin port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // close it so the initial connection will fail

	piperaddr, piperport := nextAvailablePiperAddress()

	// sshpiperd should start, even though the plugin isn't running.
	piper, _, stdout, err := runCmd("/sshpiperd/sshpiperd",
		"-p", piperport,
		"grpc",
		"--endpoint", addr,
		"--insecure",
	)
	if err != nil {
		t.Fatalf("failed to run sshpiperd: %v", err)
	}
	t.Cleanup(func() { killCmd(piper) })

	waitForStdoutContains(stdout, "listening", func(_ string) {})
	waitForEndpointReady(piperaddr)

	// Now start the plugin.
	ln, err = net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("failed to start plugin server: %v", err)
	}
	defer ln.Close()

	grpcServer := grpc.NewServer()
	plugin, err := libplugin.NewFromGrpc(libplugin.SshPiperPluginConfig{
		PasswordCallback: func(conn libplugin.ConnMetadata, password []byte) (*libplugin.Upstream, error) {
			return &libplugin.Upstream{
				Host:          "host-password",
				Port:          2222,
				IgnoreHostKey: true,
				Auth:          libplugin.CreatePasswordAuth(password),
			}, nil
		},
	}, grpcServer, ln)
	if err != nil {
		t.Fatalf("failed to create plugin: %v", err)
	}

	go plugin.Serve()
	t.Cleanup(grpcServer.Stop)
	waitForEndpointReady(addr)

	// Wait for gRPC client to reconnect (backoff is ~1s)
	time.Sleep(time.Second)

	// SSH connection should succeed
	randtext := crand.Text()
	targetfile := crand.Text()
	c, stdin, stdout2, err := runCmd(
		"ssh",
		"-v",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-p", piperport,
		"-l", "user",
		"127.0.0.1",
		fmt.Sprintf(`echo -n %v > /shared/%v`, randtext, targetfile),
	)
	if err != nil {
		t.Fatalf("failed to ssh to piper: %v", err)
	}
	t.Cleanup(func() { killCmd(c) })

	enterPassword(stdin, stdout2, "pass")
	if err := c.Wait(); err != nil {
		t.Fatalf("ssh command failed: %v", err)
	}

	time.Sleep(time.Second)
	checkSharedFileContent(t, targetfile, randtext)
}
