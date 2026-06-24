package e2e_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestSendEnv covers two env-variable flows through sshpiperd:
//
//  1. inject_env: the daemon's --inject-env flag injects KEY=VALUE pairs into
//     every upstream session before the shell/exec request (tests envinject.go
//     wired through the real sshpiperd binary).
//
//  2. client_send_env: the SSH client sends an "env" channel request via the
//     OpenSSH SetEnv client option; sshpiperd must proxy it transparently to
//     the upstream server.
//
// Both sub-tests write the received env value to /shared/<uuid> via a remote
// sh command and verify the file content.  host-password is used because its
// sshd_config.d already contains AcceptEnv SSHPIPER_*.
func TestSendEnv(t *testing.T) {
	t.Run("inject_env", func(t *testing.T) {
		piperaddr, piperport := nextAvailablePiperAddress()
		randtext := uuid.New().String()
		targetfile := uuid.New().String()

		piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
			"-p", piperport,
			"--inject-env", "SSHPIPER_E2E_INJECT="+randtext,
			"/sshpiperd/plugins/fixed",
			"--target", "host-password:2222",
		)
		if err != nil {
			t.Fatalf("failed to run sshpiperd: %v", err)
		}
		defer killCmd(piper)

		waitForEndpointReady(piperaddr)

		c, stdin, stdout, err := runCmd(
			"ssh",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-p", piperport,
			"-l", "user",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n $SSHPIPER_E2E_INJECT > /shared/%s"`, targetfile),
		)
		if err != nil {
			t.Fatalf("failed to ssh: %v", err)
		}
		defer killCmd(c)

		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for remote file flush

		checkSharedFileContent(t, targetfile, randtext)
	})

	t.Run("client_send_env", func(t *testing.T) {
		piperaddr, piperport := nextAvailablePiperAddress()
		randtext := uuid.New().String()
		targetfile := uuid.New().String()

		piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
			"-p", piperport,
			"/sshpiperd/plugins/fixed",
			"--target", "host-password:2222",
		)
		if err != nil {
			t.Fatalf("failed to run sshpiperd: %v", err)
		}
		defer killCmd(piper)

		waitForEndpointReady(piperaddr)

		// SetEnv is available in OpenSSH >= 8.7 and sets the env variable at
		// the SSH-protocol level without requiring it in the process environment.
		// sshpiperd must forward the "env" channel request transparently.
		c, stdin, stdout, err := runCmd(
			"ssh",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-o", "SetEnv=SSHPIPER_E2E_CLIENT="+randtext,
			"-p", piperport,
			"-l", "user",
			"127.0.0.1",
			fmt.Sprintf(`sh -c "echo -n $SSHPIPER_E2E_CLIENT > /shared/%s"`, targetfile),
		)
		if err != nil {
			t.Fatalf("failed to ssh: %v", err)
		}
		defer killCmd(c)

		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for remote file flush

		checkSharedFileContent(t, targetfile, randtext)
	})
}
