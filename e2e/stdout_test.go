package e2e_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestStdoutPlugin verifies that a plugin which accidentally writes to stdout
// does not corrupt the stdin/stdout gRPC transport between sshpiperd and the
// plugin. The connection must succeed (no gRPC crash).
func TestStdoutPlugin(t *testing.T) {
	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd(
		"/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/teststdoutplugin",
		"--target",
		"host-password:2222",
	)
	if err != nil {
		t.Fatalf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	randtext := uuid.New().String()
	targetFile := uuid.New().String()

	c, stdin, stdout, err := runCmd(
		"ssh",
		"-v",
		"-o",
		"StrictHostKeyChecking=no",
		"-o",
		"UserKnownHostsFile=/dev/null",
		"-p",
		piperport,
		"-l",
		"user",
		"127.0.0.1",
		fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetFile),
	)
	if err != nil {
		t.Fatalf("failed to ssh to piper-teststdout, %v", err)
	}

	defer killCmd(c)

	enterPassword(stdin, stdout, "pass")

	time.Sleep(time.Second * 3) // wait for file flush

	checkSharedFileContent(t, targetFile, randtext)
}
