package e2e_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestConnMeta(t *testing.T) {
	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/testsetmetaplugin",
		"--targetaddr",
		"host-password:2222",
		"--",
		"/sshpiperd/plugins/testgetmetaplugin",
	)

	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	randtext := uuid.New().String()
	targetfie := uuid.New().String()

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
		fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
	)

	if err != nil {
		t.Errorf("failed to ssh to piper-fixed, %v", err)
	}

	defer killCmd(c)

	enterPassword(stdin, stdout, "pass")

	time.Sleep(time.Second) // wait for file flush

	checkSharedFileContent(t, targetfie, randtext)
}
