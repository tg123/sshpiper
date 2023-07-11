package e2e_test

import (
	"io"
	"strings"
	"testing"
)

func TestFailtoban(t *testing.T) {
	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/fixed",
		"--target",
		"host-password:2222",
		"--",
		"/sshpiperd/plugins/failtoban",
		"--max-failures",
		"3",
	)

	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	// run 3 times with wrong password
	{
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
		)
		if err != nil {
			t.Errorf("failed to ssh to piper-fixed, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "wrongpass1")
		enterPassword(stdin, stdout, "wrongpass2")
		enterPassword(stdin, stdout, "wrongpass3")
	}

	{
		c, _, stdout, err := runCmd(
			"ssh",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"user",
			"127.0.0.1",
		)

		if err != nil {
			t.Errorf("failed to ssh to piper-fixed, %v", err)
		}

		defer killCmd(c)
		_ = c.Wait()

		s, _ := io.ReadAll(stdout)

		if !strings.Contains(string(s), "Connection closed by 127.0.0.1") {
			t.Errorf("expected connection closed by")
		}
	}

}
