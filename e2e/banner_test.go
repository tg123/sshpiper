package e2e_test

import (
	"os"
	"testing"

	"github.com/google/uuid"
)

func TestBanner(t *testing.T) {

	t.Run("args", func(t *testing.T) {
		piperaddr, piperport := nextAvailablePiperAddress()
		randtext := uuid.New().String()

		piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
			"--banner-text",
			randtext,
			"-p",
			piperport,
			"/sshpiperd/plugins/fixed",
			"--target",
			"host-password:2222",
		)

		if err != nil {
			t.Errorf("failed to run sshpiperd: %v", err)
		}

		defer killCmd(piper)

		waitForEndpointReady(piperaddr)

		c, _, stdout, err := runCmd(
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
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		waitForStdoutContains(stdout, randtext, func(_ string) {
		})
	})

	t.Run("file", func(t *testing.T) {

		piperaddr, piperport := nextAvailablePiperAddress()
		randtext := uuid.New().String()

		bannerfile, err := os.CreateTemp("", "banner")
		if err != nil {
			t.Errorf("failed to create temp file: %v", err)
		}
		defer os.Remove(bannerfile.Name())

		if _, err := bannerfile.WriteString(randtext); err != nil {
			t.Errorf("failed to write to temp file: %v", err)
		}

		if err := bannerfile.Close(); err != nil {
			t.Errorf("failed to close temp file: %v", err)
		}

		piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
			"--banner-file",
			bannerfile.Name(),
			"-p",
			piperport,
			"/sshpiperd/plugins/fixed",
			"--target",
			"host-password:2222",
		)

		if err != nil {
			t.Errorf("failed to run sshpiperd: %v", err)
		}

		defer killCmd(piper)

		waitForEndpointReady(piperaddr)

		c, _, stdout, err := runCmd(
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
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		waitForStdoutContains(stdout, randtext, func(_ string) {
		})

		t.Run("from_upstream", func(t *testing.T) {
			piperaddr, piperport := nextAvailablePiperAddress()

			piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
				"-p",
				piperport,
				"/sshpiperd/plugins/fixed",
				"--target",
				"host-password:2222",
			)

			if err != nil {
				t.Errorf("failed to run sshpiperd: %v", err)
			}

			defer killCmd(piper)

			waitForEndpointReady(piperaddr)

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
				t.Errorf("failed to ssh to piper, %v", err)
			}

			defer killCmd(c)

			enterPassword(stdin, stdout, "wrongpass")

			waitForStdoutContains(stdout, "sshpiper banner from upstream test", func(_ string) {
			})
		})
	})
}
