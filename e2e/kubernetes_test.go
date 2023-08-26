package e2e_test

import (
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestKubernetes(t *testing.T) {
	piperhost := "host-k8s-proxy"
	piperport := "2222"
	piperaddr := piperhost + ":" + piperport
	waitForEndpointReadyWithTimeout(piperaddr, time.Minute*10)

	t.Run("password", func(t *testing.T) {
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
			"pass",
			piperhost,
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to piper-fixed, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("key", func(t *testing.T) {

		keyfiledir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Errorf("failed to create temp key file: %v", err)
		}

		keyfile := path.Join(keyfiledir, "key")

		if err := os.WriteFile(keyfile, []byte(testprivatekey), 0400); err != nil {
			t.Errorf("failed to write to test key: %v", err)
		}

		if err := os.WriteFile("/sshconfig_publickey/.ssh/authorized_keys", []byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINRGTH325rDUp12tplwukHmR8ytbC9TPZ886gCstynP1`), 0400); err != nil {
			t.Errorf("failed to write to authorized_keys: %v", err)
		}

		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, _, _, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"anyuser",
			"-i",
			keyfile,
			piperhost,
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to piper-fixed, %v", err)
		}

		defer killCmd(c)

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("key_custom_field", func(t *testing.T) {

		keyfiledir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Errorf("failed to create temp key file: %v", err)
		}

		keyfile := path.Join(keyfiledir, "key")

		if err := os.WriteFile(keyfile, []byte(testprivatekey), 0400); err != nil {
			t.Errorf("failed to write to test key: %v", err)
		}

		if err := os.WriteFile("/sshconfig_publickey/.ssh/authorized_keys", []byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINRGTH325rDUp12tplwukHmR8ytbC9TPZ886gCstynP1`), 0400); err != nil {
			t.Errorf("failed to write to authorized_keys: %v", err)
		}

		randtext := uuid.New().String()
		targetfie := uuid.New().String()

		c, _, _, err := runCmd(
			"ssh",
			"-v",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-p",
			piperport,
			"-l",
			"custom_field",
			"-i",
			keyfile,
			piperhost,
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to piper-fixed, %v", err)
		}

		defer killCmd(c)

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("password_htpasswd", func(t *testing.T) {
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
			"htpwd",
			piperhost,
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to piper-fixed, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "htpassword")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})

	t.Run("password_htpasswd_file", func(t *testing.T) {
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
			"htpwdfile",
			piperhost,
			fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
		)

		if err != nil {
			t.Errorf("failed to ssh to piper-fixed, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "htpasswordfile")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	})
}
