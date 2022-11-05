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
	waitForEndpointReadyWithTimeout(piperaddr, time.Minute*5)

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

		if err := os.WriteFile("/sshconfig_publickey/.ssh/authorized_keys", []byte(`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVzohqdRTuT6+SvaccRc9emivp74CyVrO1beiWrGOu0gWy6cocCkodFQXa0qi5vcYO5TX40+PvgwMlNYvQwLbntvnUxHI2H7UymBKQK2jy6Fjt+hBEvFBRbCiL029YRiJE3ffGMY2gs4rkv5lzXqMJmg2HqnwAns5oJWV1TpFV2FBo8NGvAOXcUa3Nuk/nCKtVurnap7GoZD2/CAhJxuxbW+7Y2cGst87EX4Esk8p8QF+Bi5RlD9As2ublc5bIMpXA4rrQKc5gRrDtqHojfWqtdrQqQlg1pBOLHye7lSRcfxhG7qY7xzvYnkWx23KO2tLb5WCupG+V7QRJFosYwutBAqppMpNS60WflE+mymUVf+ptLn3oRDFEalo1kJkymd6uyp+BPZgrGSTt+DzHTIwoJ9RowwBVTU2sKz13WhP+6TKf82IhyjOspeKjbOjLUII/tL4647/7X9VaOvvJ5Qt5sPAdcwk7nSPfkJEr/U9ChnUNKEn6H1eNm26dZpk7hiU=`), 0400); err != nil {
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

		if err := os.WriteFile("/sshconfig_publickey/.ssh/authorized_keys", []byte(`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDVzohqdRTuT6+SvaccRc9emivp74CyVrO1beiWrGOu0gWy6cocCkodFQXa0qi5vcYO5TX40+PvgwMlNYvQwLbntvnUxHI2H7UymBKQK2jy6Fjt+hBEvFBRbCiL029YRiJE3ffGMY2gs4rkv5lzXqMJmg2HqnwAns5oJWV1TpFV2FBo8NGvAOXcUa3Nuk/nCKtVurnap7GoZD2/CAhJxuxbW+7Y2cGst87EX4Esk8p8QF+Bi5RlD9As2ublc5bIMpXA4rrQKc5gRrDtqHojfWqtdrQqQlg1pBOLHye7lSRcfxhG7qY7xzvYnkWx23KO2tLb5WCupG+V7QRJFosYwutBAqppMpNS60WflE+mymUVf+ptLn3oRDFEalo1kJkymd6uyp+BPZgrGSTt+DzHTIwoJ9RowwBVTU2sKz13WhP+6TKf82IhyjOspeKjbOjLUII/tL4647/7X9VaOvvJ5Qt5sPAdcwk7nSPfkJEr/U9ChnUNKEn6H1eNm26dZpk7hiU=`), 0400); err != nil {
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
}
