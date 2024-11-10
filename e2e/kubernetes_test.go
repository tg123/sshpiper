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

	pubkeycases := []struct {
		title string
		user  string
	}{
		{
			title: "key_pubkey_cacthall",
			user:  "anyuser",
		},
		{
			title: "key_custom_field",
			user:  "custom_field",
		},
		{
			title: "key_authorizedfile",
			user:  "authorizedfile",
		},
		{
			title: "key_public_ca",
			user:  "hostcapublickey",
		},
		{
			title: "key_to_pass",
			user:  "keytopass",
		},
	}

	for _, testcase := range pubkeycases {
		t.Run(testcase.title, func(t *testing.T) {

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
				testcase.user,
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

	passwordcases := []struct {
		title    string
		user     string
		password string
	}{
		{
			title:    "password",
			user:     "pass",
			password: "pass",
		},
		{
			title:    "password_htpwd",
			user:     "htpwd",
			password: "htpassword",
		},
		{
			title:    "password_htpasswd_file",
			user:     "htpwdfile",
			password: "htpasswordfile",
		},
	}

	for _, testcase := range passwordcases {

		t.Run(testcase.title, func(t *testing.T) {
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
				testcase.user,
				piperhost,
				fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
			)

			if err != nil {
				t.Errorf("failed to ssh to piper-fixed, %v", err)
			}

			defer killCmd(c)

			enterPassword(stdin, stdout, testcase.password)

			time.Sleep(time.Second) // wait for file flush

			checkSharedFileContent(t, targetfie, randtext)
		})

	}

	{
		// fallback to password
		t.Run("fallback to password", func(t *testing.T) {
			randtext := uuid.New().String()
			targetfie := uuid.New().String()

			keyfiledir, err := os.MkdirTemp("", "")
			if err != nil {
				t.Errorf("failed to create temp key file: %v", err)
			}

			keyfile := path.Join(keyfiledir, "key")

			if err := runCmdAndWait(
				"ssh-keygen",
				"-N",
				"",
				"-f",
				keyfile,
			); err != nil {
				t.Errorf("failed to generate key: %v", err)
			}

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
				"-i",
				keyfile,
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
	}
}
