package e2e_test

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"
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

			if err := os.WriteFile(keyfile, []byte(testprivatekey), 0o400); err != nil {
				t.Errorf("failed to write to test key: %v", err)
			}

			if err := os.WriteFile(authorizedKeysPath, []byte(testpublickey+"\n"), 0o400); err != nil {
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

	t.Run("kubectl_exec", func(t *testing.T) {
		keyfiledir, err := os.MkdirTemp("", "")
		if err != nil {
			t.Errorf("failed to create temp key file: %v", err)
		}

		keyfile := path.Join(keyfiledir, "key")
		if err := os.WriteFile(keyfile, []byte(testprivatekey), 0o400); err != nil {
			t.Errorf("failed to write to test key: %v", err)
		}

		randtext := uuid.New().String()
		var output []byte

		for i := 0; i < 10; i++ {
			c, stdin, stdout, runErr := runCmd(
				"ssh",
				"-o",
				"StrictHostKeyChecking=no",
				"-o",
				"UserKnownHostsFile=/dev/null",
				"-p",
				piperport,
				"-l",
				"kubectlexec",
				"-i",
				keyfile,
				piperhost,
			)
			if runErr != nil {
				err = runErr
				time.Sleep(time.Second)
				continue
			}

			if _, runErr = fmt.Fprintf(stdin, "echo -n %q\nexit\n", randtext); runErr != nil {
				err = runErr
				killCmd(c)
				time.Sleep(time.Second)
				continue
			}

			err = c.Wait()
			if err == nil {
				readErr := error(nil)
				output, readErr = io.ReadAll(stdout)
				if readErr != nil {
					err = readErr
				}
				break
			}

			time.Sleep(time.Second)
		}

		if err != nil {
			t.Fatalf("failed to ssh to kubectl exec pipe, %v", err)
		}

		if !strings.Contains(string(output), randtext) {
			t.Fatalf("unexpected kubectl exec output: %q (expected to contain %q)", string(output), randtext)
		}
	})
}
