package e2e_test

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"testing"
	"time"

	"github.com/google/uuid"
)

const workingdir = "/shared/workingdir"

func ensureWorkingDirectory() {
	err := os.MkdirAll(workingdir, 0700)
	if err != nil {
		log.Panicf("failed to create working directory %s: %v", workingdir, err)
	}
}

func TestWorkingDirectory(t *testing.T) {

	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/workingdir",
		"--root",
		workingdir,
	)

	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	ensureWorkingDirectory()

	t.Run("bypassword", func(t *testing.T) {
		userdir := path.Join(workingdir, "bypassword")

		{
			if err := os.MkdirAll(userdir, 0700); err != nil {
				t.Errorf("failed to create working directory %s: %v", userdir, err)
			}

			if err := ioutil.WriteFile(path.Join(userdir, "sshpiper_upstream"), []byte("user@host-password:2222"), 0400); err != nil {
				t.Errorf("failed to write upstream file: %v", err)
			}
		}

		{
			b, err := runAndGetStdout(
				"ssh-keyscan",
				"-p",
				"2222",
				"host-password",
			)

			if err != nil {
				t.Errorf("failed to run ssh-keyscan: %v", err)
			}

			if err := ioutil.WriteFile(path.Join(userdir, "known_hosts"), b, 0400); err != nil {
				t.Errorf("failed to write known_hosts: %v", err)
			}
		}

		{
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
				"bypassword",
				"127.0.0.1",
				fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
			)

			if err != nil {
				t.Errorf("failed to ssh to piper-workingdir, %v", err)
			}

			defer killCmd(c)

			enterPassword(stdin, stdout, "pass")

			time.Sleep(time.Second) // wait for file flush

			checkSharedFileContent(t, targetfie, randtext)
		}
	})

	t.Run("bypublickey", func(t *testing.T) {
		userdir := path.Join(workingdir, "bypublickey")
		if err := os.MkdirAll(userdir, 0700); err != nil {
			t.Errorf("failed to create working directory %s: %v", userdir, err)
		}

		if err := ioutil.WriteFile(path.Join(userdir, "sshpiper_upstream"), []byte("user@host-publickey:2222"), 0400); err != nil {
			t.Errorf("failed to write upstream file: %v", err)
		}

		{
			b, err := runAndGetStdout(
				"ssh-keyscan",
				"-p",
				"2222",
				"host-publickey",
			)

			if err != nil {
				t.Errorf("failed to run ssh-keyscan: %v", err)
			}

			if err := ioutil.WriteFile(path.Join(userdir, "known_hosts"), b, 0400); err != nil {
				t.Errorf("failed to write known_hosts: %v", err)
			}
		}

		keydir, err := os.MkdirTemp("", "")
		// generate a local key
		if err != nil {
			t.Errorf("failed to create temp dir: %v", err)
		}

		{

			if err := runCmdAndWait("rm", "-f", path.Join(keydir, "id_rsa")); err != nil {
				t.Errorf("failed to remove id_rsa: %v", err)
			}

			if err := runCmdAndWait(
				"ssh-keygen",
				"-N",
				"",
				"-f",
				path.Join(keydir, "id_rsa"),
			); err != nil {
				t.Errorf("failed to generate private key: %v", err)
			}

			if err := runCmdAndWait(
				"/bin/cp",
				path.Join(keydir, "id_rsa.pub"),
				path.Join(userdir, "authorized_keys"),
			); err != nil {
				t.Errorf("failed to copy public key: %v", err)
			}

			if err := runCmdAndWait(
				"chmod",
				"0400",
				path.Join(userdir, "authorized_keys"),
			); err != nil {
				t.Errorf("failed to chmod public key: %v", err)
			}

			// set upstream key
			if err := runCmdAndWait("rm", "-f", path.Join(userdir, "id_rsa")); err != nil {
				t.Errorf("failed to remove id_rsa: %v", err)
			}

			if err := runCmdAndWait(
				"ssh-keygen",
				"-N",
				"",
				"-f",
				path.Join(userdir, "id_rsa"),
			); err != nil {
				t.Errorf("failed to generate private key: %v", err)
			}

			if err := runCmdAndWait(
				"/bin/cp",
				path.Join(userdir, "id_rsa.pub"),
				"/sshconfig_publickey/.ssh/authorized_keys",
			); err != nil {
				t.Errorf("failed to copy public key: %v", err)
			}
		}

		{
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
				"bypublickey",
				"-i",
				path.Join(keydir, "id_rsa"),
				"127.0.0.1",
				fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
			)

			if err != nil {
				t.Errorf("failed to ssh to piper-workingdir, %v", err)
			}

			defer killCmd(c)

			time.Sleep(time.Second) // wait for file flush

			checkSharedFileContent(t, targetfie, randtext)
		}

	})
}
