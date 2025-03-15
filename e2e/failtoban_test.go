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

		time.Sleep(time.Second) // TODO ugly workaround, wait for stdout flush

		s, _ := io.ReadAll(stdout)

		if !strings.Contains(string(s), "Connection closed by 127.0.0.1") {
			t.Errorf("expected connection closed by")
		}
	}

}

func TestFailtobanPipeCreateFail(t *testing.T) {
	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/workingdir",
		"--root",
		workingdir,
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

	ensureWorkingDirectory()

	// ensure username works with password
	userdir := path.Join(workingdir, "bypassword")

	{
		if err := os.MkdirAll(userdir, 0700); err != nil {
			t.Errorf("failed to create working directory %s: %v", userdir, err)
		}

		if err := os.WriteFile(path.Join(userdir, "sshpiper_upstream"), []byte("user@host-password:2222"), 0400); err != nil {
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

		if err := os.WriteFile(path.Join(userdir, "known_hosts"), b, 0400); err != nil {
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

	{

		// run 5 times to trigger ban
		for i := 0; i < 3; i++ {
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
				fmt.Sprintf("notexist_%v", i),
				"127.0.0.1",
			)

			if err != nil {
				t.Errorf("ssh fail")
			}

			enterPassword(stdin, stdout, "notapass")
			killCmd(c)
		}
	}

	// run with good user
	{
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
			"bypassword",
			"127.0.0.1",
		)

		if err != nil {
			t.Errorf("failed to ssh to workingdir, %v", err)
		}

		defer killCmd(c)

		_ = c.Wait()

		time.Sleep(time.Second) // TODO ugly workaround, wait for stdout flush

		s, _ := io.ReadAll(stdout)

		if !strings.Contains(string(s), "Connection closed by 127.0.0.1") {
			t.Errorf("expected connection closed by")
		}
	}
}

func TestFailtobanIgnoreIP(t *testing.T) {
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
		"--ignore-ip",
		"127.0.0.1",
	)

	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

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
			"user",
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
			t.Errorf("failed to ssh to piper-workingdir, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	}
}

func TestFailtobanIgnoreCIDR(t *testing.T) {
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
		"--ignore-ip",
		"127.0.0.1/8",
	)

	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

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
			"user",
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
			t.Errorf("failed to ssh to piper-workingdir, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "pass")

		time.Sleep(time.Second) // wait for file flush

		checkSharedFileContent(t, targetfie, randtext)
	}
}
