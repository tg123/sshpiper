package e2e_test

import (
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"testing"
	"time"
	"uuid"
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

		// ssh exits after the 3rd rejected password, failures are counted
		// before the client is notified, so all of them are recorded now
		_ = c.Wait()
	}

	{
		c, _, stdout, err := runCmd(
			"ssh",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			// no password prompt: fail fast instead of hanging if not banned
			"-o",
			"BatchMode=yes",
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

		if !outputEventuallyContains(stdout, "Connection closed by 127.0.0.1", waitTimeout) {
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
		if err := os.MkdirAll(userdir, 0o700); err != nil {
			t.Errorf("failed to create working directory %s: %v", userdir, err)
		}

		if err := os.WriteFile(path.Join(userdir, "sshpiper_upstream"), []byte("user@host-password:2222"), 0o400); err != nil {
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

		if err := os.WriteFile(path.Join(userdir, "known_hosts"), b, 0o400); err != nil {
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

		// failures of killed clients are counted asynchronously
		time.Sleep(time.Second)
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
			// no password prompt: fail fast instead of hanging if not banned
			"-o",
			"BatchMode=yes",
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

		if !outputEventuallyContains(stdout, "Connection closed by 127.0.0.1", waitTimeout) {
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

		// ssh exits after the 3rd rejected password, failures are counted
		// before the client is notified, so all of them are recorded now
		_ = c.Wait()
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

		// ssh exits after the 3rd rejected password, failures are counted
		// before the client is notified, so all of them are recorded now
		_ = c.Wait()
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

func TestFailtobanDenyIP(t *testing.T) {
	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/fixed",
		"--target",
		"host-password:2222",
		"--",
		"/sshpiperd/plugins/failtoban",
		"--deny-ip",
		"127.0.0.0/8",
		"--deny-ip",
		"2001:db8::/32",
		// deny wins over ignore-ip
		"--ignore-ip",
		"127.0.0.1",
	)
	if err != nil {
		t.Errorf("failed to run sshpiperd: %v", err)
	}

	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	// rejected on the very first connection, no failures needed
	c, _, stdout, err := runCmd(
		"ssh",
		"-o",
		"StrictHostKeyChecking=no",
		"-o",
		"UserKnownHostsFile=/dev/null",
		// no password prompt: fail fast instead of hanging if not denied
		"-o",
		"BatchMode=yes",
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

	if !outputEventuallyContains(stdout, "Connection closed by 127.0.0.1", waitTimeout) {
		t.Errorf("expected connection closed by")
	}
}

func TestFailtobanSharedRedis(t *testing.T) {
	pwfile := path.Join(t.TempDir(), "redis-password")
	if err := os.WriteFile(pwfile, []byte("e2epass\n"), 0o400); err != nil {
		t.Fatalf("failed to write redis password file: %v", err)
	}

	// unique prefix, so that runs do not interfere with each other
	prefix := fmt.Sprintf("e2e:%v:", uuid.New().String())

	startPiper := func() (string, string) {
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
			"--store",
			"redis",
			"--store-failure-mode",
			"deny",
			"--redis-url",
			"redis://redis:6379/0",
			"--redis-insecure",
			"--redis-password-file",
			pwfile,
			"--redis-key-prefix",
			prefix,
		)
		if err != nil {
			t.Fatalf("failed to run sshpiperd: %v", err)
		}

		t.Cleanup(func() { killCmd(piper) })

		waitForEndpointReady(piperaddr)

		return piperaddr, piperport
	}

	_, portA := startPiper()
	_, portB := startPiper()

	// one connection with a single wrong password. Counted failures: the
	// rejected password (before the client is notified) and the failed pipe
	// creation after the client gave up (asynchronously), 2 in total.
	failOnce := func(port string) {
		c, stdin, stdout, err := runCmd(
			"ssh",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			"-o",
			"NumberOfPasswordPrompts=1",
			"-p",
			port,
			"-l",
			"user",
			"127.0.0.1",
		)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		defer killCmd(c)

		enterPassword(stdin, stdout, "wrongpass")
		_ = c.Wait()

		time.Sleep(time.Second) // let the async pipe create failure be counted
	}

	// 2 failures via instance A, B must still accept the connection, its
	// rejected password is failure 3 (and the failed pipe 4)
	failOnce(portA)
	failOnce(portB)

	// both instances must ban now
	for _, port := range []string{portA, portB} {
		c, _, stdout, err := runCmd(
			"ssh",
			"-o",
			"StrictHostKeyChecking=no",
			"-o",
			"UserKnownHostsFile=/dev/null",
			// no password prompt: fail fast instead of hanging if not banned
			"-o",
			"BatchMode=yes",
			"-p",
			port,
			"-l",
			"user",
			"127.0.0.1",
		)
		if err != nil {
			t.Errorf("failed to ssh to piper, %v", err)
		}

		_ = c.Wait()

		if !outputEventuallyContains(stdout, "Connection closed by 127.0.0.1", waitTimeout) {
			t.Errorf("expected connection closed by on port %v", port)
		}

		killCmd(c)
	}
}

// outputEventuallyContains polls the output of runCmd until it contains text.
// The output is copied from the pty in the background, so it may still be
// incomplete right after the process exited.
func outputEventuallyContains(stdout io.Reader, text string, timeout time.Duration) bool {
	var seen strings.Builder

	deadline := time.Now().Add(timeout)
	for {
		b, _ := io.ReadAll(stdout)
		seen.Write(b)

		if strings.Contains(seen.String(), text) {
			return true
		}

		if time.Now().After(deadline) {
			return false
		}

		time.Sleep(50 * time.Millisecond)
	}
}
