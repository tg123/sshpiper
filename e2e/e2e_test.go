// run with docker-compose up --build --abort-on-container-exit

package e2e_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/google/uuid"
)

const waitTimeout = time.Second * 10

func waitForEndpointReady(addr string) {
	now := time.Now()
	for {
		if time.Since(now) > waitTimeout {
			log.Panic("timeout waiting for endpoint " + addr)
		}

		conn, err := net.Dial("tcp", addr)
		if err == nil {
			log.Printf("endpoint %s is ready", addr)
			conn.Close()
			break
		}
		time.Sleep(time.Second)
	}
}

func runCmd(cmd string, args ...string) (*exec.Cmd, io.Writer, io.Reader, error) {
	c := exec.Command(cmd, args...)
	c.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	f, err := pty.Start(c)
	if err != nil {
		return nil, nil, nil, err
	}

	var buf bytes.Buffer
	r := io.TeeReader(f, &buf)
	go func() {
		_, _ = io.Copy(os.Stdout, r)
	}()

	log.Printf("starting %v", c.Args)

	go func() {
		if err := c.Wait(); err != nil {
			log.Printf("wait %v returns %v", c.Args, err)
		}
	}()

	return c, f, &buf, nil
}

func enterPassword(stdin io.Writer, stdout io.Reader, password string) {
	st := time.Now()
	for {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "'s password") {
				_, _ = stdin.Write([]byte(fmt.Sprintf("%v\n", password)))
				log.Printf("got password prompt, sending password")
				return
			}
		}

		if time.Since(st) > waitTimeout {
			log.Panic("timeout waiting for password prompt")
			return
		}
	}
}

func checkSharedFileContent(t *testing.T, targetfie string, expected string) {
	f, err := os.Open(fmt.Sprintf("/shared/%v", targetfie))
	if err != nil {
		t.Errorf("failed to open shared file, %v", err)
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		t.Errorf("failed to read shared file, %v", err)
	}

	if string(b) != expected {
		t.Errorf("shared file content mismathc, expected %v, got %v", expected, string(b))
	}
}

func TestMain(m *testing.M) {
	_, _, _, _ = runCmd("ssh", "-V")

	for _, ep := range []string{
		"host-password:2222",
	} {
		waitForEndpointReady(ep)
	}

	os.Exit(m.Run())
}

func TestFixed(t *testing.T) {
	waitForEndpointReady("piper-fixed:2222")

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
		"2222",
		"-l",
		"user",
		"piper-fixed",
		fmt.Sprintf(`sh -c "echo -n %v > /shared/%v"`, randtext, targetfie),
	)

	if err != nil {
		t.Errorf("failed to ssh to piper-fixed, %v", err)
	}

	defer func() {
		if c.Process != nil {
			if err = c.Process.Kill(); err != nil {
				log.Printf("failed to kill ssh process, %v", err)
			}
		}
	}()

	enterPassword(stdin, stdout, "pass")

	time.Sleep(time.Second) // wait for file flush

	checkSharedFileContent(t, targetfie, randtext)
}
