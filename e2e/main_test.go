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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

const testprivatekey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDURkx99uaw1KddraZcLpB5kfMrWwvUz2fPOoArLcpz9QAAAJC+j0+Svo9P
kgAAAAtzc2gtZWQyNTUxOQAAACDURkx99uaw1KddraZcLpB5kfMrWwvUz2fPOoArLcpz9Q
AAAEDcQgdh2z2r/6blq0ziJ1l6s6IAX8C+9QHfAH931cHNO9RGTH325rDUp12tplwukHmR
8ytbC9TPZ886gCstynP1AAAADWJvbGlhbkB1YnVudHU=
-----END OPENSSH PRIVATE KEY-----
`

const testpublickey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINRGTH325rDUp12tplwukHmR8ytbC9TPZ886gCstynP1`

const waitTimeout = time.Second * 10

func waitForEndpointReady(addr string) {
	waitForEndpointReadyWithTimeout(addr, waitTimeout)
}

func waitForEndpointReadyWithTimeout(addr string, timeout time.Duration) {
	now := time.Now()
	timeout = max(timeout, waitTimeout)
	for {
		if time.Since(now) > timeout {
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
	newargs := append([]string{cmd}, args...)
	newargs = append([]string{"-i0", "-o0", "-e0"}, newargs...)
	c := exec.Command("stdbuf", newargs...)
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

	return c, f, &buf, nil
}

func runCmdAndWait(cmd string, args ...string) error {
	c, _, _, err := runCmd(cmd, args...)
	if err != nil {
		return err
	}

	return c.Wait()
}

func waitForStdoutContains(stdout io.Reader, text string, cb func(string)) {
	st := time.Now()
	for {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, text) {
				cb(line)
				return
			}
		}

		if time.Since(st) > waitTimeout {
			log.Panicf("timeout waiting for [%s] from prompt", text)
			return
		}

		time.Sleep(time.Second) // stdout has no data yet
	}
}

func enterPassword(stdin io.Writer, stdout io.Reader, password string) {
	waitForStdoutContains(stdout, "'s password", func(_ string) {
		_, _ = stdin.Write([]byte(fmt.Sprintf("%v\n", password)))
		log.Printf("got password prompt, sending password")
	})
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
		t.Errorf("shared file content mismatch, expected %v, got %v", expected, string(b))
	}
}

func killCmd(c *exec.Cmd) {
	if c.Process != nil {
		if err := c.Process.Kill(); err != nil {
			log.Printf("failed to kill ssh process, %v", err)
		}
	}
}

func runAndGetStdout(cmd string, args ...string) ([]byte, error) {
	c, _, stdout, err := runCmd(cmd, args...)

	if err != nil {
		return nil, err
	}

	if err := c.Wait(); err != nil {
		return nil, err
	}

	return io.ReadAll(stdout)
}

func nextAvaliablePort() int {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Panic(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func nextAvailablePiperAddress() (string, string) {
	port := strconv.Itoa(nextAvaliablePort())
	return net.JoinHostPort("127.0.0.1", (port)), port
}

func TestMain(m *testing.M) {

	if os.Getenv("SSHPIPERD_E2E_TEST") != "1" {
		log.Printf("skipping e2e test")
		os.Exit(0)
		return
	}

	_ = runCmdAndWait("ssh", "-V")

	for _, ep := range []string{
		"host-password:2222",
		"host-publickey:2222",
	} {
		waitForEndpointReady(ep)
	}

	os.Exit(m.Run())
}
