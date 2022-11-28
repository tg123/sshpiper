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
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
-----END OPENSSH PRIVATE KEY-----
`

const waitTimeout = time.Second * 10

func waitForEndpointReady(addr string) {
	waitForEndpointReadyWithTimeout(addr, waitTimeout)
}

func waitForEndpointReadyWithTimeout(addr string, timeout time.Duration) {
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
