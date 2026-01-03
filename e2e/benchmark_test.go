package e2e_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const (
	benchmarkPayloadSize = 5 * 1024 * 1024
	benchmarkScpTarget   = "/shared/bench-scp-payload"
)

func BenchmarkTransferRate(b *testing.B) {
	keyfile := prepareBenchmarkKey(b)

	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/benchmark",
		"--target",
		"host-publickey:2222",
		"--private-key-file",
		keyfile,
	)
	if err != nil {
		b.Fatalf("failed to run sshpiperd: %v", err)
	}
	defer killCmd(piper)

	waitForEndpointReady(piperaddr)

	payload := make([]byte, benchmarkPayloadSize)
	if _, err := rand.Read(payload); err != nil {
		b.Fatalf("failed to generate benchmark payload: %v", err)
	}
	payloadFile := filepath.Join(b.TempDir(), "payload")

	if err := os.WriteFile(payloadFile, payload, 0o600); err != nil {
		b.Fatalf("failed to write benchmark payload: %v", err)
	}

	b.Run("scp_upload", func(b *testing.B) {
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			if err := runScpTransfer(piperport, keyfile, payloadFile); err != nil {
				b.Fatalf("scp failed: %v", err)
			}
		}
	})

	b.Run("ssh_stream", func(b *testing.B) {
		b.SetBytes(int64(len(payload)))
		const cmd = "cat > /dev/null"

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			if err := runSSHStream(piperport, keyfile, cmd, bytes.NewReader(payload)); err != nil {
				b.Fatalf("ssh stream failed: %v", err)
			}
		}
	})
}

func prepareBenchmarkKey(b *testing.B) string {
	b.Helper()

	keydir := b.TempDir()
	keyfile := filepath.Join(keydir, "id_ed25519")
	if err := os.WriteFile(keyfile, []byte(testprivatekey), 0o400); err != nil {
		b.Fatalf("failed to write benchmark private key: %v", err)
	}

	if err := os.WriteFile(authorizedKeysPath, []byte(testpublickey+"\n"), 0o400); err != nil {
		b.Fatalf("failed to write benchmark authorized_keys: %v", err)
	}

	return keyfile
}

func runScpTransfer(port, keyfile, payloadFile string) error {
	c, stdin, stdout, err := runPipeCmd(
		"scp",
		[]string{
			"-q",
			"-i", keyfile,
			"-o", "IdentitiesOnly=yes",
			"-o", "BatchMode=yes",
			"-o", "PasswordAuthentication=no",
			"-o", "KbdInteractiveAuthentication=no",
			"-o", "ConnectionAttempts=1",
			"-o", "ConnectTimeout=10",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-P", port,
			payloadFile,
			fmt.Sprintf("user@127.0.0.1:%s", benchmarkScpTarget),
		},
	)
	if err != nil {
		return err
	}

	_ = stdin.Close()

	if err := c.Wait(); err != nil {
		out, _ := io.ReadAll(stdout)
		return fmt.Errorf("scp failed: %w (stdout: %s)", err, string(out))
	}

	return nil
}

func runSSHStream(port, keyfile, remoteCmd string, stdin io.Reader) error {
	c, writer, stdout, err := runPipeCmd(
		"ssh",
		[]string{
			"-T", // disable remote pty to avoid echoing payload back
			"-i", keyfile,
			"-o", "IdentitiesOnly=yes",
			"-o", "BatchMode=yes",
			"-o", "PasswordAuthentication=no",
			"-o", "KbdInteractiveAuthentication=no",
			"-o", "ConnectionAttempts=1",
			"-o", "ConnectTimeout=10",
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
			"-p", port,
			"user@127.0.0.1",
			remoteCmd,
		},
	)
	if err != nil {
		return err
	}

	if stdin != nil {
		log.Printf("ssh_stream: starting payload copy")
		_, _ = io.Copy(writer, stdin)
		log.Printf("ssh_stream: finished payload copy, closing writer")
		if closer, ok := writer.(io.Closer); ok {
			_ = closer.Close()
		}
	}

	log.Printf("ssh_stream: waiting for ssh process")
	if err := waitWithTimeout(c, 5*time.Second); err != nil {
		out, _ := io.ReadAll(stdout)
		return fmt.Errorf("ssh failed: %w (stdout: %s)", err, string(out))
	}
	log.Printf("ssh_stream: ssh process completed")

	return nil
}

func runPipeCmd(cmd string, args []string, env ...string) (*exec.Cmd, io.WriteCloser, io.Reader, error) {
	c := exec.Command(cmd, args...)
	if len(env) > 0 {
		c.Env = append(os.Environ(), env...)
	}

	var buf bytes.Buffer
	mw := io.MultiWriter(&buf, os.Stdout)
	c.Stdout = mw
	c.Stderr = mw

	stdin, err := c.StdinPipe()
	if err != nil {
		return nil, nil, nil, err
	}

	log.Printf("starting %v", c.Args)

	if err := c.Start(); err != nil {
		return nil, nil, nil, err
	}

	return c, stdin, &buf, nil
}

func waitWithTimeout(c *exec.Cmd, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()

	if timeout <= 0 {
		return <-done
	}

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = c.Process.Kill()
		<-done
		return fmt.Errorf("ssh timed out after %s", timeout)
	}
}
