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
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	benchmarkPayloadDefaultSize = 64 * 1024 * 1024
	benchmarkPayloadEnv         = "SSHPIPERD_BENCH_PAYLOAD_BYTES"
	benchmarkCipherEnv          = "SSHPIPERD_BENCH_CIPHERS"
	benchmarkCipherDefault      = "aes128-gcm@openssh.com"
	benchmarkScpTarget          = "/shared/bench-scp-payload"
	benchmarkUpstreamAddr       = "host-publickey:2222"
)

var benchmarkPayloadSize = resolveBenchmarkPayloadSize()

func resolveBenchmarkPayloadSize() int {
	if v := strings.TrimSpace(os.Getenv(benchmarkPayloadEnv)); v != "" {
		bytes, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			log.Printf("invalid %s value %q, fallback to default: %v", benchmarkPayloadEnv, v, err)
		} else if bytes > 0 {
			log.Printf("benchmark payload size set to %d bytes via %s", bytes, benchmarkPayloadEnv)
			return int(bytes)
		} else {
			log.Printf("non-positive %s value %q, fallback to default", benchmarkPayloadEnv, v)
		}
	}

	log.Printf("benchmark payload size set to %d bytes (default)", benchmarkPayloadDefaultSize)
	return benchmarkPayloadDefaultSize
}

func benchmarkCipherArgs() []string {
	if v := strings.TrimSpace(os.Getenv(benchmarkCipherEnv)); v != "" {
		// Use -o to ensure both ssh and scp pick up the cipher list.
		return []string{"-o", "Ciphers=" + v}
	}

	return []string{"-o", "Ciphers=" + benchmarkCipherDefault}
}

func BenchmarkTransferRate(b *testing.B) {
	keyfile := prepareBenchmarkKey(b)
	payload, payloadFile := prepareBenchmarkPayload(b)

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

	b.Run("scp_upload", func(b *testing.B) {
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			if err := runScpTransfer("127.0.0.1", piperport, keyfile, payloadFile); err != nil {
				b.Fatalf("scp failed: %v", err)
			}
		}
	})

	b.Run("ssh_stream", func(b *testing.B) {
		b.SetBytes(int64(len(payload)))
		const cmd = "cat > /dev/null"

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			if err := runSSHStream("127.0.0.1", piperport, keyfile, cmd, bytes.NewReader(payload)); err != nil {
				b.Fatalf("ssh stream failed: %v", err)
			}
		}
	})
}

func BenchmarkTransferRateBaseline(b *testing.B) {
	keyfile := prepareBenchmarkKey(b)
	payload, payloadFile := prepareBenchmarkPayload(b)

	waitForEndpointReady(benchmarkUpstreamAddr)

	b.Run("scp_upload", func(b *testing.B) {
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			if err := runScpTransfer("host-publickey", "2222", keyfile, payloadFile); err != nil {
				b.Fatalf("scp failed: %v", err)
			}
		}
	})

	b.Run("ssh_stream", func(b *testing.B) {
		b.SetBytes(int64(len(payload)))
		const cmd = "cat > /dev/null"

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			if err := runSSHStream("host-publickey", "2222", keyfile, cmd, bytes.NewReader(payload)); err != nil {
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

func prepareBenchmarkPayload(b *testing.B) ([]byte, string) {
	b.Helper()

	payload := make([]byte, benchmarkPayloadSize)
	if _, err := rand.Read(payload); err != nil {
		b.Fatalf("failed to generate benchmark payload: %v", err)
	}

	payloadFile := filepath.Join(b.TempDir(), "payload")

	if err := os.WriteFile(payloadFile, payload, 0o600); err != nil {
		b.Fatalf("failed to write benchmark payload: %v", err)
	}

	return payload, payloadFile
}

func runScpTransfer(host, port, keyfile, payloadFile string) error {
	args := []string{
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
	}

	args = append(args, benchmarkCipherArgs()...)
	args = append(args, payloadFile, fmt.Sprintf("user@%s:%s", host, benchmarkScpTarget))

	c, stdin, stdout, err := runPipeCmd("scp", args)
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

func runSSHStream(host, port, keyfile, remoteCmd string, stdin io.Reader) error {
	args := []string{
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
	}

	args = append(args, benchmarkCipherArgs()...)
	args = append(args, "user@"+host, remoteCmd)

	c, writer, stdout, err := runPipeCmd("ssh", args)
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
