package e2e_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const (
	benchmarkPayloadSize = 5 * 1024 * 1024
	benchmarkScpTarget   = "/shared/bench-scp-payload"
)

func BenchmarkTransferRate(b *testing.B) {
	if os.Getenv("SSHPIPERD_E2E_TEST") != "1" {
		b.Skip("SSHPIPERD_E2E_TEST not set")
	}

	keyfile := prepareBenchmarkKey(b)

	piperaddr, piperport := nextAvailablePiperAddress()

	piper, _, _, err := runCmd("/sshpiperd/sshpiperd",
		"-p",
		piperport,
		"/sshpiperd/plugins/fixed",
		"--target",
		"host-publickey:2222",
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
	var stdout, stderr bytes.Buffer

	cmd := exec.Command("scp",
		"-q",
		"-i", keyfile,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-P", port,
		payloadFile,
		fmt.Sprintf("user@127.0.0.1:%s", benchmarkScpTarget),
	)

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.SysProcAttr = sigtermForPdeathsig

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("scp failed: %w (stdout: %s, stderr: %s)", err, stdout.String(), stderr.String())
	}

	return nil
}

func runSSHStream(port, keyfile, remoteCmd string, stdin io.Reader) error {
	var stderr bytes.Buffer

	cmd := exec.Command("ssh",
		"-i", keyfile,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-p", port,
		"user@127.0.0.1",
		remoteCmd,
	)

	cmd.Stdin = stdin
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	cmd.SysProcAttr = sigtermForPdeathsig

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh failed: %w (stderr: %s)", err, stderr.String())
	}

	return nil
}
