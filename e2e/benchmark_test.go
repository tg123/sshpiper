package e2e_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
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
	c, _, stdout, err := runCmd(
		"scp",
		"-q",
		"-i", keyfile,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "NumberOfPasswordPrompts=0",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-P", port,
		payloadFile,
		fmt.Sprintf("user@127.0.0.1:%s", benchmarkScpTarget),
	)
	if err != nil {
		return err
	}

	if err := c.Wait(); err != nil {
		b, _ := io.ReadAll(stdout)
		return fmt.Errorf("scp failed: %w (stdout: %s)", err, string(b))
	}

	return nil
}

func runSSHStream(port, keyfile, remoteCmd string, stdin io.Reader) error {
	c, writer, stdout, err := runCmd(
		"ssh",
		"-i", keyfile,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "NumberOfPasswordPrompts=0",
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-p", port,
		"user@127.0.0.1",
		remoteCmd,
	)
	if err != nil {
		return err
	}

	if stdin != nil && writer != nil {
		_, _ = io.Copy(writer, stdin)
		if closer, ok := writer.(io.Closer); ok {
			_ = closer.Close()
		}
	}

	if err := c.Wait(); err != nil {
		b, _ := io.ReadAll(stdout)
		return fmt.Errorf("ssh failed: %w (stdout: %s)", err, string(b))
	}

	return nil
}
