package e2e_test

import (
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func runAndGetStdout(cmd string, args ...string) ([]byte, error) {
	c := exec.Command(cmd, args...)
	c.SysProcAttr = sigtermForPdeathsig
	// Machine-readable output must not include PTY echo or stderr diagnostics.
	c.Stderr = os.Stderr
	log.Printf("starting %v", c.Args)
	return c.Output()
}

func TestRunAndGetStdout(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("requires sh")
	}

	for _, tt := range []struct {
		name     string
		stdout   string
		exitCode int
	}{
		{name: "known_hosts", stdout: "# comment\n[host-password]:2222 ssh-ed25519 AAAA\n"},
		{name: "empty_stdout"},
		{name: "line_endings", stdout: "unix\nwindows\r\n"},
		{name: "large_stdout", stdout: strings.Repeat("host ssh-ed25519 AAAA\n", 4096)},
		{name: "failed_command", stdout: "partial output\n", exitCode: 7},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fixture := filepath.Join(t.TempDir(), "stdout")
			if err := os.WriteFile(fixture, []byte(tt.stdout), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := runAndGetStdout("sh", "-c",
				`printf '%s\n' 'ERROR: loader diagnostic' >&2; cat "$1"; exit "$2"`,
				"stdout-test", fixture, strconv.Itoa(tt.exitCode))
			if tt.exitCode == 0 {
				if err != nil {
					t.Fatalf("runAndGetStdout: %v", err)
				}
			} else {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != tt.exitCode {
					t.Fatalf("expected exit code %d, got %v", tt.exitCode, err)
				}
			}
			if string(got) != tt.stdout {
				t.Fatalf("stdout differs: got %d bytes, want %d (stderr must be excluded and line endings preserved)", len(got), len(tt.stdout))
			}
		})
	}
}
