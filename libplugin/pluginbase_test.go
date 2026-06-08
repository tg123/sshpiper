package libplugin

import (
	"os"
	"testing"
)

func TestNewFromStdioRedirectsStdoutToStderr(t *testing.T) {
	originalStdin := os.Stdin
	originalStdout := os.Stdout
	originalStderr := os.Stderr
	defer func() {
		os.Stdin = originalStdin
		os.Stdout = originalStdout
		os.Stderr = originalStderr
	}()

	// NewFromStdio binds the gRPC transport to os.Stdin/os.Stdout and closing the
	// listener closes them. Swap in pipes so the test harness' real stdin/stdout
	// (used for coverage output) are not affected.
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdin pipe: %v", err)
	}
	defer stdinW.Close()
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	defer stdoutR.Close()

	os.Stdin = stdinR
	os.Stdout = stdoutW

	redirectedStderr := os.Stderr

	p, err := NewFromStdio(SshPiperPluginConfig{})
	if err != nil {
		t.Fatalf("NewFromStdio returned error: %v", err)
	}

	if os.Stdout != redirectedStderr {
		t.Fatalf("expected stdout to be redirected to stderr")
	}

	s, ok := p.(*server)
	if !ok {
		t.Fatalf("expected *server, got %T", p)
	}

	s.GetGrpcServer().Stop()
	if err := s.listener.Close(); err != nil {
		t.Fatalf("failed to close listener: %v", err)
	}
}
