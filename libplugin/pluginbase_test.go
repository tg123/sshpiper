package libplugin

import (
	"os"
	"testing"
	"time"
)

func TestNewFromStdioRedirectsStdoutToLogger(t *testing.T) {
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

	p, err := NewFromStdio(SshPiperPluginConfig{})
	if err != nil {
		t.Fatalf("NewFromStdio returned error: %v", err)
	}

	// After NewFromStdio, os.Stdout must no longer be the original transport
	// stdout: writes to it must be diverted into the plugin's logger sink so
	// they are forwarded as log lines instead of corrupting gRPC frames.
	if os.Stdout == stdoutW {
		t.Fatalf("expected os.Stdout to be replaced after NewFromStdio")
	}

	s, ok := p.(*server)
	if !ok {
		t.Fatalf("expected *server, got %T", p)
	}

	// Write a line to os.Stdout and ensure it surfaces on the log channel.
	const want = "hello from stray print"
	if _, err := os.Stdout.WriteString(want + "\n"); err != nil {
		t.Fatalf("WriteString returned error: %v", err)
	}

	// Close the pipe writer so the io.Copy goroutine flushes its scanner.
	if err := os.Stdout.Close(); err != nil {
		t.Fatalf("close stdout pipe: %v", err)
	}

	select {
	case got := <-s.logs:
		if got != want {
			t.Fatalf("log line: got %q want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for log line")
	}

	// Drain the scanner reader to avoid leaking the goroutine started in
	// NewFromGrpc on test exit.
	s.GetGrpcServer().Stop()
	if err := s.listener.Close(); err != nil {
		t.Fatalf("failed to close listener: %v", err)
	}
}
