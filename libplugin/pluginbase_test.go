package libplugin

import (
	"os"
	"testing"
)

func TestNewFromStdioRedirectsStdoutToStderr(t *testing.T) {
	originalStdout := os.Stdout
	originalStderr := os.Stderr
	defer func() {
		os.Stdout = originalStdout
		os.Stderr = originalStderr
	}()

	p, err := NewFromStdio(SshPiperPluginConfig{})
	if err != nil {
		t.Fatalf("NewFromStdio returned error: %v", err)
	}

	if os.Stdout != originalStderr {
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
