package libplugin

import (
	"bytes"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestChainedConfigLogger(t *testing.T) {
	var called []string

	first := func(w io.Writer, level string, tty bool) {
		called = append(called, "first:"+level)
	}
	second := func(w io.Writer, level string, tty bool) {
		if !tty {
			t.Fatalf("expected tty=true")
		}
		called = append(called, "second")
	}

	chained := ChainedConfigLogger(first, nil, second)
	chained(io.Discard, "debug", true)

	if len(called) != 2 || called[0] != "first:debug" || called[1] != "second" {
		t.Fatalf("unexpected calls: %#v", called)
	}
}

func TestConfigLoggerLogrus(t *testing.T) {
	logger := logrus.StandardLogger()
	originalOut := logger.Out
	originalLevel := logger.GetLevel()
	originalFormatter := logger.Formatter
	defer func() {
		logger.SetOutput(originalOut)
		logger.SetLevel(originalLevel)
		logger.SetFormatter(originalFormatter)
	}()

	var buf bytes.Buffer

	ConfigLoggerLogrus(&buf, "warn", false)
	if logger.Out != &buf {
		t.Fatalf("expected logger output to be configured")
	}
	if logger.GetLevel() != logrus.WarnLevel {
		t.Fatalf("expected warn level, got %v", logger.GetLevel())
	}

	ConfigLoggerLogrus(io.Discard, "not-a-level", true)
	if logger.GetLevel() != logrus.InfoLevel {
		t.Fatalf("expected info fallback level, got %v", logger.GetLevel())
	}
}
