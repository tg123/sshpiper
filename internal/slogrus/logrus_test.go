package logrus

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	level, err := ParseLevel("debug")
	if err != nil {
		t.Fatalf("ParseLevel returned error: %v", err)
	}

	if level != DebugLevel {
		t.Fatalf("expected debug level, got %v", level)
	}

	if _, err := ParseLevel("invalid"); err == nil {
		t.Fatal("expected invalid log level error")
	}
}

func TestLoggerLevelAndFormatter(t *testing.T) {
	buffer := &bytes.Buffer{}
	logger := StandardLogger()

	logger.SetOutput(buffer)
	logger.SetLevel(InfoLevel)
	logger.SetFormatter(&JSONFormatter{})

	Debug("debug message")
	Info("info message")

	output := buffer.String()
	if strings.Contains(output, "debug message") {
		t.Fatalf("debug message should be filtered out, output: %v", output)
	}

	if !strings.Contains(output, "info message") {
		t.Fatalf("info message not found, output: %v", output)
	}

	if !strings.Contains(output, "\"msg\":\"info message\"") {
		t.Fatalf("json output expected, output: %v", output)
	}
}
