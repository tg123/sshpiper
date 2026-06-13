package slogutil

import (
	"log/slog"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		expectedLevel slog.Level
		fallback      bool
	}{
		{name: "trace alias", input: "trace", expectedLevel: slog.LevelDebug},
		{name: "debug lowercase", input: "debug", expectedLevel: slog.LevelDebug},
		{name: "debug uppercase", input: "DEBUG", expectedLevel: slog.LevelDebug},
		{name: "info mixed case", input: "InFo", expectedLevel: slog.LevelInfo},
		{name: "warning alias", input: "warning", expectedLevel: slog.LevelWarn},
		{name: "warn lowercase", input: "warn", expectedLevel: slog.LevelWarn},
		{name: "fatal alias", input: "fatal", expectedLevel: slog.LevelError},
		{name: "panic alias", input: "panic", expectedLevel: slog.LevelError},
		{name: "error uppercase", input: "ERROR", expectedLevel: slog.LevelError},
		{name: "info offset", input: "INFO+1", expectedLevel: slog.LevelInfo + 1},
		{name: "warn negative offset", input: "warn-2", expectedLevel: slog.LevelWarn - 2},
		{name: "unknown", input: "invalid", expectedLevel: slog.LevelInfo, fallback: true},
		{name: "empty", input: "", expectedLevel: slog.LevelInfo, fallback: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			level, fallback := ParseLevel(tc.input)
			if level != tc.expectedLevel {
				t.Fatalf("expected level %v, got %v", tc.expectedLevel, level)
			}
			if fallback != tc.fallback {
				t.Fatalf("expected fallback %v, got %v", tc.fallback, fallback)
			}
		})
	}
}
