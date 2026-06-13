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
		wantErr       bool
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
		{name: "unknown", input: "invalid", expectedLevel: slog.LevelInfo, wantErr: true},
		{name: "empty", input: "", expectedLevel: slog.LevelInfo, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			level, err := ParseLevel(tc.input)
			if level != tc.expectedLevel {
				t.Fatalf("expected level %v, got %v", tc.expectedLevel, level)
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("expected wantErr %v, got err %v", tc.wantErr, err)
			}
		})
	}
}
