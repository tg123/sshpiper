package slogutil

import (
	"log/slog"
	"strings"
)

// ParseLevel parses slog level names ("debug", "info", "warn", "error"),
// plus offsets supported by slog.Level.UnmarshalText (e.g. "info+1", "warn-2").
// On unrecognized input it returns slog.LevelInfo and a non-nil error so
// callers can decide whether to warn and continue or fail hard.
func ParseLevel(input string) (slog.Level, error) {
	// Silent legacy aliases for logrus-era SSHPIPERD_LOG_LEVEL values.
	// Intentionally NOT advertised in flag help, READMEs, or this doc.
	switch strings.ToLower(input) {
	case "trace":
		return slog.LevelDebug, nil
	case "warning":
		return slog.LevelWarn, nil
	case "panic", "fatal":
		return slog.LevelError, nil
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(input)); err != nil {
		return slog.LevelInfo, err
	}
	return level, nil
}
