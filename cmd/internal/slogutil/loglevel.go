package slogutil

import (
	"log/slog"
	"strings"
)

const DefaultLevelName = "info"

// ParseLevel parses slog level names ("debug", "info", "warn", "error") and
// falls back to info for unknown values.
// It returns the parsed level and whether fallback was used.
func ParseLevel(logLevel string) (slog.Level, bool) {
	switch strings.ToLower(logLevel) {
	case "debug":
		return slog.LevelDebug, false
	case "info":
		return slog.LevelInfo, false
	case "warn":
		return slog.LevelWarn, false
	case "error":
		return slog.LevelError, false
	default:
		return slog.LevelInfo, true
	}
}

// LevelName returns the canonical slog level name used by CLI/plugin config.
func LevelName(level slog.Level) string {
	switch level {
	case slog.LevelDebug:
		return "debug"
	case slog.LevelInfo:
		return "info"
	case slog.LevelWarn:
		return "warn"
	case slog.LevelError:
		return "error"
	default:
		return DefaultLevelName
	}
}
