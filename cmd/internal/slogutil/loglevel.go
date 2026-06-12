package slogutil

import (
	"log/slog"
	"strings"
)

const DefaultLevelName = "info"

// ParseLevel parses slog level names and falls back to info for unknown values.
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
