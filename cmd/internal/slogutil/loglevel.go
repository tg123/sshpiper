package slogutil

import (
	"log/slog"
	"strings"
)

const DefaultLevelName = "info"

// ParseLevel parses slog level names ("debug", "info", "warn", "error"),
// plus offsets supported by slog.Level.UnmarshalText (e.g. "info+1", "warn-2").
// It returns the parsed level and whether the fallback (info) was used.
func ParseLevel(logLevel string) (slog.Level, bool) {
	// Silent legacy aliases for logrus-era SSHPIPERD_LOG_LEVEL values.
	// Intentionally NOT advertised in flag help, READMEs, or this doc.
	switch strings.ToLower(logLevel) {
	case "trace":
		return slog.LevelDebug, false
	case "warning":
		return slog.LevelWarn, false
	case "panic", "fatal":
		return slog.LevelError, false
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(logLevel)); err != nil {
		return slog.LevelInfo, true
	}
	return level, false
}
