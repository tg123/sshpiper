package logrus

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

type Level int

const (
	PanicLevel Level = 12
	FatalLevel Level = 8
	ErrorLevel Level = 4
	WarnLevel  Level = 2
	InfoLevel  Level = 0
	DebugLevel Level = -4
	TraceLevel Level = -8
)

func (l Level) String() string {
	switch l {
	case PanicLevel:
		return "panic"
	case FatalLevel:
		return "fatal"
	case ErrorLevel:
		return "error"
	case WarnLevel:
		return "warning"
	case InfoLevel:
		return "info"
	case DebugLevel:
		return "debug"
	case TraceLevel:
		return "trace"
	default:
		return slog.Level(l).String()
	}
}

type Formatter interface{}

type JSONFormatter struct{}

type TextFormatter struct {
	ForceColors bool
}

type Logger struct {
	Out       io.Writer
	level     Level
	formatter Formatter
	mu        sync.RWMutex
}

var std = &Logger{Out: os.Stderr, level: InfoLevel}

func StandardLogger() *Logger {
	return std
}

func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Out = w
}

func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

func (l *Logger) GetLevel() Level {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.level
}

func (l *Logger) SetFormatter(formatter Formatter) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.formatter = formatter
}

func (l *Logger) snapshot() (io.Writer, Level, Formatter) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.Out, l.level, l.formatter
}

func (l *Logger) log(level Level, msg string) {
	out, currentLevel, formatter := l.snapshot()
	if level < currentLevel {
		return
	}

	handlerOptions := &slog.HandlerOptions{Level: slog.Level(currentLevel)}

	var handler slog.Handler
	switch formatter.(type) {
	case JSONFormatter, *JSONFormatter:
		handler = slog.NewJSONHandler(out, handlerOptions)
	default:
		handler = slog.NewTextHandler(out, handlerOptions)
	}

	slog.New(handler).Log(context.Background(), slog.Level(level), msg)
}

func ParseLevel(level string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "panic":
		return PanicLevel, nil
	case "fatal":
		return FatalLevel, nil
	case "error":
		return ErrorLevel, nil
	case "warn", "warning":
		return WarnLevel, nil
	case "info":
		return InfoLevel, nil
	case "debug":
		return DebugLevel, nil
	case "trace":
		return TraceLevel, nil
	default:
		return InfoLevel, fmt.Errorf("not a valid log level: %v", level)
	}
}

func SetLevel(level Level) {
	std.SetLevel(level)
}

func GetLevel() Level {
	return std.GetLevel()
}

func SetFormatter(formatter Formatter) {
	std.SetFormatter(formatter)
}

func Info(args ...interface{}) {
	std.log(InfoLevel, fmt.Sprint(args...))
}

func Infof(format string, args ...interface{}) {
	std.log(InfoLevel, fmt.Sprintf(format, args...))
}

func Debug(args ...interface{}) {
	std.log(DebugLevel, fmt.Sprint(args...))
}

func Debugf(format string, args ...interface{}) {
	std.log(DebugLevel, fmt.Sprintf(format, args...))
}

func Warn(args ...interface{}) {
	std.log(WarnLevel, fmt.Sprint(args...))
}

func Warnf(format string, args ...interface{}) {
	std.log(WarnLevel, fmt.Sprintf(format, args...))
}

func Error(args ...interface{}) {
	std.log(ErrorLevel, fmt.Sprint(args...))
}

func Errorf(format string, args ...interface{}) {
	std.log(ErrorLevel, fmt.Sprintf(format, args...))
}

func Printf(format string, args ...interface{}) {
	std.log(InfoLevel, fmt.Sprintf(format, args...))
}

func Fatal(args ...interface{}) {
	std.log(FatalLevel, fmt.Sprint(args...))
	os.Exit(1)
}

func Fatalf(format string, args ...interface{}) {
	std.log(FatalLevel, fmt.Sprintf(format, args...))
	os.Exit(1)
}

func Panic(args ...interface{}) {
	message := fmt.Sprint(args...)
	std.log(PanicLevel, message)
	panic(message)
}

func Panicf(format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	std.log(PanicLevel, message)
	panic(message)
}
