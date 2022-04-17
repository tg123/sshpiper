package main

import (
	"os"

	log "github.com/sirupsen/logrus"
)

type loggerConfig struct {
	LogFile string `long:"log" description:"LogFile path. Leave empty or any error occurs will fall back to stdout" env:"SSHPIPERD_LOG_PATH" ini-name:"log-path"`

	LogLevel string `long:"log-level" default:"info" description:"These are the different logging levels, see https://pkg.go.dev/github.com/sirupsen/logrus#Level" env:"SSHPIPERD_LOG_LEVEL" ini-name:"log-level"`
}

func (l loggerConfig) createLogger() (logger *log.Logger) {

	logger = log.New()

	if l.LogFile != "" {
		f, err := os.OpenFile(l.LogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			logger.Printf("cannot open log file %v", err)
			return
		}

		logger.SetOutput(f)
	}

	if l.LogLevel == "" {
		l.LogLevel = "info"
	}

	level, err := log.ParseLevel(l.LogLevel)
	if err != nil {
		log.Fatalf("parse log level %v error %v", l.LogLevel, err)
		return
	}

	logger.SetLevel(level)

	return
}
