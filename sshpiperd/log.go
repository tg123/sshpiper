package main

import (
	"log"
	"os"
)

type loggerConfig struct {
	LogFile string `long:"log" description:"LogFile path. Leave empty or any error occurs will fall back to stdout" env:"SSHPIPERD_LOG_PATH" ini-name:"log-path"`

	LogFlags int `long:"log-flags" default:"3" description:"Flags for logger see https://godoc.org/log, default LstdFlags" env:"SSHPIPERD_LOG_FLAGS" ini-name:"log-flags"`
}

func (l loggerConfig) createLogger() (logger *log.Logger) {

	logger = log.New(os.Stdout, "", l.LogFlags)

	if l.LogFile != "" {
		f, err := os.OpenFile(l.LogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			logger.Printf("cannot open log file %v", err)
			return
		}

		logger = log.New(f, "", logger.Flags())
	}

	return
}
