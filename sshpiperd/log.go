package main

import (
	"log"
	"os"
)

var (
	logger = log.New(os.Stdout, "", log.Ldate|log.Ltime)
)

func initLogger(file string) {
	// change this value for display might be not a good idea
	if file != "" {
		f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			logger.Printf("cannot open log file %v", err)
			return
		}

		logger = log.New(f, "", logger.Flags())
	}
}
