package main

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func TestCreateLogger(t *testing.T) {

	// flags
	{
		logger := loggerConfig{LogLevel: "trace"}.createLogger()

		if logger.GetLevel().String() != "trace" {
			t.Errorf("logger level not set")
		}
	}

	// file
	{
		tmpfile, err := ioutil.TempFile("", "sshpiperlog")
		if err != nil {
			t.Errorf("failed to create tmp file %v", err)
		}
		defer os.Remove(tmpfile.Name()) // clean up

		logger := loggerConfig{LogFile: tmpfile.Name()}.createLogger()

		logger.Print("test123")

		s, _ := ioutil.ReadFile(tmpfile.Name())

		if !strings.Contains(string(s), "test123") {

			t.Errorf("log failed")
		}
	}
}
