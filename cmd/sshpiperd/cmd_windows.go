//go:build windows

package main

import (
	"os/exec"

	"github.com/tg123/jobobject"
	"log/slog"
)

func setPdeathsig(cmd *exec.Cmd) {
}

func addProcessToJob(cmd *exec.Cmd) error {
	if jobObject == nil {
		return nil
	}

	if cmd.Process == nil {
		return nil
	}

	return jobObject.AddProcess(cmd.Process)
}

var jobObject *jobobject.JobObject

func init() {
	var err error
	jobObject, err = jobobject.Create()
	if err != nil {
		slog.Warn("failed to create job object", "error", err)
	}
}
