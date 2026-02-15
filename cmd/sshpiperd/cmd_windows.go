//go:build windows

package main

import (
	"os/exec"

	"github.com/tg123/jobobject"
	log "github.com/tg123/sshpiper/internal/slogrus"
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
		log.Warnf("failed to create job object: %v", err)
	}
}
