//go:build linux

package main

import (
	"os/exec"
	"syscall"

	reaper "github.com/ramr/go-reaper"
)

func init() {
	go reaper.Reap()
}

func setPdeathsig(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}

func addProcessToJob(cmd *exec.Cmd) error {
	return nil
}
