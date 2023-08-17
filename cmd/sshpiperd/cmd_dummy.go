//go:build !linux && !windows

package main

import "os/exec"

func setPdeathsig(cmd *exec.Cmd) {
}

func addProcessToJob(cmd *exec.Cmd) error {
	return nil
}
