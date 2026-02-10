//go:build !linux && !windows

package main

import "os/exec"

func setPdeathsig(cmd *exec.Cmd) {
}

func addProcessToJob(_ *exec.Cmd) error {
	return nil
}
