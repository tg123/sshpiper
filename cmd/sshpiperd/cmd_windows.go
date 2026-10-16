//go:build windows

package main

import (
	"log/slog"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

func setPdeathsig(cmd *exec.Cmd) {
}

func addProcessToJob(cmd *exec.Cmd) error {
	if jobObject == 0 {
		return nil
	}

	if cmd.Process == nil {
		return nil
	}

	// Retain the original handle even if the plugin's concurrent Wait completes.
	var assignErr error
	if err := cmd.Process.WithHandle(func(handle uintptr) {
		assignErr = windows.AssignProcessToJobObject(jobObject, windows.Handle(handle))
	}); err != nil {
		return err
	}
	return assignErr
}

var jobObject windows.Handle

func init() {
	handle, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		slog.Warn("failed to create job object", "error", err)
		return
	}

	// Keep the job handle open for the daemon's lifetime so Windows terminates
	// plugin processes when the daemon exits, including an unexpected exit.
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(handle, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(handle)
		slog.Warn("failed to set job object limits", "error", err)
		return
	}
	jobObject = handle
}
