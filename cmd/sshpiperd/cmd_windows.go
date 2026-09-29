//go:build windows

package main

import (
	"log/slog"
	"os/exec"
	"runtime"
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

	// Do not reflect into os.Process's private handle field: its representation
	// changes between Go versions. Open our own non-inheritable handle with the
	// access rights required by AssignProcessToJobObject instead.
	defer runtime.KeepAlive(cmd.Process)
	handle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	return windows.AssignProcessToJobObject(jobObject, handle)
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
