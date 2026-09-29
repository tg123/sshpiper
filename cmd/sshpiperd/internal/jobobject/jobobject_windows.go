//go:build windows

// Package jobobject manages plugin processes that must exit with sshpiperd.
package jobobject

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

type JobObject struct {
	handle windows.Handle
}

func Create() (*JobObject, error) {
	handle, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create job object: %w", err)
	}

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(handle, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("set job object limits: %w", err)
	}

	return &JobObject{handle: handle}, nil
}

func (j *JobObject) Close() error {
	return windows.CloseHandle(j.handle)
}

// AddProcess assigns a started process before its caller waits for or releases it.
func (j *JobObject) AddProcess(p *os.Process) error {
	// os.Process's private handle representation changes between Go versions.
	// Open our own non-inheritable handle using the public PID and the access
	// rights required by AssignProcessToJobObject instead of reflecting into it.
	// Keep p alive until assignment completes so Go retains its process handle.
	defer runtime.KeepAlive(p)
	handle, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(p.Pid))
	if err != nil {
		return fmt.Errorf("open process %d for job object: %w", p.Pid, err)
	}
	defer windows.CloseHandle(handle)

	if err := windows.AssignProcessToJobObject(j.handle, handle); err != nil {
		return fmt.Errorf("assign process %d to job object: %w", p.Pid, err)
	}
	return nil
}
