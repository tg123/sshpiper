//go:build windows

package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

func TestAddProcessToJob(t *testing.T) {
	if jobObject == 0 {
		t.Fatal("Windows job object was not initialized")
	}
	if err := addProcessToJob(&exec.Cmd{}); err != nil {
		t.Fatalf("unstarted process: %v", err)
	}

	cmd, stdin := startJobTestProcess(t)
	if err := addProcessToJob(cmd); err != nil {
		t.Fatalf("assign running process: %v", err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait for assigned process: %v", err)
	}
	wantErr := cmd.Process.WithHandle(func(uintptr) {
		t.Error("waited process still has a handle")
	})
	if wantErr == nil {
		t.Fatal("WithHandle accepted a waited process")
	}
	if err := addProcessToJob(cmd); !errors.Is(err, wantErr) {
		t.Fatalf("assign waited process: got %v, want %v", err, wantErr)
	}
}

func TestAddProcessToJobAssignmentError(t *testing.T) {
	cmd, _ := startJobTestProcess(t)
	savedJob := jobObject
	jobObject = windows.InvalidHandle
	t.Cleanup(func() { jobObject = savedJob })

	if err := addProcessToJob(cmd); !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
		t.Fatalf("assign to invalid job: got %v, want ERROR_INVALID_HANDLE", err)
	}
}

func startJobTestProcess(t *testing.T) (*exec.Cmd, io.WriteCloser) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestJobProcessHelper$")
	cmd.Env = append(os.Environ(), "SSHPIPERD_JOB_TEST_HELPER=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		if cmd.Process != nil && cmd.ProcessState == nil {
			if err := cmd.Wait(); err != nil {
				t.Errorf("wait for helper: %v", err)
			}
		}
	})
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	return cmd, stdin
}

func TestJobProcessHelper(t *testing.T) {
	if os.Getenv("SSHPIPERD_JOB_TEST_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		t.Fatal(err)
	}
}
