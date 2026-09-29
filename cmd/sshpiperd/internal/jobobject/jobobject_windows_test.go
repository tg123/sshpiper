//go:build windows

package jobobject

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestJobObjectChild(t *testing.T) {
	if os.Getenv("SSHPIPER_JOB_OBJECT_TEST_CHILD") != "1" {
		return
	}
	fmt.Println("ready")
	io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

func startChild(t *testing.T) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestJobObjectChild$")
	cmd.Env = append(os.Environ(), "SSHPIPER_JOB_OBJECT_TEST_CHILD=1")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close() })
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	ready := make(chan error, 1)
	go func() {
		line, err := bufio.NewReader(out).ReadString('\n')
		if err == nil && line != "ready\n" {
			err = fmt.Errorf("unexpected child output: %q", line)
		}
		ready <- err
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child did not become ready")
	}
	return cmd
}

func TestAddProcessAndKillOnClose(t *testing.T) {
	j, err := Create()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if j != nil {
			j.Close()
		}
	})
	cmd := startChild(t)
	if err := j.AddProcess(cmd.Process); err != nil {
		t.Fatal(err)
	}

	// Hold an independent synchronization handle to verify that closing the job
	// actually terminates the child, without releasing cmd.Process beforehand.
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	if status, err := windows.WaitForSingleObject(handle, 0); err != nil || status != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("child exited before job closed: status=%d err=%v", status, err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j = nil
	if status, err := windows.WaitForSingleObject(handle, 10000); err != nil || status != windows.WAIT_OBJECT_0 {
		t.Fatalf("child survived job close: status=%d err=%v", status, err)
	}
}

func TestAddProcessErrors(t *testing.T) {
	j, err := Create()
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	// PID zero is rejected by OpenProcess, and must return an error, not panic.
	if err := j.AddProcess(&os.Process{Pid: 0}); !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		t.Fatalf("expected OpenProcess error, got %v", err)
	}
	cmd := startChild(t)
	invalidJob := &JobObject{handle: windows.InvalidHandle}
	if err := invalidJob.AddProcess(cmd.Process); !errors.Is(err, windows.ERROR_INVALID_HANDLE) {
		t.Fatalf("expected AssignProcessToJobObject error, got %v", err)
	}
}
