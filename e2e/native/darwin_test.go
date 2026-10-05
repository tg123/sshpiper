//go:build darwin && e2e

package native_test

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestMacOSE2E(t *testing.T) {
	testNativeE2E(t, nil)
}

func startDaemonProcess(p *daemonProcess) error {
	helper, err := os.Executable()
	if err != nil {
		return err
	}
	control, lifetime, err := os.Pipe()
	if err != nil {
		return err
	}
	defer control.Close()
	p.requestStop = lifetime.Close
	p.cmd.Args = append([]string{helper, "-test.run=^TestMacOSDaemonSupervisor$", "--"}, p.cmd.Args...)
	p.cmd.Path = helper
	p.cmd.ExtraFiles = []*os.File{control}
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := p.cmd.Start(); err != nil {
		return errors.Join(err, lifetime.Close())
	}
	return nil
}

func killDaemon(p *daemonProcess) error {
	err := p.requestStop()
	if errors.Is(err, os.ErrClosed) {
		err = nil
	}
	select {
	case <-p.done:
		return errors.Join(err, p.err)
	case <-time.After(waitTimeout):
		return errors.Join(err, fmt.Errorf("daemon supervisor cleanup timed out"))
	}
}

func TestMacOSSupervisorLifetime(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "daemon.pid")
	p := &daemonProcess{
		cmd:  exec.Command("/bin/sh", "-c", `sleep 300 & printf '%s %s' "$$" "$!" > "$1"; wait`, "daemon fixture", pidFile),
		done: make(chan struct{}),
	}
	p.cmd.Stdout = os.Stdout
	p.cmd.Stderr = os.Stderr
	if err := startDaemonProcess(p); err != nil {
		t.Fatal(err)
	}
	go func() {
		p.err = p.cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() {
		if err := killDaemon(p); err != nil {
			t.Errorf("clean up supervisor fixture: %v", err)
		}
	})
	var pids []int
	waitFor(t, "supervised daemon and child", func() bool {
		p.checkRunning(t)
		data, err := os.ReadFile(pidFile)
		if errors.Is(err, os.ErrNotExist) {
			return false
		}
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(data))
		if len(fields) != 2 {
			return false
		}
		for _, field := range fields {
			pid, err := strconv.Atoi(field)
			if err != nil || pid <= 0 {
				t.Fatalf("invalid fixture PID %q: %v", field, err)
			}
			pids = append(pids, pid)
		}
		return true
	})
	// Closing the only writer simulates the kernel closing it on parent death,
	// without invoking the normal daemon cleanup callback.
	if err := p.requestStop(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.done:
		if p.err != nil {
			t.Fatalf("supervisor failed: %v", p.err)
		}
	case <-time.After(waitTimeout):
		t.Fatal("supervisor survived parent EOF")
	}
	waitFor(t, "daemon and child termination", func() bool {
		for _, pid := range pids {
			if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
				if err != nil {
					t.Fatalf("check supervised PID %d: %v", pid, err)
				}
				return false
			}
		}
		return true
	})
}

// EOF also arrives when the parent test times out or is killed, when t.Cleanup
// cannot run. The supervisor stays outside the terminal's interrupt group.
func TestMacOSDaemonSupervisor(t *testing.T) {
	args := flag.Args()
	if len(args) == 0 {
		t.Skip("subprocess helper")
	}
	control := os.NewFile(3, "test lifetime")
	syscall.CloseOnExec(3)
	defer control.Close()
	cmd := exec.Command(args[0], args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	closed := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, control)
		closed <- err
	}()
	var exited bool
	var exitErr error
	select {
	case exitErr = <-done:
		exited = true
	case err := <-closed:
		if err != nil {
			t.Errorf("read test lifetime: %v", err)
		}
	}
	// Kill the entire owned group, including plugins even if the daemon exited.
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		t.Errorf("kill daemon process group: %v", err)
	}
	if exited {
		t.Fatalf("daemon exited unexpectedly: %v", exitErr)
	}
	select {
	case <-done:
	case <-time.After(waitTimeout):
		t.Fatal("daemon cleanup timed out")
	}
}
