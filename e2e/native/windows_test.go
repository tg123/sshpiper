//go:build windows && e2e

package native_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/tg123/sshpiper/libplugin"
	"golang.org/x/sys/windows"
)

func TestWindowsE2E(t *testing.T) {
	testNativeE2E(t, testWindowsJobCleanup)
}

func startDaemonProcess(p *daemonProcess) error {
	if err := p.cmd.Start(); err != nil {
		return err
	}
	p.requestStop = p.cmd.Process.Kill
	return nil
}

func killDaemon(p *daemonProcess) error {
	select {
	case <-p.done:
		return nil
	default:
		return p.requestStop()
	}
}

func testWindowsJobCleanup(t *testing.T, s *nativeSuite) {
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pidFile := filepath.Join(t.TempDir(), "plugin.pid")
	piper := startDaemon(t, s.daemon, s.keyPath, []string{"SSHPIPER_WINDOWS_JOB_PID=" + pidFile},
		helper, "-test.run=^TestWindowsJobPlugin$")
	var handle windows.Handle
	waitFor(t, "plugin PID", func() bool {
		data, err := os.ReadFile(pidFile)
		if errors.Is(err, os.ErrNotExist) || (err == nil && len(data) == 0) {
			piper.checkRunning(t)
			return false
		}
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.ParseUint(string(data), 10, 32)
		if err != nil {
			t.Fatalf("parse plugin PID: %v", err)
		}
		handle, err = windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, uint32(pid))
		if err != nil {
			t.Fatalf("open plugin process: %v", err)
		}
		return true
	})
	t.Cleanup(func() {
		defer windows.CloseHandle(handle)
		state, err := windows.WaitForSingleObject(handle, 0)
		if err != nil {
			t.Errorf("query plugin process: %v", err)
			return
		}
		if state == uint32(windows.WAIT_TIMEOUT) {
			if err := windows.TerminateProcess(handle, 1); err != nil {
				t.Errorf("clean up plugin: %v", err)
			}
			if state, err := windows.WaitForSingleObject(handle, uint32(waitTimeout.Milliseconds())); err != nil || state != windows.WAIT_OBJECT_0 {
				t.Errorf("wait for plugin cleanup: state=%d, err=%v", state, err)
			}
		}
	})
	piper.waitReady(t)
	if state, err := windows.WaitForSingleObject(handle, 0); err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("plugin is not running: state=%d, err=%v", state, err)
	}
	if err := piper.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-piper.done:
	case <-time.After(waitTimeout):
		t.Fatal("daemon did not exit after Kill")
	}
	// Wait on a retained handle, not a PID that Windows could reuse.
	if state, err := windows.WaitForSingleObject(handle, uint32(waitTimeout.Milliseconds())); err != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatalf("plugin survived daemon termination: state=%d, err=%v", state, err)
	}
}

// This subprocess deliberately survives stdio EOF, so closing the transport
// cannot make the job-object cleanup test pass without KILL_ON_JOB_CLOSE.
func TestWindowsJobPlugin(t *testing.T) {
	pidFile := os.Getenv("SSHPIPER_WINDOWS_JOB_PID")
	if pidFile == "" {
		t.Skip("subprocess helper")
	}
	plugin, err := libplugin.NewFromStdio(libplugin.SshPiperPluginConfig{
		PasswordCallback: func(libplugin.ConnMetadata, []byte) (*libplugin.Upstream, error) {
			return nil, errors.New("lifetime-test plugin does not authenticate")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	go func() {
		if err := plugin.Serve(); err != nil {
			fmt.Fprintf(os.Stderr, "plugin transport closed: %v\n", err)
		}
	}()
	time.Sleep(5 * time.Minute)
	t.Fatal("lifetime-test plugin was not terminated")
}
