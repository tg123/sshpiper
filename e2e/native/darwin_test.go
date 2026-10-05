//go:build darwin && e2e

package native_test

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestMacOSE2E(t *testing.T) {
	testNativeE2E(t, nil)
}

func configureDaemon(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func killDaemon(p *daemonProcess) error {
	// Unlike Windows Job Objects, macOS does not kill plugins with the daemon.
	err := syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}
