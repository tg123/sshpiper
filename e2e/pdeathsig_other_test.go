//go:build !linux

package e2e_test

import (
	"syscall"
)

func sigtermForPdeathsig() *syscall.SysProcAttr {
	return nil
}
