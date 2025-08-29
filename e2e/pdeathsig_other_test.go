//go:build !linux

package e2e_test

import (
	"syscall"
)

var sigtermForPdeathsig *syscall.SysProcAttr
