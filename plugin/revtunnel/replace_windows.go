//go:build (full || e2e) && windows

package main

import "golang.org/x/sys/windows"

func atomicReplace(src, dst string) error {
	srcp, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	dstp, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(
		srcp,
		dstp,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH,
	)
}
