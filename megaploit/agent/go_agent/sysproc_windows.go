//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// detachSysProcAttr returns a SysProcAttr that creates the child process
// with CREATE_NEW_PROCESS_GROUP so it is not killed when the parent exits.
// Windows has no concept of setsid; CREATE_NEW_PROCESS_GROUP is the closest
// equivalent for detached background process spawning.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
}

// Ensure exec is imported.
var _ = (*exec.Cmd)(nil)
