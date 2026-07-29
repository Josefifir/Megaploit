//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// detachSysProcAttr returns a SysProcAttr that starts the child process
// in its own new process group, detached from the parent's terminal session.
// This mirrors Python's os.setsid() / subprocess.Popen with start_new_session=True.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid: true, // new session — detaches from controlling tty
	}
}

// Ensure exec is imported (used by callers through cmd.SysProcAttr).
var _ = (*exec.Cmd)(nil)
