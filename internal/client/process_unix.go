//go:build unix

package client

import (
	"errors"
	"syscall"
)

// processAlive reports whether process pid exists: signal 0 checks
// without sending anything. EPERM means it exists but is not ours.
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
