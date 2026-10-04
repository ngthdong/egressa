//go:build !unix

package client

import "os"

// processAlive reports whether process pid exists. On Windows,
// os.FindProcess opens the process and fails if there is none.
func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = p.Release()
	return true
}
