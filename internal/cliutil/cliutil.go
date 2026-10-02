// Package cliutil holds what the cmd/ binaries share.
package cliutil

import (
	"fmt"
	"os"
	"strings"
)

// Secret reads a secret from file if set, else from the environment
// variable env. Secrets are not taken as flags, which every user on the
// host can read from the process list.
func Secret(file, env string) (string, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", file, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv(env), nil
}
