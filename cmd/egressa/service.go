//go:build linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/ngthdong/egressa/internal/client"
)

// service runs `egressa run` in the background.
type service interface {
	// Start installs (if needed) and starts the background client.
	Start(exe string) error
	// Stop stops it; it restores the host's routing as it exits.
	Stop() error
	// Hint says where to look when it does not come up.
	Hint() string
}

const unitName = "egressa.service"

// pickService uses systemd when the host has it, unless
// EGRESSA_SERVICE=process asks for a plain background process.
func pickService() service {
	if os.Getenv("EGRESSA_SERVICE") != "process" {
		if _, err := exec.LookPath("systemctl"); err == nil {
			if _, err := os.Stat("/run/systemd/system"); err == nil {
				return systemd{unitPath: "/etc/systemd/system/" + unitName}
			}
		}
	}
	return process{}
}

type systemd struct{ unitPath string }

func unitFile(exe string) string {
	return fmt.Sprintf(`[Unit]
Description=egressa VPN client
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=%s run
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
`, exe)
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (s systemd) Start(exe string) error {
	want := []byte(unitFile(exe))
	if have, err := os.ReadFile(s.unitPath); err != nil || !bytes.Equal(have, want) {
		if err := os.WriteFile(s.unitPath, want, 0o644); err != nil {
			return err
		}
		if err := systemctl("daemon-reload"); err != nil {
			return err
		}
	}
	return systemctl("start", unitName)
}

func (s systemd) Stop() error { return systemctl("stop", unitName) }
func (s systemd) Hint() string {
	return "see: journalctl -u egressa -n 30"
}

// process runs `egressa run` as a detached process logging to a file,
// for hosts without systemd.
type process struct{}

func (process) Start(exe string) error {
	logf, err := os.OpenFile(logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = logf.Close() }()
	cmd := exec.Command(exe, "run")
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

func (process) Stop() error {
	st, err := client.ReadStatus(statusPath())
	if err != nil || !st.Live(time.Now(), time.Minute) {
		return errors.New("no running egressa client found")
	}
	return syscall.Kill(st.PID, syscall.SIGTERM)
}

func (process) Hint() string { return "see: " + logPath() }
