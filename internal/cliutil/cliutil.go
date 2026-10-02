// Package cliutil holds what the cmd/ binaries share.
package cliutil

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/ngthdong/egressa/internal/buildinfo"
	"github.com/ngthdong/egressa/internal/telemetry"
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

// LogFlags are the logging flags every binary takes.
type LogFlags struct {
	Format string
	Level  string
}

// Register adds --log-format and --log-level to fs.
func (f *LogFlags) Register(fs *flag.FlagSet) {
	fs.StringVar(&f.Format, "log-format", telemetry.FormatText, "log format: text or json")
	fs.StringVar(&f.Level, "log-level", "info", "log level: debug, info, warn or error")
}

// Logger builds the process's logger, writing to stderr, for role (and
// node, a gateway's ID), and makes it slog's default.
func (f *LogFlags) Logger(role, node string) (*slog.Logger, error) {
	l, err := telemetry.NewLogger(telemetry.LogConfig{
		Writer: os.Stderr, Format: f.Format, Level: f.Level,
		Role: role, Node: node, Version: buildinfo.Version,
	})
	if err != nil {
		return nil, err
	}
	slog.SetDefault(l)
	return l, nil
}

// Fatal logs msg and err at ERROR and exits 1.
func Fatal(l *slog.Logger, msg string, err error) {
	l.Error(msg, telemetry.Err(err))
	os.Exit(1)
}

// Metrics starts serving the metrics of a process of role on addr and
// returns its registry; with no addr it returns nil, and every metrics
// value made from a nil registry records nothing.
func Metrics(ctx context.Context, addr, role string, l *slog.Logger) (*telemetry.Registry, error) {
	if addr == "" {
		return nil, nil
	}
	reg := telemetry.NewRegistry(role, buildinfo.Version, buildinfo.Commit)
	if _, err := telemetry.ServeMetrics(ctx, addr, reg, l); err != nil {
		return nil, fmt.Errorf("--metrics-listen %s: %w", addr, err)
	}
	return reg, nil
}

// MetricsFlagHelp is the help text of every binary's --metrics-listen.
const MetricsFlagHelp = "serve Prometheus metrics on /metrics at this address, e.g. 127.0.0.1:9100 (default: off); it has no authentication, so keep it private"
