// Package telemetry is egressa's observability: structured logs
// (logging.go), trace IDs and spans for sessions and migrations
// (tracing.go), and Prometheus metrics (metrics.go).
//
// The agents (internal/client, internal/gateway, internal/controller)
// never import Prometheus: they get a *slog.Logger, a *Tracer and a
// metrics value of this package through their Config, hand it plain Go
// values, and every method works on a nil receiver, so an agent built
// without telemetry needs no checks.
package telemetry

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// Log formats.
const (
	FormatText = "text"
	FormatJSON = "json"
)

// LogConfig configures NewLogger.
type LogConfig struct {
	Writer io.Writer
	// Format is FormatText (the default) or FormatJSON.
	Format string
	// Level is debug, info (the default), warn or error.
	Level string
	// Role is controller, gateway or client; Node is the gateway's ID,
	// if any; Version is the build's version.
	Role    string
	Node    string
	Version string
}

// ParseLevel parses a log level name.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("telemetry: unknown log level %q (want debug, info, warn or error)", s)
}

// NewLogger returns a logger writing cfg.Format records at cfg.Level and
// above to cfg.Writer. Every record carries role, node (when set) and
// version, and the trace_id, session and epoch of the context it is
// logged with (see WithSession and WithMigration).
func NewLogger(cfg LogConfig) (*slog.Logger, error) {
	level, err := ParseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}
	if cfg.Writer == nil {
		return nil, fmt.Errorf("telemetry: a log writer is required")
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	switch strings.ToLower(cfg.Format) {
	case "", FormatText:
		h = slog.NewTextHandler(cfg.Writer, opts)
	case FormatJSON:
		h = slog.NewJSONHandler(cfg.Writer, opts)
	default:
		return nil, fmt.Errorf("telemetry: unknown log format %q (want text or json)", cfg.Format)
	}
	attrs := []slog.Attr{slog.String("role", cfg.Role)}
	if cfg.Node != "" {
		attrs = append(attrs, slog.String("node", cfg.Node))
	}
	attrs = append(attrs, slog.String("version", cfg.Version))
	return slog.New(ContextHandler(h.WithAttrs(attrs))), nil
}

// ContextHandler wraps h so every record also carries the trace_id,
// session and epoch stored in the context it is logged with.
func ContextHandler(h slog.Handler) slog.Handler { return contextHandler{h} }

type contextHandler struct{ slog.Handler }

func (h contextHandler) Handle(ctx context.Context, r slog.Record) error {
	if t, ok := fromContext(ctx); ok {
		if t.traceID != "" {
			r.AddAttrs(slog.String("trace_id", t.traceID))
		}
		if t.session != "" {
			r.AddAttrs(slog.String("session", t.session))
		}
		if t.hasEpoch {
			r.AddAttrs(slog.Uint64("epoch", t.epoch))
		}
	}
	return h.Handler.Handle(ctx, r)
}

func (h contextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return contextHandler{h.Handler.WithAttrs(attrs)}
}

func (h contextHandler) WithGroup(name string) slog.Handler {
	return contextHandler{h.Handler.WithGroup(name)}
}

// Secret is a value that must never be logged: a token, a session secret
// or a key. It logs as REDACTED in every format.
type Secret string

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue("REDACTED") }

// String keeps a Secret out of %v and %s too.
func (Secret) String() string { return "REDACTED" }

// Err is the attribute every log record uses for an error.
func Err(err error) slog.Attr {
	if err == nil {
		return slog.Attr{}
	}
	return slog.String("err", err.Error())
}

// Discard returns a logger that drops everything, for tests and for
// agents built without a logger.
func Discard() *slog.Logger { return slog.New(slog.DiscardHandler) }
