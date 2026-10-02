package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func newTestLogger(t *testing.T, format string) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	l, err := NewLogger(LogConfig{Writer: &buf, Format: format, Level: "debug", Role: "gateway", Node: "hk", Version: "v1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	return l, &buf
}

func decodeLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not JSON: %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func TestNewLogger_JSONCarriesRootAndContextAttrs(t *testing.T) {
	l, buf := newTestLogger(t, FormatJSON)
	ctx := WithMigration(context.Background(), "42", 7)
	l.InfoContext(ctx, "migration committed", "access", "sg")
	l.Info("no context")

	recs := decodeLines(t, buf)
	if len(recs) != 2 {
		t.Fatalf("%d records", len(recs))
	}
	r := recs[0]
	for k, want := range map[string]any{
		"msg": "migration committed", "level": "INFO", "role": "gateway", "node": "hk", "version": "v1.2.3",
		"trace_id": MigrationTraceID("42", 7), "session": "42", "epoch": float64(7), "access": "sg",
	} {
		if r[k] != want {
			t.Errorf("%s = %v, want %v", k, r[k], want)
		}
	}
	if _, ok := recs[1]["trace_id"]; ok {
		t.Error("a record logged without a trace context has a trace_id")
	}
	if recs[1]["role"] != "gateway" {
		t.Error("root attributes missing without a context")
	}
}

func TestNewLogger_TextAndLevels(t *testing.T) {
	var buf bytes.Buffer
	l, err := NewLogger(LogConfig{Writer: &buf, Level: "warn", Role: "client", Version: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	l.Info("hidden")
	l.Warn("shown", Err(errors.New("boom")))
	out := buf.String()
	if strings.Contains(out, "hidden") || !strings.Contains(out, "msg=shown") || !strings.Contains(out, "err=boom") {
		t.Fatalf("text output %q", out)
	}
	if strings.Contains(out, "node=") {
		t.Error("node attribute without a node")
	}
	// Groups and attributes keep the context handler.
	buf.Reset()
	l.With("a", 1).WithGroup("g").WarnContext(WithSession(context.Background(), "9"), "grouped", "b", 2)
	if !strings.Contains(buf.String(), "trace_id="+SessionTraceID("9")) || !strings.Contains(buf.String(), "g.b=2") {
		t.Fatalf("grouped output %q", buf.String())
	}
}

func TestNewLogger_Errors(t *testing.T) {
	if _, err := NewLogger(LogConfig{Writer: &bytes.Buffer{}, Format: "xml"}); err == nil {
		t.Error("accepted format xml")
	}
	if _, err := NewLogger(LogConfig{Writer: &bytes.Buffer{}, Level: "loud"}); err == nil {
		t.Error("accepted level loud")
	}
	if _, err := NewLogger(LogConfig{}); err == nil {
		t.Error("accepted no writer")
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]slog.Level{
		"debug": slog.LevelDebug, "": slog.LevelInfo, "INFO": slog.LevelInfo,
		"warn": slog.LevelWarn, "warning": slog.LevelWarn, "error": slog.LevelError,
	} {
		if got, err := ParseLevel(in); err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v", in, got, err)
		}
	}
}

func TestSecret_RedactedInEveryFormat(t *testing.T) {
	const secret = "s3cr3t-token-value"
	for _, format := range []string{FormatText, FormatJSON} {
		l, buf := newTestLogger(t, format)
		l.Info("starting", "token", Secret(secret), slog.Any("nested", Secret(secret)))
		out := buf.String()
		if strings.Contains(out, secret) || strings.Count(out, "REDACTED") != 2 {
			t.Errorf("%s: %q", format, out)
		}
	}
	if got := fmt.Sprintf("%v %s", Secret(secret), Secret(secret)); got != "REDACTED REDACTED" {
		t.Errorf("formatted as %q", got)
	}
}

func TestErrAndDiscard(t *testing.T) {
	if a := Err(nil); !a.Equal(slog.Attr{}) {
		t.Errorf("Err(nil) = %v", a)
	}
	if a := Err(errors.New("x")); a.Key != "err" || a.Value.String() != "x" {
		t.Errorf("Err = %v", a)
	}
	Discard().Info("dropped") // must not panic
	if Discard().Enabled(context.Background(), slog.LevelError) {
		t.Error("Discard is enabled")
	}
}
