package telemetry

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"
)

var traceIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

func TestTraceIDs_Deterministic(t *testing.T) {
	s := SessionTraceID("8245435961501267382")
	if s != SessionTraceID("8245435961501267382") || !traceIDRE.MatchString(s) {
		t.Fatalf("session trace ID %q", s)
	}
	if s == SessionTraceID("8245435961501267383") {
		t.Error("two sessions share a trace ID")
	}
	m := MigrationTraceID("8245435961501267382", 2)
	if m != MigrationTraceID("8245435961501267382", 2) || !traceIDRE.MatchString(m) {
		t.Fatalf("migration trace ID %q", m)
	}
	for name, other := range map[string]string{
		"another epoch":        MigrationTraceID("8245435961501267382", 3),
		"another session":      MigrationTraceID("8245435961501267383", 2),
		"the session trace":    s,
		"a shifted separator":  MigrationTraceID("824543596150126738", 22),
		"the empty session ID": MigrationTraceID("", 2),
	} {
		if other == m {
			t.Errorf("%s has the same trace ID", name)
		}
	}
}

func TestContext(t *testing.T) {
	bg := context.Background()
	if _, ok := TraceID(bg); ok {
		t.Error("trace ID in an empty context")
	}
	if _, ok := Session(bg); ok {
		t.Error("session in an empty context")
	}
	if _, ok := Epoch(bg); ok {
		t.Error("epoch in an empty context")
	}
	//nolint:staticcheck // a nil context must not panic
	if _, ok := fromContext(nil); ok {
		t.Error("nil context carries a trace")
	}

	ctx := WithSession(bg, "7")
	if id, ok := TraceID(ctx); !ok || id != SessionTraceID("7") {
		t.Errorf("session trace %q", id)
	}
	if s, ok := Session(ctx); !ok || s != "7" {
		t.Errorf("session %q", s)
	}
	if _, ok := Epoch(ctx); ok {
		t.Error("a session context has an epoch")
	}

	ctx = WithMigration(ctx, "7", 3)
	if id, _ := TraceID(ctx); id != MigrationTraceID("7", 3) {
		t.Errorf("migration trace %q", id)
	}
	if e, ok := Epoch(ctx); !ok || e != 3 {
		t.Errorf("epoch %d", e)
	}
}

// fakeClock advances by step on every reading.
type fakeClock struct {
	t    time.Time
	step time.Duration
}

func (c *fakeClock) now() time.Time { now := c.t; c.t = c.t.Add(c.step); return now }

func TestSpan_LogsDurationAndStatus(t *testing.T) {
	l, buf := newTestLogger(t, FormatJSON)
	clock := &fakeClock{t: time.Date(2026, 10, 2, 5, 0, 0, 0, time.UTC), step: 1500 * time.Microsecond}
	tr := NewTracer(l, clock.now)
	ctx := WithMigration(context.Background(), "42", 3)

	s := tr.Start(ctx, "migration.commit", slog.String("access", "sg"))
	s.SetAttrs(slog.String("egress", "hk"))
	s.End(nil)
	s.End(errors.New("ignored: already ended"))

	tr.Start(ctx, "migration.cas").EndStatus(StatusConflict, errors.New("epoch moved"))
	tr.Start(WithSession(context.Background(), "42"), "migration.apply").End(errors.New("ip: exit 2"))
	tr.StartAt(context.Background(), "migration.decide", clock.t.Add(-time.Second)).End(nil)

	recs := decodeLines(t, buf)
	if len(recs) != 4 {
		t.Fatalf("%d span records, want 4 (End twice must log once):\n%s", len(recs), buf)
	}
	want := []map[string]any{
		{"msg": "span", "span": "migration.commit", "status": "ok", "duration_ms": 1.5, "start": "2026-10-02T05:00:00Z",
			"trace_id": MigrationTraceID("42", 3), "session": "42", "epoch": float64(3), "access": "sg", "egress": "hk", "level": "INFO"},
		{"span": "migration.cas", "status": "conflict", "err": "epoch moved", "level": "INFO"},
		{"span": "migration.apply", "status": "error", "trace_id": SessionTraceID("42"), "level": "WARN"},
		{"span": "migration.decide", "status": "ok", "duration_ms": 1000.0},
	}
	for i, w := range want {
		for k, v := range w {
			if recs[i][k] != v {
				t.Errorf("record %d: %s = %v, want %v", i, k, recs[i][k], v)
			}
		}
	}
	if _, ok := recs[2]["epoch"]; ok {
		t.Error("a session span has an epoch")
	}
	if _, ok := recs[3]["trace_id"]; ok {
		t.Error("a span without a trace context has a trace_id")
	}
	// The trace fields appear once, not again from the context handler.
	if n := strings.Count(buf.String(), `"trace_id"`); n != 3 {
		t.Errorf("trace_id appears %d times in %s", n, buf)
	}
}

func TestTracer_NilIsSafe(t *testing.T) {
	var tr *Tracer
	s := tr.Start(context.Background(), "x")
	if s != nil {
		t.Fatal("a nil tracer started a span")
	}
	s.SetAttrs(slog.Int("a", 1))
	s.End(nil)
	s.EndStatus(StatusError, errors.New("e"))
	if time.Since(tr.Now()) > time.Minute {
		t.Error("a nil tracer's clock is not the wall clock")
	}
	// The defaults: a discarding logger and the wall clock.
	d := NewTracer(nil, nil)
	if time.Since(d.Now()) > time.Minute {
		t.Error("default clock")
	}
	d.Start(context.Background(), "y").End(nil)
}
