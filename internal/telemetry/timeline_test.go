package telemetry

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// spansOf logs a migration's spans as three processes would, each to its
// own JSON log, and returns the three logs.
func spansOf(t *testing.T) (client, controller, gateway *bytes.Buffer) {
	t.Helper()
	t0 := time.Date(2026, 10, 6, 1, 0, 0, 0, time.UTC)
	mk := func(role, node string, offsets ...time.Duration) (*Tracer, *bytes.Buffer) {
		var buf bytes.Buffer
		l, err := NewLogger(LogConfig{Writer: &buf, Format: FormatJSON, Role: role, Node: node, Version: "v"})
		if err != nil {
			t.Fatal(err)
		}
		i := 0
		return NewTracer(l, func() time.Time { o := offsets[i]; i++; return t0.Add(o) }), &buf
	}
	ctx := WithMigration(context.Background(), "42", 2)
	ms := time.Millisecond

	// Readings: decide's end, commit's start and end, switch's start and
	// end, then the other session's commit (StartAt reads no clock).
	cl, cbuf := mk("client", "", 1*ms, 1*ms, 1500*time.Microsecond, 4*ms, 5*ms, 6*ms, 6*ms)
	cl.StartAt(ctx, "migration.decide", t0, slog.String("access", "sing"), slog.String("cause", "better_path")).End(nil)
	commit := cl.Start(ctx, "migration.commit")
	commit.End(nil)
	cl.Start(ctx, "migration.switch").End(nil)
	// Another session's migration that lost a conflict.
	cl.Start(WithMigration(context.Background(), "7", 5), "migration.commit").EndStatus(StatusConflict, errors.New("epoch moved"))

	ct, ctlbuf := mk("controller", "", 2*ms, 2500*time.Microsecond)
	ct.Start(ctx, "migration.cas").End(nil)

	gw, gbuf := mk("gateway", "sg", 3*ms, 3500*time.Microsecond)
	gw.Start(ctx, "migration.apply", slog.String("return_via", "sing")).End(nil)
	// Not a span, and a prefix the way journalctl prints lines.
	gbuf.WriteString("not json\nOct 06 01:00:00 host egressa[1]: {\"msg\":\"ready\"}\n")
	l, _ := NewLogger(LogConfig{Writer: gbuf, Format: FormatJSON, Role: "gateway", Version: "v"})
	NewTracer(l, nil).Start(context.Background(), "other.span").End(nil)
	return cbuf, ctlbuf, gbuf
}

func TestTimeline(t *testing.T) {
	c, ctl, gw := spansOf(t)
	var spans []SpanRecord
	for _, r := range []io.Reader{c, ctl, gw} {
		s, err := ReadSpans(r)
		if err != nil {
			t.Fatal(err)
		}
		spans = append(spans, s...)
	}
	ms := Migrations(spans)
	if len(ms) != 2 {
		t.Fatalf("%d migrations, want 2 (the other span is not a migration)", len(ms))
	}
	m := ms[0]
	if m.Session != "42" || m.Epoch != 2 || m.TraceID != MigrationTraceID("42", 2) || len(m.Spans) != 5 {
		t.Fatalf("first migration %+v", m)
	}
	var order []string
	for _, s := range m.Spans {
		order = append(order, s.Span)
	}
	if strings.Join(order, " ") != "migration.decide migration.commit migration.cas migration.apply migration.switch" {
		t.Errorf("order %v", order)
	}
	if m.Status() != "ok" || ms[1].Status() != "migration.commit conflict" {
		t.Errorf("status %q, %q", m.Status(), ms[1].Status())
	}
	if got := m.End().Sub(m.Start()); got != 5*time.Millisecond {
		t.Errorf("total %s", got)
	}
	if gwSpan := m.Spans[3]; gwSpan.Process() != "gateway sg" || gwSpan.Attrs["return_via"] != "sing" {
		t.Errorf("gateway span %+v", gwSpan)
	}

	var out bytes.Buffer
	if err := WriteTimeline(&out, ms); err != nil {
		t.Fatal(err)
	}
	text := strings.Join(strings.Fields(out.String()), " ")
	for _, want := range []string{
		"migration to epoch 2 session 42 trace " + MigrationTraceID("42", 2) + " ok 5.000 ms",
		"+0.000 ms client migration.decide ok 1.000 ms access=sing cause=better_path",
		"+2.000 ms controller migration.cas ok 0.500 ms",
		"+3.000 ms gateway sg migration.apply ok 0.500 ms return_via=sing",
		"migration.commit conflict 0.000 ms err=epoch moved",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("timeline lacks %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	if err := WriteTimeline(&out, nil); err != nil || !strings.Contains(out.String(), "no migration spans") {
		t.Errorf("empty timeline: %q, %v", out.String(), err)
	}
	if str(true) != "true" || str(nil) != "" || str(1.5) != "1.5" {
		t.Error("str")
	}
}

type failWriter struct{ after int }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.after <= 0 {
		return 0, errors.New("disk full")
	}
	f.after--
	return len(p), nil
}

func TestWriteTimelineErrors(t *testing.T) {
	c, _, _ := spansOf(t)
	spans, _ := ReadSpans(c)
	ms := Migrations(spans)
	for n := 0; n < 6; n++ {
		_ = WriteTimeline(&failWriter{after: n}, ms) // must not panic
	}
	if err := WriteTimeline(&failWriter{}, ms); err == nil {
		t.Error("a write error went unnoticed")
	}
	if err := WriteTimeline(&failWriter{}, nil); err == nil {
		t.Error("a write error went unnoticed with no migrations")
	}
	if err := WriteTimeline(&failWriter{after: 1}, ms); err == nil {
		t.Error("a write error after the header went unnoticed")
	}
	long := strings.Repeat("x", 5<<20)
	if _, err := ReadSpans(strings.NewReader(long)); err == nil {
		t.Error("an over-long line went unnoticed")
	}
}
