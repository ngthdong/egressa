package telemetry

import (
	"context"
	"regexp"
	"testing"
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
