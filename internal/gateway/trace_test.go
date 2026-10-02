package gateway

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ngthdong/egressa/internal/telemetry"
)

func TestTraceMoves(t *testing.T) {
	var buf bytes.Buffer
	l, err := telemetry.NewLogger(telemetry.LogConfig{Writer: &buf, Format: telemetry.FormatJSON, Role: "gateway", Node: "hk", Version: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	a := newAdmitAgent(t, nil)
	a.cfg.Tracer = telemetry.NewTracer(l, nil)
	vip := netip.MustParseAddr("10.201.0.2")
	plan := func(epoch uint64, access string) Plan {
		return Plan{Sessions: map[string]SessionPath{"42": {VirtualIP: vip, Access: access, Egress: "hk", Epoch: epoch}}}
	}
	began := time.Now()

	a.traceMovesLocked(plan(1, "hk"), began, nil) // first sight: not a move
	a.traceMovesLocked(plan(1, "hk"), began, nil) // no change
	a.ret[vip] = "sg"
	a.traceMovesLocked(plan(2, "sg"), began, nil)
	a.traceMovesLocked(plan(3, "hk"), began, map[netip.Addr]error{vip: errTest("ip route del: exit 2")})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d spans, want 2 (one per move):\n%s", len(lines), buf.String())
	}
	var first, second map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{
		"span": "migration.apply", "status": "ok", "trace_id": telemetry.MigrationTraceID("42", 2), "session": "42",
		"epoch": float64(2), "from_epoch": float64(1), "access": "sg", "from_access": "hk", "return_via": "sg", "node": "hk",
	} {
		if first[k] != want {
			t.Errorf("first span: %s = %v, want %v", k, first[k], want)
		}
	}
	if second["status"] != "error" || second["err"] != "ip route del: exit 2" || second["trace_id"] != telemetry.MigrationTraceID("42", 3) {
		t.Errorf("second span: %v", second)
	}
}

type errTest string

func (e errTest) Error() string { return string(e) }
