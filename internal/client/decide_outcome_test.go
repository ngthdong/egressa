package client

import (
	"math"
	"testing"
	"time"

	"github.com/ngthdong/egressa/internal/telemetry"
)

// These check what a Decision reports about itself, for metrics; what
// it decides is checked in decide_test.go.

func TestDecide_ReportsOutcomeAndCause(t *testing.T) {
	start := time.Unix(1000, 0)
	threshold := testPolicy().Decision.MigrationCost + testPolicy().Decision.SafetyMargin

	dec := NewDecider(testPolicy(), start)
	got := dec.Decide(start, "hk", "hk", paths(30, 12, 12), false)
	if got.Outcome != telemetry.OutcomeStay || got.Cause != "" || got.Threshold != threshold {
		t.Errorf("small gain: %+v", got)
	}
	if len(got.Evals) != 4 || got.Evals[0].Access != "hk" || got.Evals[1].Access != "sg" || !got.Evals[1].HasDelta || got.Evals[0].HasDelta {
		t.Fatalf("evals %+v", got.Evals)
	}
	if want := 30*1000 + 0.1*30*1000; math.Abs(got.Evals[0].Cost-want) > 1e-6 {
		t.Errorf("direct cost %v, want %v", got.Evals[0].Cost, want)
	}
	if d := got.Evals[1].Delta; d.Point <= 0 || d.Lower > d.Point {
		t.Errorf("detour delta %+v", d)
	}

	// A clear win: confirming until the flap guard lets it through.
	dec = NewDecider(testPolicy(), start)
	var outcomes []string
	for at := time.Duration(0); at <= 10*time.Second; at += 500 * time.Millisecond {
		d := dec.Decide(start.Add(at), "hk", "hk", paths(200, 10, 10), false)
		outcomes = append(outcomes, d.Outcome)
		if d.Migrate {
			if d.Cause != telemetry.CauseBetterPath {
				t.Errorf("cause %q", d.Cause)
			}
			break
		}
	}
	if outcomes[0] != telemetry.OutcomeConfirming || outcomes[len(outcomes)-1] != telemetry.OutcomeMigrate {
		t.Errorf("outcomes %v", outcomes)
	}

	dec = NewDecider(testPolicy(), start)
	if got := dec.Decide(start, "hk", "hk", paths(10, 10, 10), true); got.Cause != telemetry.CauseAccessDead || got.Outcome != telemetry.OutcomeMigrate {
		t.Errorf("dead path: %+v", got)
	}
	ps := paths(10, 10, 10)
	ps[1].Reachable = false
	if got := dec.Decide(start, "hk", "hk", ps, true); got.Cause != telemetry.CauseEgressChange {
		t.Errorf("dead egress: %+v", got)
	}
	ps[2].Reachable, ps[3].Reachable = false, false
	if got := dec.Decide(start, "hk", "hk", ps, true); got.Outcome != telemetry.OutcomeNoAlternative || got.Migrate {
		t.Errorf("nowhere to go: %+v", got)
	}
	// Alive, but no candidate path at all.
	if got := dec.Decide(start, "hk", "hk", paths(10, 10, 10)[:1], false); got.Outcome != telemetry.OutcomeNoAlternative {
		t.Errorf("no candidates: %+v", got)
	}
	// A gated path costs +Inf.
	gated := paths(10, 10, 10)
	gated[0].Segments[0].LossRate = 0.5
	if got := dec.Decide(start, "hk", "hk", gated, false); !math.IsInf(got.Evals[0].Cost, 1) {
		t.Errorf("gated cost %v", got.Evals[0].Cost)
	}
}
