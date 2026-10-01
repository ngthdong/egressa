package client

import (
	"strings"
	"testing"
	"time"

	"github.com/ngthdong/egressa/internal/control"
	"github.com/ngthdong/egressa/internal/measurement"
)

// seg is a well-measured segment with median rtt ms.
func seg(ms float64) measurement.SegmentStats {
	us := ms * 1000
	return measurement.SegmentStats{P50Micros: us, P95Micros: us * 1.1, VarianceMicros2: (us * 0.05) * (us * 0.05), N: 40, Confidence: 0.6}
}

func testPolicy() control.PolicyDocument {
	p := control.DefaultPolicyDocument
	p.Decision.MigrationCost = 5000
	p.Decision.SafetyMargin = 5000
	p.FlapGuard = measurement.FlapGuardConfig{ConfirmationWindow: 2 * time.Second, MinResidence: 3 * time.Second, Cooldown: time.Second}
	return p
}

// scenario: the client sits on hk for egress hk; sg is the detour.
func paths(direct, toSG, sgToHK float64) []Path {
	return []Path{
		{Access: "hk", Egress: "hk", Segments: []measurement.SegmentStats{seg(direct)}, Reachable: true},
		{Access: "sg", Egress: "hk", Segments: []measurement.SegmentStats{seg(toSG), seg(sgToHK)}, Reachable: true},
		{Access: "sg", Egress: "sg", Segments: []measurement.SegmentStats{seg(toSG)}, Reachable: true},
		{Access: "hk", Egress: "sg", Segments: []measurement.SegmentStats{seg(direct), seg(sgToHK)}, Reachable: true},
	}
}

// run calls Decide every 500 ms for d and returns the first migration.
func run(dec *Decider, start time.Time, d time.Duration, ps []Path, dead bool) (Decision, time.Duration) {
	for t := time.Duration(0); t <= d; t += 500 * time.Millisecond {
		if got := dec.Decide(start.Add(t), "hk", "hk", ps, dead); got.Migrate {
			return got, t
		}
	}
	return Decision{}, -1
}

func TestDecide_DetourWinsWhenDirectDegrades(t *testing.T) {
	start := time.Unix(1000, 0)
	dec := NewDecider(testPolicy(), start)
	// Direct 200 ms; via sg 10 + 10 ms.
	got, at := run(dec, start, 10*time.Second, paths(200, 10, 10), false)
	if !got.Migrate || got.Access != "sg" || got.Egress != "hk" {
		t.Fatalf("decision %+v; want access sg keeping egress hk", got)
	}
	// Not before MinResidence (3 s), and only after 2 s of confirmation.
	if at < 3*time.Second {
		t.Errorf("migrated after %s, before the 3 s minimum residence", at)
	}
	if !strings.Contains(got.Reason, "better by at least") {
		t.Errorf("reason %q", got.Reason)
	}
}

func TestDecide_BackboneCostKeepsTheDirectPath(t *testing.T) {
	// The trap: the client reaches sg fast, but sg->hk is slow, so the
	// detour is worse end to end than the mildly degraded direct path.
	start := time.Unix(1000, 0)
	dec := NewDecider(testPolicy(), start)
	if got, _ := run(dec, start, 20*time.Second, paths(60, 5, 150), false); got.Migrate {
		t.Fatalf("took the detour: %+v", got)
	}
}

func TestDecide_SmallGainIsNotWorthIt(t *testing.T) {
	start := time.Unix(1000, 0)
	dec := NewDecider(testPolicy(), start)
	// 30 ms vs 12 + 12 ms: better by 6 ms point, under the 10 ms bar.
	if got, _ := run(dec, start, 20*time.Second, paths(30, 12, 12), false); got.Migrate {
		t.Fatalf("migrated for a gain under the migration cost: %+v", got)
	}
}

func TestDecide_UnmeasuredBackboneIsNeverChosen(t *testing.T) {
	start := time.Unix(1000, 0)
	dec := NewDecider(testPolicy(), start)
	ps := paths(200, 10, 10)
	ps[1].Segments[1] = measurement.SegmentStats{} // sg->hk never measured
	if got, _ := run(dec, start, 20*time.Second, ps, false); got.Migrate {
		t.Fatalf("chose a path with an unmeasured segment: %+v", got)
	}
}

func TestDecide_UnreachableCandidateIsSkipped(t *testing.T) {
	start := time.Unix(1000, 0)
	dec := NewDecider(testPolicy(), start)
	ps := paths(200, 10, 10)
	ps[1].Reachable = false
	if got, _ := run(dec, start, 20*time.Second, ps, false); got.Migrate {
		t.Fatalf("chose an unreachable path: %+v", got)
	}
}

func TestDecide_FlappingCandidateNeverConfirms(t *testing.T) {
	start := time.Unix(1000, 0)
	dec := NewDecider(testPolicy(), start)
	good, bad := paths(200, 10, 10), paths(10, 200, 10)
	for i := 0; i < 60; i++ {
		ps := good
		if i%3 == 2 { // better for 1 s, then not, over and over
			ps = bad
		}
		if got := dec.Decide(start.Add(time.Duration(i)*500*time.Millisecond), "hk", "hk", ps, false); got.Migrate {
			t.Fatalf("migrated on a flapping signal at tick %d", i)
		}
	}
}

func TestDecide_DeadPathMovesAtOnce(t *testing.T) {
	start := time.Unix(1000, 0)
	dec := NewDecider(testPolicy(), start)
	// Right at start, inside MinResidence, with a detour no better.
	got := dec.Decide(start, "hk", "hk", paths(10, 10, 10), true)
	if !got.Migrate || got.Access != "sg" || got.Egress != "hk" {
		t.Fatalf("dead path: %+v; want an immediate move to sg keeping egress hk", got)
	}
}

func TestDecide_DeadEgressChangesEgress(t *testing.T) {
	start := time.Unix(1000, 0)
	dec := NewDecider(testPolicy(), start)
	ps := paths(10, 10, 10)
	ps[1].Reachable = false // no other way to hk either
	got := dec.Decide(start, "hk", "hk", ps, true)
	if !got.Migrate || got.Egress != "sg" || !strings.Contains(got.Reason, "connections will break") {
		t.Fatalf("decision %+v; want a move to egress sg, saying connections break", got)
	}
	ps[2].Reachable, ps[3].Reachable = false, false
	if got := dec.Decide(start, "hk", "hk", ps, true); got.Migrate {
		t.Fatalf("moved with nowhere to go: %+v", got)
	}
}

func TestDecide_NoCurrentPath(t *testing.T) {
	dec := NewDecider(testPolicy(), time.Unix(1000, 0))
	if got := dec.Decide(time.Unix(1010, 0), "xx", "hk", paths(200, 10, 10), false); got.Migrate {
		t.Fatalf("moved without knowing the current path: %+v", got)
	}
}

func TestDecide_ResetRestartsResidence(t *testing.T) {
	start := time.Unix(1000, 0)
	dec := NewDecider(testPolicy(), start)
	if _, at := run(dec, start, 10*time.Second, paths(200, 10, 10), false); at < 0 {
		t.Fatal("no first migration")
	}
	moved := start.Add(20 * time.Second)
	dec.Reset(moved)
	if got := dec.Decide(moved.Add(time.Second), "hk", "hk", paths(200, 10, 10), false); got.Migrate {
		t.Fatal("migrated again inside the minimum residence after Reset")
	}
}
