package measurement

import (
	"testing"
	"time"
)

func TestFlapGuard_MigratesAfterConfirmationWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fg := NewFlapGuard(FlapGuardConfig{ConfirmationWindow: 5 * time.Second}, start)

	now := start
	// The first qualifying tick establishes pendingSince; confirmation
	// duration is measured from there, so 5 more ticks are needed to
	// reach a full 5s of continuous confirmation.
	for i := 0; i < 5; i++ {
		now = now.Add(time.Second)
		if fg.Evaluate(now, true, "candidate-b") {
			t.Fatalf("Evaluate migrated after only %v of confirmation, want it to require 5s", now.Sub(start))
		}
	}
	now = now.Add(time.Second) // now 5s since the first qualifying tick
	if !fg.Evaluate(now, true, "candidate-b") {
		t.Fatalf("Evaluate did not migrate after a full 5s of continuous confirmation")
	}
}

func TestFlapGuard_GapInQualificationResetsWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fg := NewFlapGuard(FlapGuardConfig{ConfirmationWindow: 5 * time.Second}, start)

	now := start
	for i := 0; i < 4; i++ {
		now = now.Add(time.Second)
		fg.Evaluate(now, true, "candidate-b")
	}
	// A single missed tick (candidate momentarily stopped qualifying)
	// forfeits the 4s already built up.
	now = now.Add(time.Second)
	if fg.Evaluate(now, false, "candidate-b") {
		t.Fatal("Evaluate migrated on a tick where qualifies=false")
	}
	// Even though the candidate resumes qualifying immediately, and the
	// TOTAL elapsed time since the run started is now well over 5s, the
	// window must restart from this resumption, not from the original
	// start.
	for i := 0; i < 4; i++ {
		now = now.Add(time.Second)
		if fg.Evaluate(now, true, "candidate-b") {
			t.Fatalf("Evaluate migrated %v after resuming, want the gap to have reset the window to zero", now)
		}
	}
}

func TestFlapGuard_CandidateSwitchResetsWindow(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fg := NewFlapGuard(FlapGuardConfig{ConfirmationWindow: 5 * time.Second}, start)

	now := start
	for i := 0; i < 3; i++ {
		now = now.Add(time.Second)
		fg.Evaluate(now, true, "candidate-b")
	}

	for i := 0; i < 4; i++ {
		now = now.Add(time.Second)
		if fg.Evaluate(now, true, "candidate-c") {
			t.Fatalf("Evaluate migrated %v after a candidate switch, want the new candidate to need its own full window", now.Sub(start))
		}
	}
}

func TestFlapGuard_MinResidenceBlocksEarlyMigration(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fg := NewFlapGuard(FlapGuardConfig{ConfirmationWindow: 0, MinResidence: 30 * time.Second}, start)

	now := start.Add(time.Second)
	if fg.Evaluate(now, true, "candidate-b") {
		t.Fatal("Evaluate migrated after only 1s of residence on the current path, want MinResidence=30s enforced")
	}
	now = start.Add(30 * time.Second)
	if !fg.Evaluate(now, true, "candidate-b") {
		t.Fatal("Evaluate did not migrate once MinResidence had fully elapsed")
	}
}

func TestFlapGuard_CooldownBlocksMigrationsSoonAfterLast(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fg := NewFlapGuard(FlapGuardConfig{ConfirmationWindow: 0, MinResidence: 0, Cooldown: 10 * time.Second}, start)

	now := start
	if !fg.Evaluate(now, true, "candidate-b") {
		t.Fatal("first migration (zero confirmation/residence/cooldown required) should be approved immediately")
	}
	// Candidate C immediately starts qualifying, right after B was just
	// migrated to.
	now = now.Add(time.Second)
	if fg.Evaluate(now, true, "candidate-c") {
		t.Fatal("Evaluate migrated 1s after the previous migration, want Cooldown=10s enforced")
	}
	now = start.Add(10 * time.Second)
	if !fg.Evaluate(now, true, "candidate-c") {
		t.Fatal("Evaluate did not migrate once Cooldown had fully elapsed")
	}
}

func TestFlapGuard_ThreeSecondNoiseBurst_DoesNotMigrate(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fg := NewFlapGuard(DefaultFlapGuardConfig, start)

	now := start
	for i := 0; i < 3; i++ {
		now = now.Add(time.Second)
		if fg.Evaluate(now, true, "candidate-b") {
			t.Fatalf("Evaluate migrated during a 3s noise burst (ConfirmationWindow=%v)", DefaultFlapGuardConfig.ConfirmationWindow)
		}
	}
	now = now.Add(time.Second)
	if fg.Evaluate(now, false, "candidate-b") {
		t.Fatal("Evaluate migrated on the tick the noise burst ended")
	}
	if _, _, ok := fg.Pending(now); ok {
		t.Fatal("Pending confirmation should have been cleared once qualifies went false")
	}
}

func TestFlapGuard_Pending_ReportsConfirmationProgress(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fg := NewFlapGuard(FlapGuardConfig{ConfirmationWindow: 5 * time.Second}, start)

	if _, _, ok := fg.Pending(start); ok {
		t.Fatal("a fresh FlapGuard should report no pending candidate")
	}
	now := start.Add(2 * time.Second)
	fg.Evaluate(now, true, "candidate-b")
	id, confirming, ok := fg.Pending(now)
	if !ok || id != "candidate-b" || confirming != 0 {
		t.Fatalf("Pending() = (%q, %v, %v) right after the first qualifying tick, want (\"candidate-b\", 0, true)", id, confirming, ok)
	}
	now = now.Add(3 * time.Second)
	fg.Evaluate(now, true, "candidate-b")
	if _, confirming, _ = fg.Pending(now); confirming != 3*time.Second {
		t.Fatalf("Pending() confirming = %v, want 3s", confirming)
	}
}

// tickTracker feeds one RTT sample (in milliseconds) into tr at the
// clock's current time and returns tr's snapshot immediately after.
func tickTracker(tr *SegmentTracker, rttMillis float64) SegmentStats {
	tr.Observe(rttMillis * 1000)
	return tr.Snapshot()
}

func TestFlapGuard_SmallRTTOscillation_NeverMigrates(t *testing.T) {
	fc := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	cw := CostWeights{TailWeight: 1, LossWeight: 1000, LossGate: 0.5, MaxCapacityFraction: 0.9}
	dw := DecisionWeights{Z: 1.645, MigrationCost: 0, SafetyMargin: 0}

	currentTr := NewSegmentTracker(DefaultSegmentTrackerConfig)
	currentTr.now = fc.now
	candidateTr := NewSegmentTracker(DefaultSegmentTrackerConfig)
	candidateTr.now = fc.now

	for i := 0; i < 200; i++ {
		fc.advance(time.Second)
		tickTracker(currentTr, 50)
	}

	fg := NewFlapGuard(DefaultFlapGuardConfig, fc.now())

	oscillation := []float64{50, 48, 51, 49}
	for i := 0; i < 120; i++ { // 120 ticks, one per second: 2 minutes
		fc.advance(time.Second)
		currentStats := tickTracker(currentTr, 50)
		candidateStats := tickTracker(candidateTr, oscillation[i%len(oscillation)])

		current := PathCandidate{EgressID: "shared", Segments: []SegmentStats{currentStats}}
		candidate := PathCandidate{EgressID: "shared", Segments: []SegmentStats{candidateStats}}

		decision, err := DecideMigration(current, candidate, 0, cw, dw)
		if err != nil {
			t.Fatalf("DecideMigration at tick %d: %v", i, err)
		}
		if decision.Migrate {
			t.Fatalf("tick %d: DecideMigration itself said Migrate=true for pure RTT oscillation (candidateStats=%+v); expected the confidence bound alone to already refuse", i, candidateStats)
		}
		if fg.Evaluate(fc.now(), decision.Migrate, "candidate") {
			t.Fatalf("tick %d: FlapGuard approved a migration driven by 50/48/51/49ms oscillation", i)
		}
	}
}

func TestFlapGuard_SmallRTTOscillation_EvenIfNaivelyQualifying_FlapGuardStillHolds(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fg := NewFlapGuard(DefaultFlapGuardConfig, start)

	now := start
	qualifiesPattern := []bool{true, false, true, false, true, false, true, false}
	for i, q := range qualifiesPattern {
		now = now.Add(time.Second)
		if fg.Evaluate(now, q, "candidate-b") {
			t.Fatalf("tick %d: FlapGuard migrated on a flickering qualifies signal that never sustains for the full ConfirmationWindow", i)
		}
	}
}
