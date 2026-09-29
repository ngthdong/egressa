package handoff

import (
	"testing"
	"time"

	"github.com/ngthdong/egressa/internal/measurement"
)

func shortFlapCfg() measurement.FlapGuardConfig {
	return measurement.FlapGuardConfig{
		ConfirmationWindow: time.Second,
		MinResidence:       time.Second,
		Cooldown:           time.Hour,
	}
}

func TestShouldCutover_NormalPath_NotYetConfirmed(t *testing.T) {
	t0 := time.Now()
	flap := measurement.NewFlapGuard(shortFlapCfg(), t0)
	if got := ShouldCutover(flap, false, t0.Add(2*time.Second), true, "gw-a"); got {
		t.Fatal("ShouldCutover(deadGateway=false) = true on the first qualifying tick, want false")
	}
}

func TestShouldCutover_NormalPath_TrueOnceFlapGuardConfirms(t *testing.T) {
	t0 := time.Now()
	flap := measurement.NewFlapGuard(shortFlapCfg(), t0)
	t1 := t0.Add(2 * time.Second)
	if got := ShouldCutover(flap, false, t1, true, "gw-a"); got {
		t.Fatal("ShouldCutover(deadGateway=false) = true too early")
	}
	t2 := t1.Add(2 * time.Second) // past both ConfirmationWindow and MinResidence
	if got := ShouldCutover(flap, false, t2, true, "gw-a"); !got {
		t.Fatal("ShouldCutover(deadGateway=false) = false once flap's own conditions are satisfied, want true")
	}
}

func TestShouldCutover_DeadGateway_OverridesHysteresisEvenMidCooldown(t *testing.T) {
	t0 := time.Now()
	flap := measurement.NewFlapGuard(shortFlapCfg(), t0)

	t1 := t0.Add(2 * time.Second)
	ShouldCutover(flap, false, t1, true, "gw-a") // starts pending confirmation
	t2 := t1.Add(2 * time.Second)
	if got := ShouldCutover(flap, false, t2, true, "gw-a"); !got {
		t.Fatalf("baseline migration at t2 should have succeeded (confirmed + resident), got false")
	}

	// Immediately after, still qualifying, but now inside Cooldown.
	t3 := t2.Add(2 * time.Second)
	ShouldCutover(flap, false, t3, true, "gw-a") // starts a fresh pending window
	t4 := t3.Add(2 * time.Second)                // past ConfirmationWindow and MinResidence again
	if got := ShouldCutover(flap, false, t4, true, "gw-a"); got {
		t.Fatal("ordinary path succeeded during Cooldown -- hysteresis is not actually active, test setup is wrong")
	}

	pendingBefore, sinceBefore, okBefore := flap.Pending(t4)

	// The active gateway is now declared dead. The override must
	// succeed at this exact instant, on this exact FlapGuard, despite
	// the ordinary path having just been refused for it.
	if got := ShouldCutover(flap, true, t4, true, "gw-a"); !got {
		t.Fatal("ShouldCutover(deadGateway=true) = false, want true (must override hysteresis unconditionally)")
	}

	// And it must have done so WITHOUT touching flap's own state
	pendingAfter, sinceAfter, okAfter := flap.Pending(t4)
	if pendingBefore != pendingAfter || sinceBefore != sinceAfter || okBefore != okAfter {
		t.Fatalf("dead-gateway override mutated FlapGuard state: before=(%q,%v,%v) after=(%q,%v,%v)",
			pendingBefore, sinceBefore, okBefore, pendingAfter, sinceAfter, okAfter)
	}
}

func TestShouldCutover_DeadGateway_TrueEvenWithNilFlapGuard(t *testing.T) {
	// deadGateway=true must short-circuit before flap is ever dereferenced.
	if got := ShouldCutover(nil, true, time.Now(), true, "gw-a"); !got {
		t.Fatal("ShouldCutover(deadGateway=true, flap=nil) = false, want true")
	}
}
