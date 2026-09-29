package handoff

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestArmPhase_String(t *testing.T) {
	cases := map[ArmPhase]string{
		PhaseIdle:    "idle",
		PhasePrepare: "prepare",
		PhaseReady:   "ready",
		ArmPhase(99): "ArmPhase(99)",
	}
	for phase, want := range cases {
		if got := phase.String(); got != want {
			t.Errorf("ArmPhase(%d).String() = %q, want %q", int(phase), got, want)
		}
	}
}

func TestAccessState_ContainsOnlyAccessSideFields(t *testing.T) {
	typ := reflect.TypeOf(AccessState{})
	want := []string{"SessionID", "VirtualIP", "SeqHighWater"}
	if typ.NumField() != len(want) {
		t.Fatalf("AccessState has %d fields, want exactly %d (%v), if this is intentional, update this test deliberately", typ.NumField(), len(want), want)
	}
	for i, name := range want {
		if got := typ.Field(i).Name; got != name {
			t.Fatalf("AccessState field %d = %q, want %q", i, got, name)
		}
	}
}

func TestAccessState_Validate(t *testing.T) {
	cases := []struct {
		name    string
		s       AccessState
		wantErr bool
	}{
		{"complete", AccessState{SessionID: "s1", VirtualIP: "10.0.0.1", SeqHighWater: 5}, false},
		{"empty session id", AccessState{VirtualIP: "10.0.0.1"}, true},
		{"empty virtual ip", AccessState{SessionID: "s1"}, true},
		{"zero seq high water is fine", AccessState{SessionID: "s1", VirtualIP: "10.0.0.1"}, false},
	}
	for _, c := range cases {
		err := c.s.Validate()
		if (err != nil) != c.wantErr {
			t.Errorf("%s: Validate() err = %v, wantErr %v", c.name, err, c.wantErr)
		}
	}
}

func TestNewStandbyArmer_PhaseIdleForUnknownSession(t *testing.T) {
	a := NewStandbyArmer()
	if got := a.Phase("nope"); got != PhaseIdle {
		t.Fatalf("Phase() for unknown session = %v, want %v", got, PhaseIdle)
	}
	if _, _, _, _, ok := a.Snapshot("nope"); ok {
		t.Fatal("Snapshot() ok = true for unknown session")
	}
}

func TestStandbyArmer_Prepare_ArmsAtCurrentEpochPlusOne(t *testing.T) {
	a := NewStandbyArmer()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	state := AccessState{SessionID: "s1", VirtualIP: "10.0.0.5", SeqHighWater: 42}

	if err := a.Prepare("s1", 7, state, now); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	target, got, phase, armedAt, ok := a.Snapshot("s1")
	if !ok {
		t.Fatal("Snapshot() ok = false right after Prepare")
	}
	if target != 8 {
		t.Fatalf("targetEpoch = %d, want currentEpoch+1 = 8", target)
	}
	if got != state {
		t.Fatalf("state = %+v, want %+v", got, state)
	}
	if phase != PhasePrepare {
		t.Fatalf("phase = %v, want %v", phase, PhasePrepare)
	}
	if !armedAt.Equal(now) {
		t.Fatalf("armedAt = %v, want %v", armedAt, now)
	}
}

func TestStandbyArmer_Prepare_RejectsSessionMismatch(t *testing.T) {
	a := NewStandbyArmer()
	err := a.Prepare("s1", 0, AccessState{SessionID: "other", VirtualIP: "10.0.0.1"}, time.Now())
	if !errors.Is(err, ErrSessionMismatch) {
		t.Fatalf("Prepare error = %v, want %v", err, ErrSessionMismatch)
	}
	if phase := a.Phase("s1"); phase != PhaseIdle {
		t.Fatalf("phase after rejected Prepare = %v, want %v", phase, PhaseIdle)
	}
}

func TestStandbyArmer_Prepare_RejectsInvalidState(t *testing.T) {
	a := NewStandbyArmer()
	err := a.Prepare("s1", 0, AccessState{SessionID: "s1"}, time.Now())
	if err == nil {
		t.Fatal("Prepare accepted a state with an empty VirtualIP")
	}
}

func TestStandbyArmer_MarkReady_TransitionsToReady(t *testing.T) {
	a := NewStandbyArmer()
	now := time.Now()
	state := AccessState{SessionID: "s1", VirtualIP: "10.0.0.1"}
	if err := a.Prepare("s1", 0, state, now); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := a.MarkReady("s1", 1); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}
	if phase := a.Phase("s1"); phase != PhaseReady {
		t.Fatalf("phase after MarkReady = %v, want %v", phase, PhaseReady)
	}
}

func TestStandbyArmer_MarkReady_RequiresPriorPrepare(t *testing.T) {
	a := NewStandbyArmer()
	if err := a.MarkReady("s1", 1); !errors.Is(err, ErrNoArmInProgress) {
		t.Fatalf("MarkReady error = %v, want %v", err, ErrNoArmInProgress)
	}
}

func TestStandbyArmer_MarkReady_RejectsEpochMismatch(t *testing.T) {
	a := NewStandbyArmer()
	if err := a.Prepare("s1", 0, AccessState{SessionID: "s1", VirtualIP: "10.0.0.1"}, time.Now()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := a.MarkReady("s1", 99); !errors.Is(err, ErrEpochMismatch) {
		t.Fatalf("MarkReady error = %v, want %v", err, ErrEpochMismatch)
	}
	if phase := a.Phase("s1"); phase != PhasePrepare {
		t.Fatalf("phase after rejected MarkReady = %v, want unchanged %v", phase, PhasePrepare)
	}
}

func TestStandbyArmer_MarkReady_IdempotentWhenAlreadyReady(t *testing.T) {
	a := NewStandbyArmer()
	if err := a.Prepare("s1", 0, AccessState{SessionID: "s1", VirtualIP: "10.0.0.1"}, time.Now()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := a.MarkReady("s1", 1); err != nil {
		t.Fatalf("first MarkReady: %v", err)
	}
	if err := a.MarkReady("s1", 1); err != nil {
		t.Fatalf("second MarkReady (idempotent) returned an error: %v", err)
	}
	if phase := a.Phase("s1"); phase != PhaseReady {
		t.Fatalf("phase after idempotent MarkReady = %v, want %v", phase, PhaseReady)
	}
}

func TestStandbyArmer_Prepare_RefreshesStateWithoutLeavingReady(t *testing.T) {
	a := NewStandbyArmer()
	now := time.Now()
	if err := a.Prepare("s1", 0, AccessState{SessionID: "s1", VirtualIP: "10.0.0.1", SeqHighWater: 10}, now); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := a.MarkReady("s1", 1); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}

	later := now.Add(time.Second)
	if err := a.Prepare("s1", 0, AccessState{SessionID: "s1", VirtualIP: "10.0.0.1", SeqHighWater: 55}, later); err != nil {
		t.Fatalf("refreshing Prepare: %v", err)
	}
	target, state, phase, armedAt, ok := a.Snapshot("s1")
	if !ok {
		t.Fatal("Snapshot ok = false")
	}
	if phase != PhaseReady {
		t.Fatalf("phase after refreshing Prepare at the same target = %v, want unchanged %v", phase, PhaseReady)
	}
	if target != 1 {
		t.Fatalf("targetEpoch changed to %d on a same-target refresh, want unchanged 1", target)
	}
	if state.SeqHighWater != 55 {
		t.Fatalf("SeqHighWater = %d, want the refreshed 55", state.SeqHighWater)
	}
	if !armedAt.Equal(later) {
		t.Fatalf("armedAt = %v, want refreshed %v", armedAt, later)
	}
}

func TestStandbyArmer_Prepare_SupersedesStaleArmAtHigherEpoch(t *testing.T) {
	a := NewStandbyArmer()
	now := time.Now()
	if err := a.Prepare("s1", 0, AccessState{SessionID: "s1", VirtualIP: "10.0.0.1"}, now); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := a.MarkReady("s1", 1); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}

	if err := a.Prepare("s1", 1, AccessState{SessionID: "s1", VirtualIP: "10.0.0.9", SeqHighWater: 3}, now); err != nil {
		t.Fatalf("superseding Prepare: %v", err)
	}
	target, state, phase, _, ok := a.Snapshot("s1")
	if !ok {
		t.Fatal("Snapshot ok = false")
	}
	if target != 2 {
		t.Fatalf("targetEpoch = %d, want superseded target 2", target)
	}
	if phase != PhasePrepare {
		t.Fatalf("phase = %v, want the superseding arm to start at %v, not stay Ready", phase, PhasePrepare)
	}
	if state.VirtualIP != "10.0.0.9" {
		t.Fatalf("state = %+v, want the new superseding state", state)
	}
}

func TestStandbyArmer_Prepare_RejectsEpochRegression(t *testing.T) {
	a := NewStandbyArmer()
	now := time.Now()
	if err := a.Prepare("s1", 5, AccessState{SessionID: "s1", VirtualIP: "10.0.0.1"}, now); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	// currentEpoch=3 would target epoch 4, older than the already-armed
	// target of 6.
	err := a.Prepare("s1", 3, AccessState{SessionID: "s1", VirtualIP: "10.0.0.2"}, now)
	if !errors.Is(err, ErrStaleEpoch) {
		t.Fatalf("Prepare error = %v, want %v", err, ErrStaleEpoch)
	}
	target, state, _, _, _ := a.Snapshot("s1")
	if target != 6 || state.VirtualIP != "10.0.0.1" {
		t.Fatalf("arm changed after a rejected regressive Prepare: target=%d state=%+v", target, state)
	}
}

func TestStandbyArmer_Reset_ReturnsToIdle(t *testing.T) {
	a := NewStandbyArmer()
	if err := a.Prepare("s1", 0, AccessState{SessionID: "s1", VirtualIP: "10.0.0.1"}, time.Now()); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := a.MarkReady("s1", 1); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}
	a.Reset("s1")

	if phase := a.Phase("s1"); phase != PhaseIdle {
		t.Fatalf("phase after Reset = %v, want %v", phase, PhaseIdle)
	}
	if _, _, _, _, ok := a.Snapshot("s1"); ok {
		t.Fatal("Snapshot ok = true after Reset")
	}
	// A fresh Prepare after Reset must behave like a brand new arm, not
	// be rejected as a regression against the discarded one.
	if err := a.Prepare("s1", 0, AccessState{SessionID: "s1", VirtualIP: "10.0.0.1"}, time.Now()); err != nil {
		t.Fatalf("Prepare after Reset: %v", err)
	}
}

func TestStandbyArmer_IndependentPerSession(t *testing.T) {
	a := NewStandbyArmer()
	now := time.Now()
	if err := a.Prepare("s1", 0, AccessState{SessionID: "s1", VirtualIP: "10.0.0.1"}, now); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := a.MarkReady("s1", 1); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}
	if err := a.Prepare("s2", 10, AccessState{SessionID: "s2", VirtualIP: "10.0.0.2"}, now); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	if phase := a.Phase("s1"); phase != PhaseReady {
		t.Fatalf("s1 phase = %v, want %v", phase, PhaseReady)
	}
	if phase := a.Phase("s2"); phase != PhasePrepare {
		t.Fatalf("s2 phase = %v, want %v", phase, PhasePrepare)
	}
	target2, _, _, _, _ := a.Snapshot("s2")
	if target2 != 11 {
		t.Fatalf("s2 targetEpoch = %d, want 11", target2)
	}
}

func TestStandbyArmer_ConcurrentSessions_RaceFree(t *testing.T) {
	a := NewStandbyArmer()
	now := time.Now()
	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			session := egressName(i%len(egressNames)) + string(rune('0'+i))
			state := AccessState{SessionID: session, VirtualIP: "10.0.0.1", SeqHighWater: uint64(i)}
			if err := a.Prepare(session, uint64(i), state, now); err != nil {
				t.Errorf("Prepare(%s): %v", session, err)
				return
			}
			if err := a.MarkReady(session, uint64(i)+1); err != nil {
				t.Errorf("MarkReady(%s): %v", session, err)
			}
		}(i)
	}
	wg.Wait()
}

var egressNames = []string{"hk", "sg", "jp", "us", "de", "uk", "fr", "kr", "in", "br"}

func egressName(i int) string {
	return egressNames[i%len(egressNames)]
}
