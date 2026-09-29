package handoff

import (
	"context"
	"testing"
	"time"

	"github.com/ngthdong/egressa/internal/control"
)

func TestRollback_ResetsInProgressArm(t *testing.T) {
	armer := NewStandbyArmer()
	now := time.Now()
	state := AccessState{SessionID: "sess-1", VirtualIP: "10.0.0.1", SeqHighWater: 42}
	if err := armer.Prepare("sess-1", 0, state, now); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	result := Rollback(armer, "sess-1")
	if !result.HadArm {
		t.Fatal("HadArm = false, want true (there was an in-progress Prepare)")
	}
	if got := armer.Phase("sess-1"); got != PhaseIdle {
		t.Fatalf("Phase after Rollback = %v, want %v", got, PhaseIdle)
	}
}

func TestRollback_ResetsReadyArm(t *testing.T) {
	armer := NewStandbyArmer()
	now := time.Now()
	state := AccessState{SessionID: "sess-1", VirtualIP: "10.0.0.1", SeqHighWater: 42}
	if err := armer.Prepare("sess-1", 0, state, now); err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := armer.MarkReady("sess-1", 1); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}

	result := Rollback(armer, "sess-1")
	if !result.HadArm {
		t.Fatal("HadArm = false, want true (there was a Ready arm)")
	}
	if got := armer.Phase("sess-1"); got != PhaseIdle {
		t.Fatalf("Phase after Rollback = %v, want %v", got, PhaseIdle)
	}
}

func TestRollback_NoOpWhenNothingArmed(t *testing.T) {
	armer := NewStandbyArmer()
	result := Rollback(armer, "sess-never-armed")
	if result.HadArm {
		t.Fatal("HadArm = true, want false (nothing was ever armed)")
	}
	if got := armer.Phase("sess-never-armed"); got != PhaseIdle {
		t.Fatalf("Phase = %v, want %v", got, PhaseIdle)
	}
}

func TestRollback_NeverTouchesControlPlane(t *testing.T) {
	ctx := context.Background()
	store := control.NewMemStore()
	ownership := control.NewOwnershipService(store)
	armer := NewStandbyArmer()
	cutover := NewCutoverController(armer, ownership)

	seed := control.OwnershipRecord{Session: "sess-1", Access: "gw-old", Egress: "eg-1", Epoch: 0}
	if _, err := ownership.SetIfNewer(ctx, seed); err != nil {
		t.Fatalf("seeding ownership record: %v", err)
	}

	t0 := time.Now()
	state := AccessState{SessionID: "sess-1", VirtualIP: "10.0.0.1", SeqHighWater: 7}
	if err := armer.Prepare("sess-1", 0, state, t0); err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	before, found, err := ownership.Get(ctx, "sess-1")
	if err != nil || !found {
		t.Fatalf("Get before Rollback: found=%v err=%v", found, err)
	}

	Rollback(armer, "sess-1")

	after, found, err := ownership.Get(ctx, "sess-1")
	if err != nil || !found {
		t.Fatalf("Get after Rollback: found=%v err=%v", found, err)
	}
	if after != before {
		t.Fatalf("ownership record changed by Rollback: before=%+v after=%+v", before, after)
	}
	if after.Epoch != 0 {
		t.Fatalf("Epoch = %d after a rolled-back attempt, want unchanged 0", after.Epoch)
	}

	t1 := t0.Add(time.Second)
	if err := armer.Prepare("sess-1", 0, state, t1); err != nil {
		t.Fatalf("Prepare after Rollback: %v", err)
	}
	if err := armer.MarkReady("sess-1", 1); err != nil {
		t.Fatalf("MarkReady after Rollback: %v", err)
	}
	result, ok, err := cutover.Cutover(ctx, "sess-1", "gw-new", after, t1)
	if err != nil || !ok {
		t.Fatalf("Cutover after Rollback: ok=%v err=%v", ok, err)
	}
	if result.Epoch != 1 || result.NewAccess != "gw-new" || result.Egress != "eg-1" {
		t.Fatalf("Cutover result = %+v, want Epoch=1 NewAccess=gw-new Egress=eg-1", result)
	}
}
