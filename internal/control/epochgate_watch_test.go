package control

import (
	"context"
	"sync"
	"testing"
	"time"
)

func waitForEpoch(t *testing.T, gate *EpochGate, session string, wantAtLeast uint64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if epoch, ok := gate.Known(session); ok && epoch >= wantAtLeast {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for EpochGate to observe epoch >= %d for session %q", wantAtLeast, session)
}

func TestFollowOwnership_PropagatesWrites(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ownership := NewOwnershipService(NewMemStore())
	gate := NewEpochGate()
	events, err := ownership.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	go Follow(gate, events)

	rec := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if applied, err := ownership.SetIfNewer(context.Background(), rec); err != nil || !applied {
		t.Fatalf("SetIfNewer: applied=%v err=%v", applied, err)
	}
	waitForEpoch(t, gate, "s1", 0, time.Second)

	next := rec.NextEpoch("sg")
	if applied, err := ownership.SetIfNewer(context.Background(), next); err != nil || !applied {
		t.Fatalf("SetIfNewer: applied=%v err=%v", applied, err)
	}
	waitForEpoch(t, gate, "s1", 1, time.Second)
}

func TestFollowOwnership_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ownership := NewOwnershipService(NewMemStore())
	gate := NewEpochGate()

	done := make(chan error, 1)
	go func() { done <- FollowOwnership(ctx, gate, ownership) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("FollowOwnership returned %v after context cancel, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("FollowOwnership did not return after its context was cancelled")
	}
}

func TestFollowOwnership_FencesStaleOwnerAfterCASRace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ownership := NewOwnershipService(NewMemStore())
	gate := NewEpochGate()
	events, err := ownership.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	go Follow(gate, events)

	base := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if applied, err := ownership.SetIfNewer(context.Background(), base); err != nil || !applied {
		t.Fatalf("seeding base record: applied=%v err=%v", applied, err)
	}
	waitForEpoch(t, gate, "s1", 0, time.Second)

	// The old-owner gateway "caches" base.Epoch=0 right here, before the
	// race below decides who actually wins Epoch=1.
	staleEpoch := base.Epoch

	const n = 8
	candidates := make([]OwnershipRecord, n)
	for i := range candidates {
		candidates[i] = base.NextEpoch(egressName(i))
	}
	var wg sync.WaitGroup
	applied := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ok, err := ownership.SetIfNewer(context.Background(), candidates[i])
			if err != nil {
				t.Errorf("SetIfNewer: %v", err)
			}
			applied[i] = ok
		}(i)
	}
	wg.Wait()

	winners := 0
	for _, ok := range applied {
		if ok {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("winners = %d, want exactly 1", winners)
	}

	waitForEpoch(t, gate, "s1", 1, time.Second)

	if gate.AdmitAndAdvance("s1", staleEpoch) {
		t.Fatalf("the old owner's stale Epoch=%d was admitted after the CAS race committed a newer epoch -- fencing failed", staleEpoch)
	}
	if !gate.AdmitAndAdvance("s1", 1) {
		t.Fatal("the CAS race's own winning Epoch=1 was rejected by the gate it should have advanced")
	}
}
