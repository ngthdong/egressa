package control

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestOwnershipService_Get_NotFound(t *testing.T) {
	s := NewOwnershipService(NewMemStore())
	_, found, err := s.Get(context.Background(), "no-such-session")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if found {
		t.Fatal("Get reported found=true for a session that was never written")
	}
}

func TestOwnershipService_SetIfNewer_FirstWriteAlwaysApplies(t *testing.T) {
	ctx := context.Background()
	s := NewOwnershipService(NewMemStore())
	rec := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}

	applied, err := s.SetIfNewer(ctx, rec)
	if err != nil || !applied {
		t.Fatalf("SetIfNewer on an empty session = (%v, %v), want (true, nil)", applied, err)
	}
	got, found, err := s.Get(ctx, "s1")
	if err != nil || !found || got != rec {
		t.Fatalf("Get after first write = (%+v, %v, %v), want (%+v, true, nil)", got, found, err, rec)
	}
}

func TestOwnershipService_SetIfNewer_AdvancesOnStrictlyGreaterEpoch(t *testing.T) {
	ctx := context.Background()
	s := NewOwnershipService(NewMemStore())
	first := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if _, err := s.SetIfNewer(ctx, first); err != nil {
		t.Fatalf("SetIfNewer (seed): %v", err)
	}

	second := first.NextEpoch("sg")
	applied, err := s.SetIfNewer(ctx, second)
	if err != nil || !applied {
		t.Fatalf("SetIfNewer with a strictly greater Epoch = (%v, %v), want (true, nil)", applied, err)
	}
	got, _, _ := s.Get(ctx, "s1")
	if got.Egress != "sg" || got.Epoch != 1 {
		t.Fatalf("Get after second write = %+v, want Egress=sg Epoch=1", got)
	}
}

func TestOwnershipService_SetIfNewer_RejectsEqualOrStaleEpoch(t *testing.T) {
	ctx := context.Background()
	s := NewOwnershipService(NewMemStore())
	current := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 5}
	if _, err := s.SetIfNewer(ctx, current); err != nil {
		t.Fatalf("SetIfNewer (seed): %v", err)
	}

	cases := []OwnershipRecord{
		{Session: "s1", Access: "a1", Egress: "sg", Epoch: 5}, // equal epoch, different egress
		{Session: "s1", Access: "a1", Egress: "sg", Epoch: 3}, // lower epoch, e.g. a delayed retry
	}
	for _, stale := range cases {
		applied, err := s.SetIfNewer(ctx, stale)
		if err != nil {
			t.Fatalf("SetIfNewer(%+v): %v", stale, err)
		}
		if applied {
			t.Fatalf("SetIfNewer(%+v) applied, want it rejected as not newer than the current Epoch=5 record", stale)
		}
	}
	got, _, _ := s.Get(ctx, "s1")
	if got != current {
		t.Fatalf("current record changed to %+v despite every write being rejected, want unchanged %+v", got, current)
	}
}

func TestOwnershipService_SetIfNewer_RejectsInvalidRecord(t *testing.T) {
	s := NewOwnershipService(NewMemStore())
	_, err := s.SetIfNewer(context.Background(), OwnershipRecord{Session: "s1"})
	if err == nil {
		t.Fatal("SetIfNewer accepted a record missing Access/Egress")
	}
}

func TestOwnershipService_SetIfNewer_ConcurrentWritersExactlyOneEpochAdvanceWins(t *testing.T) {
	ctx := context.Background()
	s := NewOwnershipService(NewMemStore())
	base := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if applied, err := s.SetIfNewer(ctx, base); err != nil || !applied {
		t.Fatalf("seeding base record: applied=%v err=%v", applied, err)
	}

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
			ok, err := s.SetIfNewer(ctx, candidates[i])
			if err != nil {
				t.Errorf("SetIfNewer: %v", err)
			}
			applied[i] = ok
		}(i)
	}
	wg.Wait()

	winners := 0
	var winnerEgress string
	for i, ok := range applied {
		if ok {
			winners++
			winnerEgress = candidates[i].Egress
		}
	}
	if winners != 1 {
		t.Fatalf("winners = %d, want exactly 1 (concurrent Epoch=0->1 race must have exactly one survivor)", winners)
	}
	final, _, err := s.Get(ctx, "s1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if final.Epoch != 1 || final.Egress != winnerEgress {
		t.Fatalf("final record = %+v, want Epoch=1 Egress=%q (the recorded winner)", final, winnerEgress)
	}
}

func egressName(i int) string {
	names := []string{"hk", "sg", "jp", "us", "de", "uk", "fr", "kr", "in", "br"}
	return names[i%len(names)]
}

func TestOwnershipService_List(t *testing.T) {
	ctx := context.Background()
	s := NewOwnershipService(NewMemStore())
	if _, err := s.SetIfNewer(ctx, OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}); err != nil {
		t.Fatalf("SetIfNewer (s1): %v", err)
	}
	if _, err := s.SetIfNewer(ctx, OwnershipRecord{Session: "s2", Access: "a1", Egress: "sg", Epoch: 0}); err != nil {
		t.Fatalf("SetIfNewer (s2): %v", err)
	}

	recs, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("List returned %d records, want 2", len(recs))
	}
}

func TestOwnershipService_Watch_DeliversWrites(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewOwnershipService(NewMemStore())

	events, err := s.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	rec := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if applied, err := s.SetIfNewer(context.Background(), rec); err != nil || !applied {
		t.Fatalf("SetIfNewer: applied=%v err=%v", applied, err)
	}

	select {
	case got := <-events:
		if got != rec {
			t.Fatalf("Watch delivered %+v, want %+v", got, rec)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Watch to deliver the write")
	}
}
