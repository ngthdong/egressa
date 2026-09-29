package handoff

import (
	"testing"

	"github.com/ngthdong/egressa/internal/reorder"
)

func TestDrainOldGateway_ReportsStuckPacketsAndClosesReceiver(t *testing.T) {
	rec := reorder.NewReceiver(reorder.Config{WindowSize: 8}, 1, 0)

	// seq 1 delivered cleanly; seq 3 arrives leaving a gap at seq 2
	// that will never be filled, the old gateway is about to close.
	if _, reason := rec.Receive(reorder.Packet{Epoch: 1, Seq: 1}); reason != reorder.NotDropped {
		t.Fatalf("Receive(seq 1): reason = %v", reason)
	}
	if _, reason := rec.Receive(reorder.Packet{Epoch: 1, Seq: 3}); reason != reorder.NotDropped {
		t.Fatalf("Receive(seq 3): reason = %v", reason)
	}

	result := DrainOldGateway("sess-1", rec)
	if result.Session != "sess-1" {
		t.Fatalf("Session = %q, want sess-1", result.Session)
	}
	if len(result.Stuck) != 1 || result.Stuck[0].Seq != 3 {
		t.Fatalf("Stuck = %+v, want exactly [seq 3]", result.Stuck)
	}
	if !rec.Closed() {
		t.Fatal("Receiver not closed after DrainOldGateway")
	}

	// A drain that finds nothing stuck reports an empty (non-nil)
	// slice, not nil, so callers can range over it unconditionally.
	clean := reorder.NewReceiver(reorder.DefaultConfig, 1, 0)
	if _, reason := clean.Receive(reorder.Packet{Epoch: 1, Seq: 1}); reason != reorder.NotDropped {
		t.Fatalf("Receive(seq 1) on the clean receiver: reason = %v", reason)
	}
	cleanResult := DrainOldGateway("sess-2", clean)
	if cleanResult.Stuck == nil || len(cleanResult.Stuck) != 0 {
		t.Fatalf("Stuck = %+v, want a non-nil empty slice", cleanResult.Stuck)
	}
}

func TestDrainOldGateway_Idempotent(t *testing.T) {
	rec := reorder.NewReceiver(reorder.Config{WindowSize: 8}, 1, 0)
	if _, reason := rec.Receive(reorder.Packet{Epoch: 1, Seq: 5}); reason != reorder.NotDropped {
		t.Fatalf("Receive(seq 5): reason = %v", reason)
	}

	first := DrainOldGateway("sess-1", rec)
	if len(first.Stuck) != 1 {
		t.Fatalf("first drain Stuck = %+v, want exactly 1 packet", first.Stuck)
	}
	second := DrainOldGateway("sess-1", rec)
	if len(second.Stuck) != 0 {
		t.Fatalf("second drain Stuck = %+v, want empty (nothing left to flush)", second.Stuck)
	}
}
