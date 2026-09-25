package measurement

import (
	"sync"
	"testing"
	"time"
)

// fakeClock lets tests feed exact, controlled timestamps to a
// PassiveTracker instead of racing the real clock.
type fakeClock struct {
	t time.Time
}

func (c *fakeClock) now() time.Time { return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.t = c.t.Add(d)
}

func newTestTracker() (*PassiveTracker, *fakeClock) {
	fc := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	p := NewPassiveTracker()
	p.now = fc.now
	return p, fc
}

func TestPassiveTracker_FirstPacket_NoRetroactiveLoss(t *testing.T) {
	p, _ := newTestTracker()
	p.Observe(100) // arbitrary starting seq, e.g. tunnel already running

	snap := p.Snapshot()
	if snap.Received != 1 {
		t.Fatalf("Received = %d, want 1", snap.Received)
	}
	if snap.Lost != 0 {
		t.Fatalf("Lost = %d, want 0 (the first packet ever seen can't imply a gap)", snap.Lost)
	}
}

func TestPassiveTracker_InOrder_NoLossNoOutOfOrder(t *testing.T) {
	p, fc := newTestTracker()
	for seq := uint64(1); seq <= 5; seq++ {
		p.Observe(seq)
		fc.advance(10 * time.Millisecond)
	}
	snap := p.Snapshot()
	if snap.Received != 5 {
		t.Fatalf("Received = %d, want 5", snap.Received)
	}
	if snap.Lost != 0 {
		t.Fatalf("Lost = %d, want 0", snap.Lost)
	}
	if snap.OutOfOrder != 0 {
		t.Fatalf("OutOfOrder = %d, want 0", snap.OutOfOrder)
	}
}

func TestPassiveTracker_ForwardGap_CountsLoss(t *testing.T) {
	p, fc := newTestTracker()
	p.Observe(1)
	fc.advance(10 * time.Millisecond)
	p.Observe(2)
	fc.advance(10 * time.Millisecond)
	p.Observe(5) // 3 and 4 never arrive

	snap := p.Snapshot()
	if snap.Lost != 2 {
		t.Fatalf("Lost = %d, want 2 (packets 3 and 4)", snap.Lost)
	}
	if snap.Received != 3 {
		t.Fatalf("Received = %d, want 3", snap.Received)
	}
}

func TestPassiveTracker_LateArrival_CountsOutOfOrder_DoesNotUndoLoss(t *testing.T) {
	p, fc := newTestTracker()
	p.Observe(1)
	fc.advance(10 * time.Millisecond)
	p.Observe(2)
	fc.advance(10 * time.Millisecond)
	p.Observe(5) // gap: 3, 4 presumed lost
	fc.advance(1 * time.Millisecond)
	p.Observe(3) // 3 shows up late after all

	snap := p.Snapshot()
	if snap.OutOfOrder != 1 {
		t.Fatalf("OutOfOrder = %d, want 1", snap.OutOfOrder)
	}

	if snap.Lost != 2 {
		t.Fatalf("Lost = %d, want 2 (late arrival must not decrement it)", snap.Lost)
	}
}

func TestPassiveTracker_Jitter_ZeroForPerfectlySpacedPackets(t *testing.T) {
	p, fc := newTestTracker()
	for seq := uint64(1); seq <= 20; seq++ {
		p.Observe(seq)
		fc.advance(20 * time.Millisecond)
	}
	snap := p.Snapshot()
	if snap.JitterMicros != 0 {
		t.Fatalf("JitterMicros = %f, want 0 for perfectly even spacing", snap.JitterMicros)
	}
}

func TestPassiveTracker_Jitter_NonZeroForVariableSpacing(t *testing.T) {
	p, fc := newTestTracker()
	deltas := []time.Duration{
		10 * time.Millisecond, 40 * time.Millisecond, 10 * time.Millisecond, 40 * time.Millisecond,
		10 * time.Millisecond, 40 * time.Millisecond, 10 * time.Millisecond, 40 * time.Millisecond,
	}
	seq := uint64(1)
	p.Observe(seq)
	for _, d := range deltas {
		seq++
		fc.advance(d)
		p.Observe(seq)
	}
	snap := p.Snapshot()
	if snap.JitterMicros <= 0 {
		t.Fatalf("JitterMicros = %f, want > 0 for alternating 10ms/40ms spacing", snap.JitterMicros)
	}
}

func TestPassiveTracker_Jitter_GapTransitionNotCountedAsSample(t *testing.T) {
	p, fc := newTestTracker()
	p.Observe(1)
	fc.advance(10 * time.Millisecond)
	p.Observe(2)
	fc.advance(30 * time.Millisecond) // 3 and 4 are "in flight" but lost
	p.Observe(5)
	fc.advance(10 * time.Millisecond)
	p.Observe(6)
	fc.advance(10 * time.Millisecond)
	p.Observe(7)

	snap := p.Snapshot()
	if snap.JitterMicros != 0 {
		t.Fatalf("JitterMicros = %f, want 0: a gap's inflated interval must not be treated as a jitter sample", snap.JitterMicros)
	}
}

func TestSnapshot_LossRate(t *testing.T) {
	cases := []struct {
		name string
		snap Snapshot
		want float64
	}{
		{"nothing observed", Snapshot{}, 0},
		{"no loss", Snapshot{Received: 10, Lost: 0}, 0},
		{"half lost", Snapshot{Received: 10, Lost: 10}, 0.5},
		{"all lost but one seen", Snapshot{Received: 1, Lost: 99}, 0.99},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.snap.LossRate(); got != tc.want {
				t.Fatalf("LossRate() = %f, want %f", got, tc.want)
			}
		})
	}
}

func TestPassiveTracker_Reset(t *testing.T) {
	p, fc := newTestTracker()
	p.Observe(1)
	fc.advance(10 * time.Millisecond)
	p.Observe(5) // induces loss
	fc.advance(10 * time.Millisecond)
	p.Observe(6)

	if snap := p.Snapshot(); snap.Received == 0 || snap.Lost == 0 {
		t.Fatalf("test setup didn't produce nonzero state: %+v", snap)
	}

	p.Reset()
	snap := p.Snapshot()
	if snap != (Snapshot{}) {
		t.Fatalf("Snapshot after Reset = %+v, want zero value", snap)
	}

	// The tracker must also behave like a fresh one afterward: the next
	// Observe must not be treated as a gap relative to pre-Reset state.
	p.Observe(1000)
	snap = p.Snapshot()
	if snap.Lost != 0 || snap.Received != 1 {
		t.Fatalf("post-Reset first Observe: got %+v, want Received=1 Lost=0", snap)
	}
}

func TestPassiveTracker_ConcurrentObserve_NoRaceNoLostUpdates(t *testing.T) {
	p := NewPassiveTracker()

	const goroutines = 20
	const perGoroutine = 200
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			base := uint64(g) * perGoroutine
			for i := uint64(0); i < perGoroutine; i++ {
				p.Observe(base + i)
			}
		}(g)
	}
	wg.Wait()

	snap := p.Snapshot()
	if snap.Received != goroutines*perGoroutine {
		t.Fatalf("Received = %d, want %d (mutex must serialize every Observe call)", snap.Received, goroutines*perGoroutine)
	}
}
