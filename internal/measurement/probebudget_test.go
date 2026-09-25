package measurement

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeBudget_AllowsWithinBurst(t *testing.T) {
	fc := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	b := NewProbeBudget(100, 1000) // 1000-byte burst
	b.now = fc.now

	if !b.TryTake(500) {
		t.Fatal("TryTake(500) failed within a 1000-byte burst")
	}
	if !b.TryTake(500) {
		t.Fatal("TryTake(500) (second) failed within a 1000-byte burst")
	}
}

func TestProbeBudget_BlocksOverBurst(t *testing.T) {
	fc := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	b := NewProbeBudget(0, 1000) // no refill, so the burst is a hard cap
	b.now = fc.now

	if !b.TryTake(1000) {
		t.Fatal("TryTake(1000) failed while exactly at the burst capacity")
	}
	if b.TryTake(1) {
		t.Fatal("TryTake(1) succeeded after the burst was fully spent with zero refill rate")
	}
}

func TestProbeBudget_RefillsOverTime(t *testing.T) {
	fc := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	b := NewProbeBudget(100, 100) // 100 bytes/sec, burst = 100
	b.now = fc.now

	if !b.TryTake(100) {
		t.Fatal("TryTake(100) failed at full burst")
	}
	if b.TryTake(1) {
		t.Fatal("TryTake(1) succeeded immediately after exhausting the burst")
	}

	fc.advance(500 * time.Millisecond) // should refill ~50 bytes
	if b.TryTake(51) {
		t.Fatal("TryTake(51) succeeded after only ~50 bytes should have refilled")
	}
	if !b.TryTake(50) {
		t.Fatal("TryTake(50) failed after ~50 bytes should have refilled")
	}
}

func TestProbeBudget_NeverExceedsCapacityEvenAfterLongIdle(t *testing.T) {
	fc := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	b := NewProbeBudget(1_000_000, 100) // huge rate, small burst cap
	b.now = fc.now

	if !b.TryTake(100) {
		t.Fatal("TryTake(100) failed at full burst")
	}
	fc.advance(time.Hour) // would refill far more than the 100-byte cap allows
	if b.TryTake(101) {
		t.Fatal("TryTake(101) succeeded: tokens must be clamped to capacity, not accumulate unbounded")
	}
	if !b.TryTake(100) {
		t.Fatal("TryTake(100) failed after a long idle period; capacity should be fully available")
	}
}

func TestProbeBudget_NegativeRateClampedToZero(t *testing.T) {
	fc := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	b := NewProbeBudget(-5, 10)
	b.now = fc.now

	if !b.TryTake(10) {
		t.Fatal("TryTake(10) failed within the initial burst")
	}
	fc.advance(time.Hour)
	if b.TryTake(1) {
		t.Fatal("TryTake(1) succeeded with a negative rate clamped to zero: budget must never refill")
	}
}

func TestProbeBudget_ConcurrentTryTake_NoDoubleSpend(t *testing.T) {
	b := NewProbeBudget(0, 1000) // fixed 1000-byte budget, no refill
	const (
		goroutines   = 50
		attempts     = 10
		probeSize    = 20
		maxSuccesses = 1000 / probeSize // exactly 50
	)

	var successes int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < attempts; j++ {
				if b.TryTake(probeSize) {
					atomic.AddInt64(&successes, 1)
				}
			}
		}()
	}
	wg.Wait()

	if successes != int64(maxSuccesses) {
		t.Fatalf("successes = %d, want exactly %d (1000-byte budget / %d-byte probes): a race would over- or under-count this", successes, maxSuccesses, probeSize)
	}
}
