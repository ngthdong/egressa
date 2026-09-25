package measurement

import (
	"sync"
	"time"
)

// ProbeBudget limits aggregate probe traffic using a token bucket.
// All Probers sharing a budget consume from the same global allowance.
type ProbeBudget struct {
	mu sync.Mutex

	ratePerSecond float64
	capacity      float64
	tokens        float64
	lastRefill    time.Time
	now           func() time.Time
}

func NewProbeBudget(ratePerSecond, burstBytes float64) *ProbeBudget {
	if ratePerSecond < 0 {
		ratePerSecond = 0
	}
	if burstBytes < 0 {
		burstBytes = 0
	}
	now := time.Now
	return &ProbeBudget{
		ratePerSecond: ratePerSecond,
		capacity:      burstBytes,
		tokens:        burstBytes, // start full: probing may run immediately, not wait one refill period first
		lastRefill:    now(),
		now:           now,
	}
}

// TryTake consumes size bytes from the budget if available.
// It returns false when the probe must be skipped.
func (b *ProbeBudget) TryTake(size int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	if elapsed := now.Sub(b.lastRefill).Seconds(); elapsed > 0 {
		b.tokens += elapsed * b.ratePerSecond
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
	}
	b.lastRefill = now

	if float64(size) > b.tokens {
		return false
	}
	b.tokens -= float64(size)
	return true
}
