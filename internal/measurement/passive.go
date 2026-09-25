package measurement

import (
	"sync"
	"time"
)

const jitterGain = 1.0 / 16.0

type Snapshot struct {
	Received     uint64
	Lost         uint64
	OutOfOrder   uint64
	JitterMicros float64
}

func (s Snapshot) LossRate() float64 {
	total := s.Received + s.Lost
	if total == 0 {
		return 0
	}
	return float64(s.Lost) / float64(total)
}

// PassiveTracker derives loss and inter-arrival jitter from a monotonically
// increasing packet sequence. It adds no traffic and uses only the local
// arrival clock.
type PassiveTracker struct {
	mu sync.Mutex

	started      bool
	expectedNext uint64

	received   uint64
	lost       uint64
	outOfOrder uint64

	lastArrival          time.Time
	lastInterarrival     time.Duration
	haveLastInterarrival bool
	jitterMicros         float64

	now func() time.Time
}

func NewPassiveTracker() *PassiveTracker {
	return &PassiveTracker{now: time.Now}
}

// Observe records a received packet and updates loss and jitter metrics.
// Call Observe as close to packet arrival as practical to avoid measuring
// local processing or queueing delay as network jitter.
func (p *PassiveTracker) Observe(seq uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.now()
	p.received++

	if !p.started {
		p.started = true
		p.expectedNext = seq + 1
		p.lastArrival = now
		return
	}

	switch {
	case seq == p.expectedNext:
		p.expectedNext = seq + 1
		p.recordArrival(now, true)
	case seq > p.expectedNext:
		// Treat the forward gap as lost packets. Do not use the gap
		// interval as a jitter sample.
		p.lost += seq - p.expectedNext
		p.expectedNext = seq + 1
		p.recordArrival(now, false)
	default:
		// Late or duplicate packets do not affect loss or timing state.
		p.outOfOrder++
	}
}

func (p *PassiveTracker) recordArrival(now time.Time, comparable bool) {
	interarrival := now.Sub(p.lastArrival)
	p.lastArrival = now

	if comparable && p.haveLastInterarrival {
		d := interarrival - p.lastInterarrival
		if d < 0 {
			d = -d
		}
		p.jitterMicros += (float64(d.Microseconds()) - p.jitterMicros) * jitterGain
	}

	p.lastInterarrival = interarrival
	p.haveLastInterarrival = comparable
}

func (p *PassiveTracker) Snapshot() Snapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Snapshot{
		Received:     p.received,
		Lost:         p.lost,
		OutOfOrder:   p.outOfOrder,
		JitterMicros: p.jitterMicros,
	}
}

func (p *PassiveTracker) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.started = false
	p.expectedNext = 0
	p.received = 0
	p.lost = 0
	p.outOfOrder = 0
	p.lastArrival = time.Time{}
	p.lastInterarrival = 0
	p.haveLastInterarrival = false
	p.jitterMicros = 0
}
