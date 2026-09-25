package measurement

import (
	"fmt"
	"sync"
	"time"
)

const rttGain = 1.0 / 8.0

// ProbeSender sends a probe payload and returns after it is handed off.
type ProbeSender func(probeID uint32, payload []byte) error

type ProbeStats struct {
	Sent      uint64
	Replied   uint64
	Lost      uint64
	RTTMicros float64
}

func (s ProbeStats) LossRate() float64 {
	if s.Sent == 0 {
		return 0
	}
	return float64(s.Lost) / float64(s.Sent)
}

// probeRateSchedule controls the probe interval during ramp-up and steady state.
type probeRateSchedule struct {
	fastInterval   time.Duration
	steadyInterval time.Duration
	rampSamples    int
}

func (s probeRateSchedule) NextInterval(sent uint64) time.Duration {
	if sent < uint64(s.rampSamples) {
		return s.fastInterval
	}
	return s.steadyInterval
}

type ProberConfig struct {
	Send      ProbeSender
	Budget    *ProbeBudget
	ProbeSize int
	Timeout   time.Duration

	FastInterval   time.Duration
	SteadyInterval time.Duration
	RampSamples    int
}

func (c ProberConfig) validate() error {
	switch {
	case c.Send == nil:
		return fmt.Errorf("measurement: ProberConfig.Send is required")
	case c.Budget == nil:
		return fmt.Errorf("measurement: ProberConfig.Budget is required")
	case c.ProbeSize <= 0:
		return fmt.Errorf("measurement: ProberConfig.ProbeSize must be positive, got %d", c.ProbeSize)
	case c.Timeout <= 0:
		return fmt.Errorf("measurement: ProberConfig.Timeout must be positive, got %s", c.Timeout)
	case c.FastInterval <= 0:
		return fmt.Errorf("measurement: ProberConfig.FastInterval must be positive, got %s", c.FastInterval)
	case c.SteadyInterval <= 0:
		return fmt.Errorf("measurement: ProberConfig.SteadyInterval must be positive, got %s", c.SteadyInterval)
	}
	return nil
}

// Prober actively measures one candidate using RTT and probe loss.
// It is transport-agnostic; callers drive probing, deliver replies, and
// expire outstanding probes.
type Prober struct {
	mu sync.Mutex

	cfg  ProberConfig
	rate probeRateSchedule

	nextProbeID uint32
	outstanding map[uint32]time.Time // probeID -> sent-at
	lastSent    time.Time
	haveSent    bool

	stats ProbeStats

	now func() time.Time
}

func NewProber(cfg ProberConfig) (*Prober, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Prober{
		cfg:         cfg,
		rate:        probeRateSchedule{cfg.FastInterval, cfg.SteadyInterval, cfg.RampSamples},
		outstanding: make(map[uint32]time.Time),
		now:         time.Now,
	}, nil
}

// MaybeProbe sends a probe when the rate schedule and shared budget allow.
// It returns nil when the probe is not due or the budget is exhausted.
func (p *Prober) MaybeProbe() error {
	p.mu.Lock()

	now := p.now()
	if p.haveSent {
		interval := p.rate.NextInterval(p.stats.Sent)
		if now.Sub(p.lastSent) < interval {
			p.mu.Unlock()
			return nil
		}
	}
	if !p.cfg.Budget.TryTake(p.cfg.ProbeSize) {
		p.mu.Unlock()
		return nil
	}

	id := p.nextProbeID
	p.nextProbeID++
	p.outstanding[id] = now
	p.stats.Sent++
	p.lastSent = now
	p.haveSent = true
	send := p.cfg.Send
	size := p.cfg.ProbeSize
	p.mu.Unlock()

	// Send outside the lock so a slow sender cannot block other operations.
	if err := send(id, make([]byte, size)); err != nil {
		return fmt.Errorf("measurement: send probe %d: %w", id, err)
	}
	return nil
}

// OnReply records a reply and updates the smoothed RTT estimate.
// Unknown or expired probe IDs are ignored.
func (p *Prober) OnReply(probeID uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	sentAt, ok := p.outstanding[probeID]
	if !ok {
		return
	}
	delete(p.outstanding, probeID)

	rtt := p.now().Sub(sentAt)
	p.stats.Replied++
	if p.stats.Replied == 1 {
		p.stats.RTTMicros = float64(rtt.Microseconds())
	} else {
		p.stats.RTTMicros += (float64(rtt.Microseconds()) - p.stats.RTTMicros) * rttGain
	}
}

func (p *Prober) ExpireTimeouts() {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.now()
	for id, sentAt := range p.outstanding {
		if now.Sub(sentAt) >= p.cfg.Timeout {
			delete(p.outstanding, id)
			p.stats.Lost++
		}
	}
}

func (p *Prober) Stats() ProbeStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stats
}
