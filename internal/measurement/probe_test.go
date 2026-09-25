package measurement

import (
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeSender struct {
	mu   sync.Mutex
	sent []uint32
	err  error
}

func (s *fakeSender) send(probeID uint32, _ []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.sent = append(s.sent, probeID)
	return nil
}

func (s *fakeSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

func unlimitedBudget() *ProbeBudget {
	return NewProbeBudget(1_000_000_000, 1_000_000_000)
}

func newTestProber(t *testing.T, cfg ProberConfig) (*Prober, *fakeClock) {
	t.Helper()
	fc := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	p, err := NewProber(cfg)
	if err != nil {
		t.Fatalf("NewProber: %v", err)
	}
	p.now = fc.now
	return p, fc
}

func TestNewProber_Validation(t *testing.T) {
	valid := ProberConfig{
		Send: func(uint32, []byte) error { return nil }, Budget: unlimitedBudget(),
		ProbeSize: 32, Timeout: time.Second, FastInterval: time.Millisecond, SteadyInterval: time.Second,
	}
	if _, err := NewProber(valid); err != nil {
		t.Fatalf("NewProber(valid config) failed: %v", err)
	}

	cases := []struct {
		name string
		mod  func(c ProberConfig) ProberConfig
	}{
		{"nil Send", func(c ProberConfig) ProberConfig { c.Send = nil; return c }},
		{"nil Budget", func(c ProberConfig) ProberConfig { c.Budget = nil; return c }},
		{"zero ProbeSize", func(c ProberConfig) ProberConfig { c.ProbeSize = 0; return c }},
		{"zero Timeout", func(c ProberConfig) ProberConfig { c.Timeout = 0; return c }},
		{"zero FastInterval", func(c ProberConfig) ProberConfig { c.FastInterval = 0; return c }},
		{"zero SteadyInterval", func(c ProberConfig) ProberConfig { c.SteadyInterval = 0; return c }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewProber(tc.mod(valid)); err == nil {
				t.Fatalf("NewProber(%s): expected an error", tc.name)
			}
		})
	}
}

func TestProber_MaybeProbe_FirstCallAlwaysSends(t *testing.T) {
	sender := &fakeSender{}
	p, _ := newTestProber(t, ProberConfig{
		Send: sender.send, Budget: unlimitedBudget(), ProbeSize: 32,
		Timeout: time.Second, FastInterval: 10 * time.Millisecond, SteadyInterval: time.Second,
	})

	if err := p.MaybeProbe(); err != nil {
		t.Fatalf("MaybeProbe: %v", err)
	}
	if sender.count() != 1 {
		t.Fatalf("sent %d probes, want 1", sender.count())
	}
	if got := p.Stats().Sent; got != 1 {
		t.Fatalf("Stats().Sent = %d, want 1", got)
	}
}

func TestProber_MaybeProbe_RespectsInterval(t *testing.T) {
	sender := &fakeSender{}
	p, fc := newTestProber(t, ProberConfig{
		Send: sender.send, Budget: unlimitedBudget(), ProbeSize: 32,
		Timeout: time.Second, FastInterval: 50 * time.Millisecond, SteadyInterval: time.Second, RampSamples: 100,
	})

	_ = p.MaybeProbe() // sends #1
	_ = p.MaybeProbe() // too soon, must not send #2
	if sender.count() != 1 {
		t.Fatalf("sent %d probes before the interval elapsed, want 1", sender.count())
	}

	fc.advance(49 * time.Millisecond)
	_ = p.MaybeProbe() // still 1ms short
	if sender.count() != 1 {
		t.Fatalf("sent %d probes at 49ms/50ms interval, want 1", sender.count())
	}

	fc.advance(1 * time.Millisecond) // now exactly 50ms since #1
	_ = p.MaybeProbe()
	if sender.count() != 2 {
		t.Fatalf("sent %d probes once the interval fully elapsed, want 2", sender.count())
	}
}

func TestProber_MaybeProbe_AdaptiveRateSwitchesAfterRamp(t *testing.T) {
	sender := &fakeSender{}
	p, fc := newTestProber(t, ProberConfig{
		Send: sender.send, Budget: unlimitedBudget(), ProbeSize: 32,
		Timeout: time.Second, FastInterval: 10 * time.Millisecond, SteadyInterval: 200 * time.Millisecond, RampSamples: 2,
	})

	_ = p.MaybeProbe() // sent #1 (Sent was 0 < RampSamples=2 -> fast interval governs the NEXT wait)
	fc.advance(10 * time.Millisecond)
	_ = p.MaybeProbe() // sent #2 (Sent was 1 < 2 -> still fast)
	if sender.count() != 2 {
		t.Fatalf("sent %d probes during ramp, want 2", sender.count())
	}

	// Sent is now 2, so NextInterval(2) must return steadyInterval
	// (200ms), not fastInterval (10ms).
	fc.advance(10 * time.Millisecond)
	_ = p.MaybeProbe()
	if sender.count() != 2 {
		t.Fatalf("sent %d probes only 10ms after leaving ramp, want still 2 (steady interval should now apply)", sender.count())
	}

	fc.advance(190 * time.Millisecond) // total 200ms since #2
	_ = p.MaybeProbe()
	if sender.count() != 3 {
		t.Fatalf("sent %d probes after the full steady interval, want 3", sender.count())
	}
}

func TestProber_MaybeProbe_RespectsBudget(t *testing.T) {
	sender := &fakeSender{}
	budget := NewProbeBudget(0, 32) // exactly one probe's worth, never refills
	p, fc := newTestProber(t, ProberConfig{
		Send: sender.send, Budget: budget, ProbeSize: 32,
		Timeout: time.Second, FastInterval: time.Millisecond, SteadyInterval: time.Millisecond,
	})

	_ = p.MaybeProbe() // consumes the only 32 bytes in the budget
	fc.advance(time.Second)
	_ = p.MaybeProbe() // rate allows it, but budget is exhausted and never refills
	if sender.count() != 1 {
		t.Fatalf("sent %d probes, want exactly 1 (budget must block the second even though the rate schedule allows it)", sender.count())
	}
	if got := p.Stats().Sent; got != 1 {
		t.Fatalf("Stats().Sent = %d, want 1 (a budget-blocked attempt must not count as sent)", got)
	}
}

func TestProber_MaybeProbe_SendError(t *testing.T) {
	sender := &fakeSender{err: errors.New("network unreachable")}
	p, _ := newTestProber(t, ProberConfig{
		Send: sender.send, Budget: unlimitedBudget(), ProbeSize: 32,
		Timeout: time.Second, FastInterval: time.Millisecond, SteadyInterval: time.Millisecond,
	})
	if err := p.MaybeProbe(); err == nil {
		t.Fatal("MaybeProbe: expected an error when Send fails")
	}
	if got := p.Stats().Sent; got != 1 {
		t.Fatalf("Stats().Sent = %d, want 1 even though Send returned an error", got)
	}
}

func TestProber_OnReply_ComputesRTT(t *testing.T) {
	sender := &fakeSender{}
	p, fc := newTestProber(t, ProberConfig{
		Send: sender.send, Budget: unlimitedBudget(), ProbeSize: 32,
		Timeout: time.Second, FastInterval: time.Millisecond, SteadyInterval: time.Millisecond,
	})
	_ = p.MaybeProbe() // probe ID 0
	fc.advance(20 * time.Millisecond)
	p.OnReply(0)

	stats := p.Stats()
	if stats.Replied != 1 {
		t.Fatalf("Replied = %d, want 1", stats.Replied)
	}
	if stats.RTTMicros != 20_000 {
		t.Fatalf("RTTMicros = %f, want 20000 (first sample is exact, not yet smoothed)", stats.RTTMicros)
	}
}

func TestProber_OnReply_UnknownProbeIDIgnored(t *testing.T) {
	sender := &fakeSender{}
	p, _ := newTestProber(t, ProberConfig{
		Send: sender.send, Budget: unlimitedBudget(), ProbeSize: 32,
		Timeout: time.Second, FastInterval: time.Millisecond, SteadyInterval: time.Millisecond,
	})
	p.OnReply(999) // nothing was ever sent with this ID

	stats := p.Stats()
	if stats.Replied != 0 {
		t.Fatalf("Replied = %d, want 0 for a reply to an unknown probe ID", stats.Replied)
	}
}

func TestProber_OnReply_EWMASmoothsSubsequentRTTs(t *testing.T) {
	sender := &fakeSender{}
	p, fc := newTestProber(t, ProberConfig{
		Send: sender.send, Budget: unlimitedBudget(), ProbeSize: 32,
		Timeout: time.Second, FastInterval: time.Millisecond, SteadyInterval: time.Millisecond,
	})

	_ = p.MaybeProbe() // ID 0
	fc.advance(10 * time.Millisecond)
	p.OnReply(0) // RTT = 10ms exactly -> RTTMicros = 10000

	fc.advance(time.Millisecond)
	_ = p.MaybeProbe() // ID 1
	fc.advance(50 * time.Millisecond)
	p.OnReply(1) // RTT = 50ms

	stats := p.Stats()
	if stats.RTTMicros <= 10_000 || stats.RTTMicros >= 50_000 {
		t.Fatalf("RTTMicros = %f, want strictly between 10000 and 50000 (a smoothed value, not either raw sample)", stats.RTTMicros)
	}
}

func TestProber_ExpireTimeouts_CountsLoss(t *testing.T) {
	sender := &fakeSender{}
	p, fc := newTestProber(t, ProberConfig{
		Send: sender.send, Budget: unlimitedBudget(), ProbeSize: 32,
		Timeout: 100 * time.Millisecond, FastInterval: time.Millisecond, SteadyInterval: time.Millisecond,
	})
	_ = p.MaybeProbe() // ID 0

	fc.advance(99 * time.Millisecond)
	p.ExpireTimeouts()
	if got := p.Stats().Lost; got != 0 {
		t.Fatalf("Lost = %d, want 0 before the timeout elapses", got)
	}

	fc.advance(2 * time.Millisecond) // now 101ms since sent
	p.ExpireTimeouts()
	if got := p.Stats().Lost; got != 1 {
		t.Fatalf("Lost = %d, want 1 after the timeout elapses", got)
	}

	// A reply arriving after expiry must be ignored, not un-expire the
	// probe or double count anything.
	p.OnReply(0)
	stats := p.Stats()
	if stats.Replied != 0 || stats.Lost != 1 {
		t.Fatalf("stats after a late reply to an expired probe: %+v, want Replied=0 Lost=1", stats)
	}
}

func TestProber_ExpireTimeouts_DoesNotExpireRepliedOrFreshProbes(t *testing.T) {
	sender := &fakeSender{}
	p, fc := newTestProber(t, ProberConfig{
		Send: sender.send, Budget: unlimitedBudget(), ProbeSize: 32,
		Timeout: 100 * time.Millisecond, FastInterval: time.Millisecond, SteadyInterval: time.Millisecond,
	})

	_ = p.MaybeProbe() // ID 0
	fc.advance(10 * time.Millisecond)
	p.OnReply(0) // replied well before timeout

	fc.advance(time.Millisecond)
	_ = p.MaybeProbe() // ID 1, fresh
	fc.advance(10 * time.Millisecond)

	p.ExpireTimeouts()
	stats := p.Stats()
	if stats.Lost != 0 {
		t.Fatalf("Lost = %d, want 0: probe 0 already replied, probe 1 is still fresh", stats.Lost)
	}
	if stats.Replied != 1 {
		t.Fatalf("Replied = %d, want 1", stats.Replied)
	}
}

func TestProbeStats_LossRate(t *testing.T) {
	cases := []struct {
		name string
		s    ProbeStats
		want float64
	}{
		{"nothing sent", ProbeStats{}, 0},
		{"no loss", ProbeStats{Sent: 10, Lost: 0}, 0},
		{"half lost", ProbeStats{Sent: 10, Lost: 5}, 0.5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.LossRate(); got != tc.want {
				t.Fatalf("LossRate() = %f, want %f", got, tc.want)
			}
		})
	}
}
