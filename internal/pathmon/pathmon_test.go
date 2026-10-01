package pathmon

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ngthdong/egressa/internal/measurement"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestWindow_ForgetsOldSamples(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	w := newWindowAt(measurement.DefaultSegmentTrackerConfig, 10*time.Second, c.now)
	// A long, steady 5 ms history.
	for i := 0; i < 600; i++ {
		w.Observe(5 * time.Millisecond)
		c.add(100 * time.Millisecond)
	}
	if p50 := w.Snapshot().P50Micros; p50 < 4000 || p50 > 6000 {
		t.Fatalf("steady P50 = %.0f us", p50)
	}
	// The path turns to 200 ms. Within one span the median follows; a
	// plain SegmentTracker would need another 60 s of samples.
	for i := 0; i < 100; i++ {
		w.Observe(200 * time.Millisecond)
		c.add(100 * time.Millisecond)
	}
	if p50 := w.Snapshot().P50Micros; p50 < 150000 {
		t.Fatalf("P50 = %.0f us 10 s after the path changed; still remembering the old path", p50)
	}
	s := w.Snapshot()
	if s.N < 50 || s.N > 100 {
		t.Errorf("N = %d, want between half a span and a span of samples", s.N)
	}
}

func TestWindow_Loss(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	w := newWindowAt(measurement.DefaultSegmentTrackerConfig, 10*time.Second, c.now)
	for i := 0; i < 10; i++ {
		w.Observe(time.Millisecond)
		w.ObserveLoss()
	}
	if s := w.Snapshot(); s.LossRate != 0.5 || s.N != 20 {
		t.Fatalf("loss %.2f over %d samples", s.LossRate, s.N)
	}
}

func testConfig() Config {
	return Config{
		Budget:       measurement.NewProbeBudget(1<<20, 1<<20),
		FastInterval: 20 * time.Millisecond, SteadyInterval: 20 * time.Millisecond, RampSamples: 5,
		Timeout: 200 * time.Millisecond, Window: 10 * time.Second,
		Tracker: measurement.DefaultSegmentTrackerConfig,
	}
}

func TestMonitor_MeasuresAndCountsLoss(t *testing.T) {
	echo, err := ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echo.Close() }()
	go func() { _ = Echo(echo) }()

	// A socket nobody answers on: every probe to it is lost.
	silent, err := ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = silent.Close() }()

	conn, err := ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	m := NewMonitor(conn, testConfig())
	if err := m.Set(map[string]netip.AddrPort{
		"up":   echo.LocalAddr().(*net.UDPAddr).AddrPort(),
		"down": silent.LocalAddr().(*net.UDPAddr).AddrPort(),
	}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = m.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		up, last, _ := m.Stats("up")
		down, _, _ := m.Stats("down")
		if up.N >= 10 && down.N >= 5 {
			if up.LossRate != 0 || time.Since(last) > time.Second || up.P50Micros <= 0 {
				t.Fatalf("up: %+v, last reply %s ago", up, time.Since(last))
			}
			if down.LossRate != 1 {
				t.Fatalf("down: loss %.2f, want 1", down.LossRate)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if up, _, _ := m.Stats("up"); up.N < 10 {
		t.Fatalf("only %d samples in 5 s", up.N)
	}

	// Removing a target drops it; keeping one keeps its history.
	before, _, _ := m.Stats("up")
	if err := m.Set(map[string]netip.AddrPort{"up": echo.LocalAddr().(*net.UDPAddr).AddrPort()}); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := m.Stats("down"); ok {
		t.Error("a removed target still has stats")
	}
	if after, _, _ := m.Stats("up"); after.N < before.N {
		t.Errorf("a kept target lost its history: %d -> %d samples", before.N, after.N)
	}
}

func TestEcho_IgnoresStrangers(t *testing.T) {
	echo, err := ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = Echo(echo) }()
	c, err := net.DialUDP("udp4", nil, echo.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write(make([]byte, 64)); err != nil { // no magic
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := c.Read(make([]byte, 64)); err == nil {
		t.Error("echoed a datagram that is not a probe")
	}
	if err := echo.Close(); err != nil {
		t.Fatal(err)
	}
}
