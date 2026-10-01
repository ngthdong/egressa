package pathmon

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/ngthdong/egressa/internal/measurement"
)

// probeMagic starts every probe, so stray datagrams are never mistaken
// for replies.
var probeMagic = [4]byte{'E', 'G', 'P', 'R'}

const (
	// ProbeSize is the size of a probe datagram.
	ProbeSize = 64
	headerLen = 12 // magic, target index, probe ID
)

// Echo answers probes on conn until it is closed: every datagram that
// starts with the probe magic goes straight back to its sender.
func Echo(conn net.PacketConn) error {
	buf := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if n < headerLen || [4]byte(buf[:4]) != probeMagic {
			continue
		}
		_, _ = conn.WriteTo(buf[:n], from)
	}
}

// Config configures a Monitor.
type Config struct {
	// Budget caps the probe traffic of every target together.
	Budget *measurement.ProbeBudget
	// FastInterval is the probe interval for a target's first
	// RampSamples probes, SteadyInterval after that.
	FastInterval   time.Duration
	SteadyInterval time.Duration
	RampSamples    int
	// Timeout is how long a probe may go unanswered before it counts as
	// lost.
	Timeout time.Duration
	// Window is how much history a target's stats cover.
	Window  time.Duration
	Tracker measurement.SegmentTrackerConfig
}

// DefaultConfig probes every 200 ms at first, then every 250 ms, counts a
// probe lost after 1 s, and keeps about 10 s of history. That is roughly
// 260 B/s per target, enough samples per window for a confident decision.
// The budget, 64 KiB/s, is fresh on every call.
func DefaultConfig() Config {
	return Config{
		Budget:         measurement.NewProbeBudget(64*1024, 64*1024),
		FastInterval:   200 * time.Millisecond,
		SteadyInterval: 250 * time.Millisecond,
		RampSamples:    20,
		Timeout:        time.Second,
		Window:         10 * time.Second,
		Tracker:        measurement.DefaultSegmentTrackerConfig,
	}
}

type target struct {
	id     string
	index  uint32
	addr   *net.UDPAddr
	prober *measurement.Prober
	window *Window

	// guarded by Monitor.mu
	sent      map[uint32]time.Time
	lastReply time.Time
}

// Monitor probes a changing set of targets over one UDP socket.
type Monitor struct {
	cfg  Config
	conn net.PacketConn

	mu        sync.Mutex
	targets   map[string]*target
	byIndex   map[uint32]*target
	nextIndex uint32
}

// NewMonitor probes from conn, which it takes ownership of.
func NewMonitor(conn net.PacketConn, cfg Config) *Monitor {
	return &Monitor{cfg: cfg, conn: conn, targets: make(map[string]*target), byIndex: make(map[uint32]*target)}
}

// Set makes the targets exactly those in addrs (target ID -> address).
// A target whose address is unchanged keeps its history.
func (m *Monitor) Set(addrs map[string]netip.AddrPort) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, t := range m.targets {
		if a, ok := addrs[id]; !ok || a != t.addr.AddrPort() {
			delete(m.targets, id)
			delete(m.byIndex, t.index)
		}
	}
	for id, a := range addrs {
		if _, ok := m.targets[id]; ok {
			continue
		}
		t := &target{
			id: id, index: m.nextIndex, addr: net.UDPAddrFromAddrPort(a),
			window: NewWindow(m.cfg.Tracker, m.cfg.Window),
			sent:   make(map[uint32]time.Time),
		}
		m.nextIndex++
		p, err := measurement.NewProber(measurement.ProberConfig{
			Send:           m.sender(t),
			Budget:         m.cfg.Budget,
			ProbeSize:      ProbeSize,
			Timeout:        m.cfg.Timeout,
			FastInterval:   m.cfg.FastInterval,
			SteadyInterval: m.cfg.SteadyInterval,
			RampSamples:    m.cfg.RampSamples,
		})
		if err != nil {
			return err
		}
		t.prober = p
		m.targets[id] = t
		m.byIndex[t.index] = t
	}
	return nil
}

func (m *Monitor) sender(t *target) measurement.ProbeSender {
	return func(id uint32, payload []byte) error {
		copy(payload, probeMagic[:])
		binary.BigEndian.PutUint32(payload[4:], t.index)
		binary.BigEndian.PutUint32(payload[8:], id)
		m.mu.Lock()
		t.sent[id] = time.Now()
		m.mu.Unlock()
		_, err := m.conn.WriteTo(payload, t.addr)
		return err
	}
}

// Run probes until ctx ends, then closes the socket.
func (m *Monitor) Run(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = m.conn.Close()
	}()
	go m.receive()
	tick := time.NewTicker(m.cfg.FastInterval / 4)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			m.tick()
		}
	}
}

func (m *Monitor) tick() {
	m.mu.Lock()
	ts := make([]*target, 0, len(m.targets))
	now := time.Now()
	for _, t := range m.targets {
		ts = append(ts, t)
		for id, at := range t.sent {
			if now.Sub(at) >= m.cfg.Timeout {
				delete(t.sent, id)
				t.window.ObserveLoss()
			}
		}
	}
	m.mu.Unlock()
	for _, t := range ts {
		t.prober.ExpireTimeouts()
		// A send error (no route yet, say) is a lost probe like any
		// other; the timeout above already counts it.
		_ = t.prober.MaybeProbe()
	}
}

func (m *Monitor) receive() {
	buf := make([]byte, 1500)
	for {
		n, _, err := m.conn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n < headerLen || [4]byte(buf[:4]) != probeMagic {
			continue
		}
		index := binary.BigEndian.Uint32(buf[4:])
		id := binary.BigEndian.Uint32(buf[8:])
		now := time.Now()
		m.mu.Lock()
		t, ok := m.byIndex[index]
		var sentAt time.Time
		if ok {
			sentAt, ok = t.sent[id]
			delete(t.sent, id)
			if ok {
				t.lastReply = now
			}
		}
		m.mu.Unlock()
		if !ok {
			continue // late (already counted lost) or for a removed target
		}
		t.window.Observe(now.Sub(sentAt))
		t.prober.OnReply(id)
	}
}

// Stats returns target id's current stats; ok is false for an unknown
// target.
func (m *Monitor) Stats(id string) (stats measurement.SegmentStats, lastReply time.Time, ok bool) {
	m.mu.Lock()
	t, ok := m.targets[id]
	if ok {
		lastReply = t.lastReply
	}
	m.mu.Unlock()
	if !ok {
		return measurement.SegmentStats{}, time.Time{}, false
	}
	return t.window.Snapshot(), lastReply, true
}

// ListenUDP opens a probe socket bound to local (port 0 for any).
func ListenUDP(local netip.AddrPort) (net.PacketConn, error) {
	c, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(local))
	if err != nil {
		return nil, fmt.Errorf("pathmon: listen on %s: %w", local, err)
	}
	return c, nil
}
