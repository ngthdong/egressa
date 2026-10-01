// Package pathmon measures overlay paths with UDP probes: a client probes
// every access gateway through its tunnel, and a gateway probes each of
// its backbone peers. Every probe is a datagram to a gateway's NodeIP,
// which echoes it back.
package pathmon

import (
	"sync"
	"time"

	"github.com/ngthdong/egressa/internal/measurement"
)

// Window gives a measurement.SegmentTracker a bounded memory.
//
// A SegmentTracker's P50/P95 come from P² estimators, which never forget:
// after an hour of 5 ms samples, a path that turns to 200 ms takes most
// of another hour to move its median. A path monitor has to follow the
// path as it is now, so Window keeps two trackers that both see every
// sample and starts the older one afresh every Span/2. Stats come from the
// older of the two, which always holds between Span/2 and Span of history.
type Window struct {
	cfg  measurement.SegmentTrackerConfig
	span time.Duration
	now  func() time.Time

	mu      sync.Mutex
	old     *measurement.SegmentTracker
	young   *measurement.SegmentTracker
	rotated time.Time
}

// NewWindow returns a Window that remembers about span of samples.
func NewWindow(cfg measurement.SegmentTrackerConfig, span time.Duration) *Window {
	return newWindowAt(cfg, span, time.Now)
}

func newWindowAt(cfg measurement.SegmentTrackerConfig, span time.Duration, now func() time.Time) *Window {
	return &Window{
		cfg: cfg, span: span, now: now,
		old:     measurement.NewSegmentTracker(cfg),
		young:   measurement.NewSegmentTracker(cfg),
		rotated: now(),
	}
}

func (w *Window) rotateLocked() {
	if w.now().Sub(w.rotated) < w.span/2 {
		return
	}
	w.old, w.young = w.young, measurement.NewSegmentTracker(w.cfg)
	w.rotated = w.now()
}

// Observe records a reply that took rtt.
func (w *Window) Observe(rtt time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rotateLocked()
	us := float64(rtt.Microseconds())
	w.old.Observe(us)
	w.young.Observe(us)
}

// ObserveLoss records a probe that got no reply.
func (w *Window) ObserveLoss() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rotateLocked()
	w.old.ObserveLoss()
	w.young.ObserveLoss()
}

// Snapshot returns the stats of the last Span/2 to Span.
func (w *Window) Snapshot() measurement.SegmentStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rotateLocked()
	return w.old.Snapshot()
}
