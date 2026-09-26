package measurement

import (
	"math"
	"sync"
	"time"
)

const segmentStatsAlpha = rttGain

// SegmentStats contains the current quality metrics for a segment.
type SegmentStats struct {
	P50Micros float64
	P95Micros float64
	LossRate  float64

	// VarianceMicros2 is the EWMA variance of RTT in microseconds².
	VarianceMicros2 float64

	// N is the total number of successful and lost observations.
	N uint64

	// Age is how long ago the most recent sample (success or loss) was
	// recorded. Zero if nothing has ever been observed.
	Age time.Duration

	// Confidence is a value in [0, 1] indicating how much the metrics
	// should be trusted based on sample count and observation freshness.
	Confidence float64
}

type SegmentTrackerConfig struct {
	// SampleHalfCount is the sample count at which the sample-count
	// confidence component reaches 0.5.
	SampleHalfCount float64

	// StalenessHalfLife is the age at which the freshness confidence
	// component reaches 0.5.
	StalenessHalfLife time.Duration
}

// DefaultSegmentTrackerConfig treats 20 samples and 30 seconds of
// silence as each independently halving confidence -- reasonable
// starting points for a segment probed or carrying traffic on the order
// of once per second or faster. Tune per deployment: a segment probed
// only every few minutes (Stage 11's steady-rate schedule, say) would
// want a much longer StalenessHalfLife, or every reading would be
// permanently reported as low-confidence.
var DefaultSegmentTrackerConfig = SegmentTrackerConfig{
	SampleHalfCount:   20,
	StalenessHalfLife: 30 * time.Second,
}

// SegmentTracker accumulates RTT and loss measurements for a segment.
// RTT is tracked using an EWMA mean and variance and streaming P²
// estimators for P50 and P95. Raw samples are not retained.
// Confidence decreases with both insufficient samples and stale
// observations.
type SegmentTracker struct {
	mu  sync.Mutex
	cfg SegmentTrackerConfig

	p50 *p2Quantile
	p95 *p2Quantile

	haveMean bool
	mean     float64
	varEWMA  float64

	successes uint64
	losses    uint64

	haveSample bool
	lastSample time.Time

	now func() time.Time
}

func NewSegmentTracker(cfg SegmentTrackerConfig) *SegmentTracker {
	if cfg.SampleHalfCount <= 0 {
		cfg.SampleHalfCount = DefaultSegmentTrackerConfig.SampleHalfCount
	}
	if cfg.StalenessHalfLife <= 0 {
		cfg.StalenessHalfLife = DefaultSegmentTrackerConfig.StalenessHalfLife
	}
	return &SegmentTracker{
		cfg: cfg,
		p50: newP2Quantile(0.5),
		p95: newP2Quantile(0.95),
		now: time.Now,
	}
}

// Observe records a successful observation with RTT in microseconds.
func (t *SegmentTracker) Observe(rttMicros float64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.p50.Observe(rttMicros)
	t.p95.Observe(rttMicros)

	if !t.haveMean {
		t.mean = rttMicros
		t.varEWMA = 0
		t.haveMean = true
	} else {
		// Update the EWMA mean and variance together so both adapt to
		// changes in the underlying RTT distribution.
		diff := rttMicros - t.mean
		incr := segmentStatsAlpha * diff
		t.mean += incr
		t.varEWMA = (1 - segmentStatsAlpha) * (t.varEWMA + diff*incr)
	}

	t.successes++
	t.lastSample = t.now()
	t.haveSample = true
}

// ObserveLoss records a lost observation.
// A loss contributes to the sample count and loss rate and refreshes the
// observation timestamp, but does not contribute to RTT statistics.
func (t *SegmentTracker) ObserveLoss() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.losses++
	t.lastSample = t.now()
	t.haveSample = true
}

func (t *SegmentTracker) Snapshot() SegmentStats {
	t.mu.Lock()
	defer t.mu.Unlock()

	n := t.successes + t.losses
	var lossRate float64
	if n > 0 {
		lossRate = float64(t.losses) / float64(n)
	}

	var age time.Duration
	if t.haveSample {
		age = t.now().Sub(t.lastSample)
	}

	return SegmentStats{
		P50Micros:       t.p50.Value(),
		P95Micros:       t.p95.Value(),
		LossRate:        lossRate,
		VarianceMicros2: t.varEWMA,
		N:               n,
		Age:             age,
		Confidence:      t.confidenceLocked(n, age),
	}
}

// confidenceLocked derives confidence from sample count and observation age.
// The two components are multiplied so both sufficient sample history and
// recent evidence are required for high confidence.
func (t *SegmentTracker) confidenceLocked(n uint64, age time.Duration) float64 {
	if n == 0 {
		return 0
	}
	sampleConf := float64(n) / (float64(n) + t.cfg.SampleHalfCount)
	ageRatio := float64(age) / float64(t.cfg.StalenessHalfLife)
	freshConf := math.Exp2(-ageRatio)
	return sampleConf * freshConf
}
