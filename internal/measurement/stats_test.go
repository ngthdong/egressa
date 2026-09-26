package measurement

import (
	"math"
	"sync"
	"testing"
	"time"
)

func newTestSegmentTracker(cfg SegmentTrackerConfig) (*SegmentTracker, *fakeClock) {
	fc := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	tr := NewSegmentTracker(cfg)
	tr.now = fc.now
	return tr, fc
}

func TestSegmentTracker_Empty(t *testing.T) {
	tr, _ := newTestSegmentTracker(SegmentTrackerConfig{})
	s := tr.Snapshot()
	if s.N != 0 || s.Confidence != 0 || s.Age != 0 || s.LossRate != 0 {
		t.Fatalf("Snapshot() on a fresh tracker = %+v, want all zero", s)
	}
}

func TestSegmentTracker_ObserveAndLoss_CountTowardN(t *testing.T) {
	tr, _ := newTestSegmentTracker(SegmentTrackerConfig{})
	tr.Observe(100)
	tr.Observe(100)
	tr.ObserveLoss()

	s := tr.Snapshot()
	if s.N != 3 {
		t.Fatalf("N = %d, want 3", s.N)
	}
	if got, want := s.LossRate, 1.0/3.0; math.Abs(got-want) > 1e-9 {
		t.Fatalf("LossRate = %f, want %f", got, want)
	}
}

func TestSegmentTracker_Variance_ZeroForConstantRTT(t *testing.T) {
	tr, _ := newTestSegmentTracker(SegmentTrackerConfig{})
	for i := 0; i < 20; i++ {
		tr.Observe(50_000)
	}
	s := tr.Snapshot()
	if s.VarianceMicros2 != 0 {
		t.Fatalf("VarianceMicros2 = %f, want 0 for a perfectly constant RTT stream", s.VarianceMicros2)
	}
}

func TestSegmentTracker_Variance_NonZeroForVariableRTT(t *testing.T) {
	tr, _ := newTestSegmentTracker(SegmentTrackerConfig{})
	for i := 0; i < 20; i++ {
		if i%2 == 0 {
			tr.Observe(10_000)
		} else {
			tr.Observe(90_000)
		}
	}
	s := tr.Snapshot()
	if s.VarianceMicros2 <= 0 {
		t.Fatalf("VarianceMicros2 = %f, want > 0 for an alternating RTT stream", s.VarianceMicros2)
	}
}

func TestSegmentTracker_Percentiles_TrackObservedRange(t *testing.T) {
	tr, _ := newTestSegmentTracker(SegmentTrackerConfig{})
	for i := 1; i <= 1000; i++ {
		tr.Observe(float64(i))
	}
	s := tr.Snapshot()
	if diff := math.Abs(s.P50Micros - 500.5); diff > 15 {
		t.Fatalf("P50Micros = %f, want ~500.5", s.P50Micros)
	}
	if diff := math.Abs(s.P95Micros - 950.05); diff > 25 {
		t.Fatalf("P95Micros = %f, want ~950.05", s.P95Micros)
	}
}

func TestSegmentTracker_Confidence_ZeroWhenNeverObserved(t *testing.T) {
	tr, _ := newTestSegmentTracker(SegmentTrackerConfig{})
	if got := tr.Snapshot().Confidence; got != 0 {
		t.Fatalf("Confidence = %f, want 0 with no samples at all", got)
	}
}

func TestSegmentTracker_Confidence_WorkedExample(t *testing.T) {
	tr, fc := newTestSegmentTracker(SegmentTrackerConfig{
		SampleHalfCount:   10,
		StalenessHalfLife: 10 * time.Second,
	})
	for i := 0; i < 10; i++ {
		tr.Observe(1000)
	}
	fc.advance(10 * time.Second)

	// N=10=SampleHalfCount -> sampleConf=0.5. Age=10s=StalenessHalfLife
	// -> freshConf=0.5. Combined: exactly 0.25.
	got := tr.Snapshot().Confidence
	if diff := math.Abs(got - 0.25); diff > 1e-9 {
		t.Fatalf("Confidence = %f, want exactly 0.25 (0.5 sample factor * 0.5 freshness factor)", got)
	}
}

func TestSegmentTracker_Confidence_MoreSamplesIncreasesConfidence(t *testing.T) {
	tr, _ := newTestSegmentTracker(SegmentTrackerConfig{SampleHalfCount: 20})
	tr.Observe(1000)
	first := tr.Snapshot().Confidence
	for i := 0; i < 100; i++ {
		tr.Observe(1000)
	}
	second := tr.Snapshot().Confidence
	if second <= first {
		t.Fatalf("Confidence did not increase with more samples: %f -> %f", first, second)
	}
}

func TestSegmentTracker_Confidence_DecaysWithAge(t *testing.T) {
	tr, fc := newTestSegmentTracker(SegmentTrackerConfig{StalenessHalfLife: 10 * time.Second})
	tr.Observe(1000) // N fixed from here on, sampleConf component stays constant

	atZero := tr.Snapshot().Confidence
	fc.advance(10 * time.Second)
	atOneHalfLife := tr.Snapshot().Confidence
	fc.advance(10 * time.Second)
	atTwoHalfLives := tr.Snapshot().Confidence

	// Since N never changes, sampleConf is the same constant at all three
	// readings, so consecutive ratios must equal exactly the freshness
	// half-life ratio (0.5), independent of what that constant is.
	if diff := math.Abs(atOneHalfLife/atZero - 0.5); diff > 1e-9 {
		t.Fatalf("Confidence ratio after 1 half-life = %f, want 0.5", atOneHalfLife/atZero)
	}
	if diff := math.Abs(atTwoHalfLives/atOneHalfLife - 0.5); diff > 1e-9 {
		t.Fatalf("Confidence ratio after a 2nd half-life = %f, want 0.5", atTwoHalfLives/atOneHalfLife)
	}
}

func TestSegmentTracker_ObserveLoss_RefreshesStaleness(t *testing.T) {
	tr, fc := newTestSegmentTracker(SegmentTrackerConfig{})
	tr.Observe(1000)
	fc.advance(5 * time.Second)
	tr.ObserveLoss()

	s := tr.Snapshot()
	if s.Age != 0 {
		t.Fatalf("Age = %v, want 0 immediately after ObserveLoss refreshed the staleness clock", s.Age)
	}
}

func TestSegmentTracker_Snapshot_AgeReflectsElapsedTime(t *testing.T) {
	tr, fc := newTestSegmentTracker(SegmentTrackerConfig{})
	tr.Observe(1000)
	fc.advance(7 * time.Second)

	if got := tr.Snapshot().Age; got != 7*time.Second {
		t.Fatalf("Age = %v, want 7s", got)
	}
}

func TestSegmentTracker_DefaultConfig_AppliedWhenZero(t *testing.T) {
	tr := NewSegmentTracker(SegmentTrackerConfig{})
	if tr.cfg.SampleHalfCount != DefaultSegmentTrackerConfig.SampleHalfCount {
		t.Fatalf("SampleHalfCount = %f, want default %f", tr.cfg.SampleHalfCount, DefaultSegmentTrackerConfig.SampleHalfCount)
	}
	if tr.cfg.StalenessHalfLife != DefaultSegmentTrackerConfig.StalenessHalfLife {
		t.Fatalf("StalenessHalfLife = %v, want default %v", tr.cfg.StalenessHalfLife, DefaultSegmentTrackerConfig.StalenessHalfLife)
	}
}

func TestSegmentTracker_ConcurrentObserve_NoRace(t *testing.T) {
	tr := NewSegmentTracker(SegmentTrackerConfig{})
	var wg sync.WaitGroup
	const goroutines = 20
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if j%5 == 0 {
					tr.ObserveLoss()
				} else {
					tr.Observe(float64(i*50 + j))
				}
			}
			tr.Snapshot()
		}(i)
	}
	wg.Wait()

	if n := tr.Snapshot().N; n != goroutines*50 {
		t.Fatalf("N = %d, want %d", n, goroutines*50)
	}
}
