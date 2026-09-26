package measurement

import (
	"math"
	"math/rand"
	"sort"
	"testing"
)

func TestP2Quantile_Empty(t *testing.T) {
	q := newP2Quantile(0.5)
	if got := q.Value(); got != 0 {
		t.Fatalf("Value() on an empty estimator = %f, want 0", got)
	}
}

func TestP2Quantile_FewerThanFiveSamples_ExactInterpolation(t *testing.T) {
	q := newP2Quantile(0.5)
	// 3 samples: 10, 20, 30 (fed out of order). Median of 3 values is
	// the middle one, 20 exactly representable by the fallback path.
	for _, v := range []float64{30, 10, 20} {
		q.Observe(v)
	}
	if got := q.Value(); got != 20 {
		t.Fatalf("Value() with 3 samples = %f, want 20 (exact median, pre-P² fallback)", got)
	}
}

func TestP2Quantile_SortedStream_ApproximatesTruePercentiles(t *testing.T) {
	const n = 1000
	p50 := newP2Quantile(0.5)
	p95 := newP2Quantile(0.95)
	for i := 1; i <= n; i++ {
		p50.Observe(float64(i))
		p95.Observe(float64(i))
	}

	// True median of 1..1000 is 500.5, true P95 is 950.05.
	if diff := math.Abs(p50.Value() - 500.5); diff > 15 {
		t.Fatalf("P50 estimate = %f, want ~500.5 (within 15)", p50.Value())
	}
	if diff := math.Abs(p95.Value() - 950.05); diff > 25 {
		t.Fatalf("P95 estimate = %f, want ~950.05 (within 25)", p95.Value())
	}
}

func TestP2Quantile_ShuffledStream_ApproximatesTruePercentiles(t *testing.T) {
	const n = 2000
	values := make([]float64, n)
	for i := range values {
		values[i] = float64(i + 1)
	}
	rnd := rand.New(rand.NewSource(42))
	rnd.Shuffle(n, func(i, j int) { values[i], values[j] = values[j], values[i] })

	p50 := newP2Quantile(0.5)
	p95 := newP2Quantile(0.95)
	for _, v := range values {
		p50.Observe(v)
		p95.Observe(v)
	}

	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	trueP50 := sorted[n/2]
	trueP95 := sorted[int(0.95*float64(n))]

	if diff := math.Abs(p50.Value() - trueP50); diff > float64(n)*0.02 {
		t.Fatalf("P50 estimate = %f, true = %f, diff too large", p50.Value(), trueP50)
	}
	if diff := math.Abs(p95.Value() - trueP95); diff > float64(n)*0.03 {
		t.Fatalf("P95 estimate = %f, true = %f, diff too large", p95.Value(), trueP95)
	}
}

func TestP2Quantile_ConstantStream(t *testing.T) {
	q := newP2Quantile(0.5)
	for i := 0; i < 50; i++ {
		q.Observe(42)
	}
	if got := q.Value(); got != 42 {
		t.Fatalf("Value() for a constant stream = %f, want 42", got)
	}
}

func TestP2Quantile_MarkersStayMonotonic(t *testing.T) {
	rnd := rand.New(rand.NewSource(7))
	q := newP2Quantile(0.5)
	for i := 0; i < 5000; i++ {
		q.Observe(rnd.NormFloat64() * 100)
		if len(q.initBuf) == 0 { // only once fully seeded
			for j := 1; j < 5; j++ {
				if q.heights[j] < q.heights[j-1] {
					t.Fatalf("marker heights not monotonic after %d observations: %v", i+1, q.heights)
				}
			}
		}
	}
}
