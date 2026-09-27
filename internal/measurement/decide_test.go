package measurement

import (
	"math"
	"testing"
)

func decideTestCostWeights() CostWeights {
	return CostWeights{TailWeight: 1, LossWeight: 1000, LossGate: 0.5, MaxCapacityFraction: 0.9}
}

func TestSegmentCostBound_NoSamples_InfiniteInterval(t *testing.T) {
	w := decideTestCostWeights()
	cases := []SegmentStats{
		{P50Micros: 1000, N: 0, Confidence: 1},
		{P50Micros: 1000, N: 100, Confidence: 0},
	}
	for _, s := range cases {
		_, lower, upper := segmentCostBound(s, w, 1.645)
		if !math.IsInf(lower, -1) || !math.IsInf(upper, 1) {
			t.Fatalf("segmentCostBound(%+v) = (_, %f, %f), want (-Inf, +Inf)", s, lower, upper)
		}
	}
}

func TestSegmentCostBound_NarrowsWithMoreSamples(t *testing.T) {
	w := decideTestCostWeights()
	base := SegmentStats{P50Micros: 50_000, P95Micros: 60_000, LossRate: 0.02, VarianceMicros2: 4_000_000, Confidence: 1}

	small := base
	small.N = 5
	_, lowerSmall, upperSmall := segmentCostBound(small, w, 1.645)

	big := base
	big.N = 5000
	_, lowerBig, upperBig := segmentCostBound(big, w, 1.645)

	if (upperSmall - lowerSmall) <= (upperBig - lowerBig) {
		t.Fatalf("interval width with N=5 (%f) must be wider than with N=5000 (%f)", upperSmall-lowerSmall, upperBig-lowerBig)
	}
}

func TestSegmentCostBound_WidensWithLowerConfidence(t *testing.T) {
	w := decideTestCostWeights()
	base := SegmentStats{P50Micros: 50_000, P95Micros: 60_000, LossRate: 0.02, VarianceMicros2: 4_000_000, N: 100}

	high := base
	high.Confidence = 1
	_, lowerHigh, upperHigh := segmentCostBound(high, w, 1.645)

	low := base
	low.Confidence = 0.1
	_, lowerLow, upperLow := segmentCostBound(low, w, 1.645)

	if (upperLow - lowerLow) <= (upperHigh - lowerHigh) {
		t.Fatalf("interval width at Confidence=0.1 (%f) must be wider than at Confidence=1 (%f)", upperLow-lowerLow, upperHigh-lowerHigh)
	}
}

func TestSegmentCostBound_ZeroVarianceZeroLoss_TightInterval(t *testing.T) {
	w := decideTestCostWeights()
	s := SegmentStats{P50Micros: 30_000, P95Micros: 30_000, LossRate: 0, VarianceMicros2: 0, N: 100, Confidence: 1}
	point, lower, upper := segmentCostBound(s, w, 1.645)
	if lower != point || upper != point {
		t.Fatalf("segmentCostBound with zero variance and zero loss = (%f, %f, %f), want lower=upper=point", point, lower, upper)
	}
}

func TestSegmentCostBound_LossBoundIsAsymmetric(t *testing.T) {
	// The convex loss penalty makes the upper-side spread (from pHigh)
	// larger than the lower-side spread (from pLow) for the same
	// absolute delta in loss rate.
	w := CostWeights{LossWeight: 1000}
	s := SegmentStats{LossRate: 0.3, VarianceMicros2: 0, N: 50, Confidence: 1}
	point, lower, upper := segmentCostBound(s, w, 1.645)
	if (upper - point) <= (point - lower) {
		t.Fatalf("upper spread (%f) must exceed lower spread (%f) for a convex loss penalty", upper-point, point-lower)
	}
}

func TestAggregateBounds_SumsPointsAndCombinesRSS(t *testing.T) {
	w := CostWeights{TailWeight: 0, LossWeight: 0}
	s := SegmentStats{P50Micros: 10_000, VarianceMicros2: 900, N: 9, Confidence: 1}
	z := 1.645
	segSE := math.Sqrt(900.0 / 9.0) // = 10
	segSpread := z * segSE

	point, lower, upper := aggregateBounds([]SegmentStats{s, s}, w, z)
	if point != 20_000 {
		t.Fatalf("point = %f, want 20000 (sum of point estimates)", point)
	}
	wantSpread := math.Sqrt(segSpread*segSpread + segSpread*segSpread) // RSS of 2 equal spreads
	if diff := (upper - point) - wantSpread; math.Abs(diff) > 1e-6 {
		t.Fatalf("upper spread = %f, want %f (root-sum-of-squares of the two segments' spreads)", upper-point, wantSpread)
	}
	if diff := (point - lower) - wantSpread; math.Abs(diff) > 1e-6 {
		t.Fatalf("lower spread = %f, want %f", point-lower, wantSpread)
	}
}

func TestAggregateBounds_AnyUntrustedSegmentMakesWholeIntervalInfinite(t *testing.T) {
	w := decideTestCostWeights()
	good := SegmentStats{P50Micros: 1000, VarianceMicros2: 10, N: 100, Confidence: 1}
	unmeasured := SegmentStats{P50Micros: 1000, N: 0, Confidence: 0}

	_, lower, upper := aggregateBounds([]SegmentStats{good, unmeasured}, w, 1.645)
	if !math.IsInf(lower, -1) || !math.IsInf(upper, 1) {
		t.Fatalf("aggregateBounds with one unmeasured segment = (%f, %f), want (-Inf, +Inf)", lower, upper)
	}
}

func wellMeasured(p50 float64) SegmentStats {
	return SegmentStats{
		P50Micros:       p50,
		P95Micros:       p50 * 1.2,
		LossRate:        0.01,
		VarianceMicros2: 4_000_000,
		N:               2000,
		Confidence:      0.99,
	}
}

func noisyBut(p50 float64) SegmentStats {
	return SegmentStats{
		P50Micros:       p50,
		P95Micros:       p50 * 1.2,
		LossRate:        0.01,
		VarianceMicros2: 900_000_000,
		N:               3,
		Confidence:      0.05,
	}
}

func TestDecideMigration_ClearWin_Migrates(t *testing.T) {
	cw := decideTestCostWeights()
	dw := DecisionWeights{Z: 1.645, MigrationCost: 1000, SafetyMargin: 500}

	current := PathCandidate{EgressID: "hk", Segments: []SegmentStats{wellMeasured(60_000)}}
	candidate := PathCandidate{EgressID: "hk", Segments: []SegmentStats{wellMeasured(20_000)}}

	decision, err := DecideMigration(current, candidate, 0, cw, dw)
	if err != nil {
		t.Fatalf("DecideMigration: %v", err)
	}
	if !decision.Migrate {
		t.Fatalf("decision = %+v, want Migrate=true for a large, well-measured improvement", decision)
	}
}

func TestDecideMigration_NoisyCandidate_DoesNotMigrate(t *testing.T) {
	cw := decideTestCostWeights()
	dw := DecisionWeights{Z: 1.645}

	current := PathCandidate{EgressID: "hk", Segments: []SegmentStats{wellMeasured(50_000)}}
	candidate := PathCandidate{EgressID: "hk", Segments: []SegmentStats{noisyBut(48_000)}}

	naivePoint := ScorePath(current, cw).Cost - ScorePath(candidate, cw).Cost
	if naivePoint <= 0 {
		t.Fatalf("test setup invalid: candidate's point estimate (%f) must look better than current's for this test to be meaningful", naivePoint)
	}

	decision, err := DecideMigration(current, candidate, 0, cw, dw)
	if err != nil {
		t.Fatalf("DecideMigration: %v", err)
	}
	if decision.Migrate {
		t.Fatalf("decision = %+v (naive point comparison = %f): a noisy, low-confidence candidate must not trigger migration just because its point estimate looks better", decision, naivePoint)
	}
	if decision.Delta.Lower > decision.Threshold {
		t.Fatalf("Delta.Lower (%f) unexpectedly clears the threshold (%f)", decision.Delta.Lower, decision.Threshold)
	}
}

func TestDecideMigration_MigrationCostRequiresBiggerGap(t *testing.T) {
	cw := decideTestCostWeights()
	current := PathCandidate{EgressID: "hk", Segments: []SegmentStats{wellMeasured(60_000)}}
	candidate := PathCandidate{EgressID: "hk", Segments: []SegmentStats{wellMeasured(55_000)}}

	cheap, err := DecideMigration(current, candidate, 0, cw, DecisionWeights{Z: 1.645, MigrationCost: 0, SafetyMargin: 0})
	if err != nil {
		t.Fatalf("DecideMigration: %v", err)
	}
	if !cheap.Migrate {
		t.Fatalf("with zero migration cost, a proven (if small) improvement should migrate: %+v", cheap)
	}

	expensive, err := DecideMigration(current, candidate, 0, cw, DecisionWeights{Z: 1.645, MigrationCost: 1_000_000, SafetyMargin: 0})
	if err != nil {
		t.Fatalf("DecideMigration: %v", err)
	}
	if expensive.Migrate {
		t.Fatalf("with a huge migration cost, the same small improvement should not be worth migrating: %+v", expensive)
	}
}

func TestDecideMigration_BothSidesGated_NoMigrate(t *testing.T) {
	cw := decideTestCostWeights()
	dw := DefaultDecisionWeights
	current := PathCandidate{EgressID: "hk", Segments: []SegmentStats{{LossRate: 0.9, N: 100, Confidence: 1}}}
	candidate := PathCandidate{EgressID: "hk", Segments: []SegmentStats{{LossRate: 0.95, N: 100, Confidence: 1}}}

	decision, err := DecideMigration(current, candidate, 0, cw, dw)
	if err != nil {
		t.Fatalf("DecideMigration: %v", err)
	}
	if !math.IsNaN(decision.Delta.Lower) {
		t.Fatalf("Delta.Lower = %f, want NaN when both sides are gated", decision.Delta.Lower)
	}
	if decision.Migrate {
		t.Fatal("Migrate must be false when the comparison is NaN")
	}
}

func TestDecideMigration_SharedSuffixGated_Errors(t *testing.T) {
	cw := decideTestCostWeights()
	gatedShared := SegmentStats{LossRate: 0.9, N: 10, Confidence: 1}
	current := PathCandidate{EgressID: "hk", Segments: []SegmentStats{wellMeasured(1000), gatedShared}}
	candidate := PathCandidate{EgressID: "hk", Segments: []SegmentStats{wellMeasured(2000), gatedShared}}

	if _, err := DecideMigration(current, candidate, 1, cw, DefaultDecisionWeights); err == nil {
		t.Fatal("DecideMigration with a gated shared suffix: expected an error")
	}
}

func TestDecideMigration_EqualCandidates_NoMigrate(t *testing.T) {
	cw := decideTestCostWeights()
	seg := wellMeasured(50_000)
	current := PathCandidate{EgressID: "hk", Segments: []SegmentStats{seg}}
	candidate := PathCandidate{EgressID: "hk", Segments: []SegmentStats{seg}}

	decision, err := DecideMigration(current, candidate, 0, cw, DefaultDecisionWeights)
	if err != nil {
		t.Fatalf("DecideMigration: %v", err)
	}
	if decision.Delta.Point != 0 {
		t.Fatalf("Delta.Point = %f, want exactly 0 for identical candidates", decision.Delta.Point)
	}
	if decision.Migrate {
		t.Fatal("identical candidates must never trigger a migration")
	}
}

func TestDecideMigration_UnmeasuredCandidate_NeverMigrates(t *testing.T) {
	cw := decideTestCostWeights()
	current := PathCandidate{EgressID: "hk", Segments: []SegmentStats{wellMeasured(80_000)}}
	candidate := PathCandidate{EgressID: "hk", Segments: []SegmentStats{{P50Micros: 1000, N: 0, Confidence: 0}}}

	decision, err := DecideMigration(current, candidate, 0, cw, DefaultDecisionWeights)
	if err != nil {
		t.Fatalf("DecideMigration: %v", err)
	}
	if !math.IsInf(decision.Delta.Lower, -1) {
		t.Fatalf("Delta.Lower = %f, want -Inf for a completely unmeasured candidate", decision.Delta.Lower)
	}
	if decision.Migrate {
		t.Fatal("an unmeasured candidate, however tempting its raw point estimate, must never trigger a migration")
	}
}

func TestClamp01(t *testing.T) {
	cases := []struct{ in, want float64 }{{-1, 0}, {0, 0}, {0.5, 0.5}, {1, 1}, {2, 1}}
	for _, c := range cases {
		if got := clamp01(c.in); got != c.want {
			t.Fatalf("clamp01(%f) = %f, want %f", c.in, got, c.want)
		}
	}
}
