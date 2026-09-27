package measurement

import (
	"math"
	"testing"
)

func TestSegmentCost_ZeroLossZeroTail(t *testing.T) {
	s := SegmentStats{P50Micros: 20_000, P95Micros: 20_000, LossRate: 0}
	got := SegmentCost(s, CostWeights{TailWeight: 1, LossWeight: 1000})
	if got != 20_000 {
		t.Fatalf("SegmentCost = %f, want exactly 20000 (P50 only, no tail spread, no loss)", got)
	}
}

func TestSegmentCost_TailPremiumAddsWeightedDifference(t *testing.T) {
	s := SegmentStats{P50Micros: 20_000, P95Micros: 50_000, LossRate: 0}
	w := CostWeights{TailWeight: 0.5, LossWeight: 1000}
	want := 20_000.0 + 0.5*(50_000.0-20_000.0)
	if got := SegmentCost(s, w); got != want {
		t.Fatalf("SegmentCost = %f, want %f (P50 + TailWeight*(P95-P50))", got, want)
	}
}

func TestSegmentCost_TailWeightZero_IgnoresP95(t *testing.T) {
	s := SegmentStats{P50Micros: 20_000, P95Micros: 500_000, LossRate: 0}
	got := SegmentCost(s, CostWeights{TailWeight: 0})
	if got != 20_000 {
		t.Fatalf("SegmentCost = %f, want 20000 (TailWeight=0 must fully ignore P95)", got)
	}
}

func TestSegmentCost_NegativeTailPremiumClampedToZero(t *testing.T) {
	// P95 < P50 can happen from P² estimator noise on a tiny sample;
	// must never subtract cost.
	s := SegmentStats{P50Micros: 20_000, P95Micros: 19_000, LossRate: 0}
	got := SegmentCost(s, CostWeights{TailWeight: 1})
	if got != 20_000 {
		t.Fatalf("SegmentCost = %f, want 20000 (negative tail premium must clamp to 0, not go negative)", got)
	}
}

func TestSegmentCost_ConvexLossPenalty_MatchesFormula(t *testing.T) {
	s := SegmentStats{P50Micros: 0, P95Micros: 0, LossRate: 0.1}
	w := CostWeights{LossWeight: 1000}
	want := -math.Log(1-0.1) * 1000
	if got := SegmentCost(s, w); math.Abs(got-want) > 1e-9 {
		t.Fatalf("SegmentCost = %f, want %f (-ln(1-loss)*LossWeight)", got, want)
	}
}

func TestSegmentCost_LossPenaltyIsConvex(t *testing.T) {
	w := CostWeights{LossWeight: 1}
	penalty := func(loss float64) float64 {
		return SegmentCost(SegmentStats{LossRate: loss}, w)
	}
	p10 := penalty(0.10)
	p20 := penalty(0.20)
	p40 := penalty(0.40)
	// Convexity: doubling the loss rate more than doubles the penalty.
	if p20 <= 2*p10 {
		t.Fatalf("penalty(0.20)=%f, want > 2*penalty(0.10)=%f (convex growth)", p20, 2*p10)
	}
	if p40 <= 2*p20 {
		t.Fatalf("penalty(0.40)=%f, want > 2*penalty(0.20)=%f (convex growth)", p40, 2*p20)
	}
}

func TestSegmentCost_LossOfOne_ReturnsInf(t *testing.T) {
	s := SegmentStats{LossRate: 1}
	if got := SegmentCost(s, CostWeights{LossWeight: 1}); !math.IsInf(got, 1) {
		t.Fatalf("SegmentCost with LossRate=1 = %f, want +Inf", got)
	}
}

func TestScorePath_SumsSegmentCosts(t *testing.T) {
	w := CostWeights{TailWeight: 0, LossWeight: 1000, LossGate: 0.5, MaxCapacityFraction: 1}
	c := PathCandidate{
		Segments: []SegmentStats{
			{P50Micros: 10_000},
			{P50Micros: 20_000},
		},
	}
	got := ScorePath(c, w)
	if got.Gate != GateNone {
		t.Fatalf("Gate = %v, want GateNone", got.Gate)
	}
	if got.Cost != 30_000 {
		t.Fatalf("Cost = %f, want 30000 (sum of segment costs)", got.Cost)
	}
}

func TestScorePath_GatesOnLoss(t *testing.T) {
	w := CostWeights{LossGate: 0.2, MaxCapacityFraction: 1}
	c := PathCandidate{
		Segments: []SegmentStats{
			{P50Micros: 1000, LossRate: 0.05},
			{P50Micros: 1000, LossRate: 0.25}, // over the gate
		},
	}
	got := ScorePath(c, w)
	if got.Gate != GateLoss {
		t.Fatalf("Gate = %v, want GateLoss", got.Gate)
	}
	if !math.IsInf(got.Cost, 1) {
		t.Fatalf("Cost = %f, want +Inf", got.Cost)
	}
	if got.GatedSegment != 1 {
		t.Fatalf("GatedSegment = %d, want 1", got.GatedSegment)
	}
}

func TestScorePath_GatesOnCapacity(t *testing.T) {
	w := CostWeights{LossGate: 1, MaxCapacityFraction: 0.9}
	c := PathCandidate{
		Segments:         []SegmentStats{{P50Micros: 1000}},
		CapacityFraction: 0.95,
	}
	got := ScorePath(c, w)
	if got.Gate != GateCapacity {
		t.Fatalf("Gate = %v, want GateCapacity", got.Gate)
	}
	if !math.IsInf(got.Cost, 1) {
		t.Fatalf("Cost = %f, want +Inf", got.Cost)
	}
	if got.GatedSegment != -1 {
		t.Fatalf("GatedSegment = %d, want -1 for a capacity gate", got.GatedSegment)
	}
}

func TestScorePath_CapacityCheckedBeforeSegments(t *testing.T) {
	// Even a path with zero segments (nothing to gate on loss) must
	// still be gated by capacity.
	w := CostWeights{MaxCapacityFraction: 0.9}
	c := PathCandidate{CapacityFraction: 0.99}
	got := ScorePath(c, w)
	if got.Gate != GateCapacity {
		t.Fatalf("Gate = %v, want GateCapacity even with no segments", got.Gate)
	}
}

func TestScorePath_EmptyPath_ZeroCost(t *testing.T) {
	w := CostWeights{MaxCapacityFraction: 0.9}
	got := ScorePath(PathCandidate{}, w)
	if got.Gate != GateNone || got.Cost != 0 {
		t.Fatalf("ScorePath(empty) = %+v, want Cost=0 Gate=None", got)
	}
}

func testCostWeights() CostWeights {
	return CostWeights{TailWeight: 1, LossWeight: 1000, LossGate: 0.3, MaxCapacityFraction: 0.9}
}

func TestPathDifferential_CancelsSharedSuffix_ExactAlgebraicMatch(t *testing.T) {
	w := testCostWeights()
	shared := SegmentStats{P50Micros: 40_000, P95Micros: 90_000, LossRate: 0.02}

	a := PathCandidate{
		EgressID: "hk",
		Segments: []SegmentStats{
			{P50Micros: 5_000, P95Micros: 8_000, LossRate: 0.001},
			shared,
		},
	}
	b := PathCandidate{
		EgressID: "hk",
		Segments: []SegmentStats{
			{P50Micros: 12_000, P95Micros: 30_000, LossRate: 0.01},
			shared,
		},
	}

	diff, err := PathDifferential(a, b, 1, w)
	if err != nil {
		t.Fatalf("PathDifferential: %v", err)
	}

	fullA := ScorePath(a, w)
	fullB := ScorePath(b, w)
	wantDiff := fullA.Cost - fullB.Cost

	if math.Abs(diff-wantDiff) > 1e-6 {
		t.Fatalf("PathDifferential = %f, want %f (must exactly equal the full-cost difference when the suffix is truly shared)", diff, wantDiff)
	}
}

func TestPathDifferential_IgnoresSuffixContentEntirely(t *testing.T) {
	w := testCostWeights()
	prefixA := SegmentStats{P50Micros: 5_000}
	prefixB := SegmentStats{P50Micros: 12_000}

	a := PathCandidate{EgressID: "hk", Segments: []SegmentStats{prefixA, {P50Micros: 1_000_000, LossRate: 0.001}}}
	b := PathCandidate{EgressID: "hk", Segments: []SegmentStats{prefixB, {P50Micros: 2_000_000, LossRate: 0.002}}}

	diff, err := PathDifferential(a, b, 1, w)
	if err != nil {
		t.Fatalf("PathDifferential: %v", err)
	}
	want := SegmentCost(prefixA, w) - SegmentCost(prefixB, w)
	if math.Abs(diff-want) > 1e-6 {
		t.Fatalf("PathDifferential = %f, want %f (must depend only on the differing prefix)", diff, want)
	}
}

func TestPathDifferential_DifferentEgressID_Errors(t *testing.T) {
	w := testCostWeights()
	a := PathCandidate{EgressID: "hk", Segments: []SegmentStats{{}}}
	b := PathCandidate{EgressID: "sg", Segments: []SegmentStats{{}}}
	if _, err := PathDifferential(a, b, 0, w); err == nil {
		t.Fatal("PathDifferential with different EgressID: expected an error")
	}
}

func TestPathDifferential_SharedSuffixLenInvalid_Errors(t *testing.T) {
	w := testCostWeights()
	a := PathCandidate{EgressID: "hk", Segments: []SegmentStats{{}, {}}}
	b := PathCandidate{EgressID: "hk", Segments: []SegmentStats{{}}}

	if _, err := PathDifferential(a, b, -1, w); err == nil {
		t.Fatal("PathDifferential with sharedSuffixLen=-1: expected an error")
	}
	if _, err := PathDifferential(a, b, 2, w); err == nil {
		t.Fatal("PathDifferential with sharedSuffixLen exceeding b's segment count: expected an error")
	}
}

func TestPathDifferential_SharedSuffixGated_Errors(t *testing.T) {
	w := testCostWeights()
	gatedShared := SegmentStats{LossRate: 0.5} // >= LossGate 0.3
	a := PathCandidate{EgressID: "hk", Segments: []SegmentStats{{P50Micros: 1000}, gatedShared}}
	b := PathCandidate{EgressID: "hk", Segments: []SegmentStats{{P50Micros: 2000}, gatedShared}}

	if _, err := PathDifferential(a, b, 1, w); err == nil {
		t.Fatal("PathDifferential with a gated shared suffix: expected an error, not a cancelled-away result")
	}
}

func TestPathDifferential_SharedCapacityGated_Errors(t *testing.T) {
	w := testCostWeights()
	a := PathCandidate{EgressID: "hk", Segments: []SegmentStats{{}}, CapacityFraction: 0.95}
	b := PathCandidate{EgressID: "hk", Segments: []SegmentStats{{}}, CapacityFraction: 0.95}
	if _, err := PathDifferential(a, b, 0, w); err == nil {
		t.Fatal("PathDifferential with the shared egress over capacity: expected an error")
	}
}

func TestPathDifferential_DifferingSegmentGated_ReturnsInf(t *testing.T) {
	w := testCostWeights()
	shared := SegmentStats{P50Micros: 10_000, LossRate: 0.01}
	a := PathCandidate{EgressID: "hk", Segments: []SegmentStats{{LossRate: 0.9}, shared}} // a's own leg is gated
	b := PathCandidate{EgressID: "hk", Segments: []SegmentStats{{P50Micros: 1000}, shared}}

	diff, err := PathDifferential(a, b, 1, w)
	if err != nil {
		t.Fatalf("PathDifferential: %v", err)
	}
	if !math.IsInf(diff, 1) {
		t.Fatalf("diff = %f, want +Inf (a's own differing segment is gated, so a costs infinitely more)", diff)
	}
}

func TestPathDifferential_BothDifferingGated_NaN(t *testing.T) {
	w := testCostWeights()
	shared := SegmentStats{P50Micros: 10_000}
	a := PathCandidate{EgressID: "hk", Segments: []SegmentStats{{LossRate: 0.9}, shared}}
	b := PathCandidate{EgressID: "hk", Segments: []SegmentStats{{LossRate: 0.95}, shared}}

	diff, err := PathDifferential(a, b, 1, w)
	if err != nil {
		t.Fatalf("PathDifferential: %v", err)
	}
	if !math.IsNaN(diff) {
		t.Fatalf("diff = %f, want NaN when both differing segments are gated", diff)
	}
}

func TestPathDifferential_ZeroSharedSuffixLen_EqualsFullCostDifference(t *testing.T) {
	w := testCostWeights()
	a := PathCandidate{EgressID: "hk", Segments: []SegmentStats{{P50Micros: 5_000}, {P50Micros: 8_000}}}
	b := PathCandidate{EgressID: "hk", Segments: []SegmentStats{{P50Micros: 6_000}}}

	diff, err := PathDifferential(a, b, 0, w)
	if err != nil {
		t.Fatalf("PathDifferential: %v", err)
	}
	want := ScorePath(a, w).Cost - ScorePath(b, w).Cost
	if math.Abs(diff-want) > 1e-9 {
		t.Fatalf("diff = %f, want %f (sharedSuffixLen=0 must equal the plain full-cost difference)", diff, want)
	}
}

func TestGateReason_String(t *testing.T) {
	cases := map[GateReason]string{GateNone: "none", GateLoss: "loss", GateCapacity: "capacity"}
	for reason, want := range cases {
		if got := reason.String(); got != want {
			t.Fatalf("%v.String() = %q, want %q", reason, got, want)
		}
	}
}
