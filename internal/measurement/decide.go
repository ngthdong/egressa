package measurement

import "math"

// DeltaEstimate contains a point estimate and confidence bounds for the
// cost difference between two paths.
//
// The differential is defined as:
//
//	Δ = Cost(current) - Cost(candidate)
//
// A positive value means the candidate has lower estimated cost.
type DeltaEstimate struct {
	Point float64
	Lower float64
	Upper float64
}

// DecisionWeights configures DecideMigration on top of a CostWeights.
type DecisionWeights struct {
	// Z is the confidence-bound multiplier.
	// Larger values produce wider bounds and require stronger evidence.
	Z float64

	// MigrationCost is the minimum cost that must be recovered to justify
	// switching paths.
	MigrationCost float64

	// SafetyMargin is an additional margin required beyond MigrationCost.
	SafetyMargin float64
}

var DefaultDecisionWeights = DecisionWeights{Z: 1.645}

// MigrationDecision contains the result of a migration decision.
type MigrationDecision struct {
	// Migrate reports whether the candidate meets the decision threshold.
	Migrate bool

	// Delta contains the estimated cost differential used for the decision.
	Delta DeltaEstimate

	// Threshold is the minimum required lower-bound improvement.
	Threshold float64
}

// DecideMigration determines whether the candidate has sufficient evidence
// of improvement over the current path to justify migration.
//
// Migration occurs only when the lower confidence bound of
// Cost(current) - Cost(candidate) exceeds MigrationCost + SafetyMargin.
// This prevents a migration based solely on a noisy point estimate.
func DecideMigration(current, candidate PathCandidate, sharedSuffixLen int, cw CostWeights, dw DecisionWeights) (MigrationDecision, error) {
	differingA, differingB, err := validateDifferential(current, candidate, sharedSuffixLen, cw)
	if err != nil {
		return MigrationDecision{}, err
	}

	pointA, lowerA, upperA := aggregateBounds(differingA, cw, dw.Z)
	pointB, lowerB, upperB := aggregateBounds(differingB, cw, dw.Z)
	if segmentsGated(differingA, cw) {
		pointA, lowerA, upperA = math.Inf(1), math.Inf(1), math.Inf(1)
	}
	if segmentsGated(differingB, cw) {
		pointB, lowerB, upperB = math.Inf(1), math.Inf(1), math.Inf(1)
	}

	delta := DeltaEstimate{
		Point: pointA - pointB,
		Lower: lowerA - upperB,
		Upper: upperA - lowerB,
	}
	threshold := dw.MigrationCost + dw.SafetyMargin

	return MigrationDecision{
		Migrate:   delta.Lower > threshold,
		Delta:     delta,
		Threshold: threshold,
	}, nil
}

// clamp01 clamps x into [0, 1].
func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

// segmentCostBound computes the cost estimate for a segment together with
// lower and upper confidence bounds.
//
// A segment without usable observations returns an unbounded interval,
// preventing an unmeasured segment from supporting a migration decision.
//
// Latency uncertainty is estimated from the observed RTT variance.
// Loss uncertainty uses a proportion confidence interval and is transformed
// through the same loss penalty used by SegmentCost.
//
// Confidence widens both bounds: stale or low-confidence measurements are
// treated as less reliable even when their sample count is sufficient.
func segmentCostBound(s SegmentStats, w CostWeights, z float64) (point, lower, upper float64) {
	point = SegmentCost(s, w)
	if s.N == 0 || s.Confidence <= 0 {
		return point, math.Inf(-1), math.Inf(1)
	}

	tailPremium := s.P95Micros - s.P50Micros
	if tailPremium < 0 {
		tailPremium = 0
	}
	latencyPoint := s.P50Micros + w.TailWeight*tailPremium

	confidenceInflation := math.Sqrt(s.Confidence)
	se := math.Sqrt(s.VarianceMicros2/float64(s.N)) / confidenceInflation
	latencySpread := z * se * (1 + w.TailWeight)

	p := clamp01(s.LossRate)
	lossSE := math.Sqrt(p*(1-p)/float64(s.N)) / confidenceInflation
	pLow := clamp01(p - z*lossSE)
	pHigh := clamp01(p + z*lossSE)

	lower = (latencyPoint - latencySpread) + lossPenalty(pLow, w.LossWeight)
	upper = (latencyPoint + latencySpread) + lossPenalty(pHigh, w.LossWeight)

	if lower > point {
		lower = point
	}
	if upper < point {
		upper = point
	}
	return point, lower, upper
}

// aggregateBounds combines segment-level cost estimates into bounds for the
// complete path.
//
// Point estimates are summed directly. Lower and upper spreads are combined
// independently using root-sum-of-squares. If any segment has an unbounded
// interval, the aggregate interval is also unbounded.
func aggregateBounds(segs []SegmentStats, w CostWeights, z float64) (point, lower, upper float64) {
	var upperSpreadSq, lowerSpreadSq float64
	untrusted := false
	for _, s := range segs {
		p, l, u := segmentCostBound(s, w, z)
		point += p
		if math.IsInf(l, -1) || math.IsInf(u, 1) {
			untrusted = true
			continue
		}
		upperSpreadSq += (u - p) * (u - p)
		lowerSpreadSq += (p - l) * (p - l)
	}
	if untrusted {
		return point, math.Inf(-1), math.Inf(1)
	}
	return point, point - math.Sqrt(lowerSpreadSq), point + math.Sqrt(upperSpreadSq)
}
