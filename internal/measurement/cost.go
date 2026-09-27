package measurement

import (
	"fmt"
	"math"
)

// CostWeights configures the cost function used to compare path quality.
type CostWeights struct {
	// TailWeight controls how strongly the P95-P50 latency spread affects cost.
	TailWeight float64

	// LossWeight scales the loss penalty relative to latency, in microseconds.
	LossWeight float64

	// LossGate is the maximum allowed loss rate for a segment.
	// A segment with loss >= LossGate causes the candidate to be gated.
	LossGate float64

	// MaxCapacityFraction is the maximum allowed egress capacity usage.
	// A candidate with capacity >= this value is gated.
	MaxCapacityFraction float64
}

var DefaultCostWeights = CostWeights{
	TailWeight:          1,
	LossWeight:          995_033,
	LossGate:            0.20,
	MaxCapacityFraction: 0.90,
}

// SegmentCost computes the cost contribution of one segment.
//
// Latency is calculated as P50 plus a weighted P95-P50 tail premium.
// Loss is converted to an additive penalty using -ln(1-loss).
//
// SegmentCost does not apply loss or capacity gates. Callers that need
// gating should use ScorePath or PathDifferential.
func SegmentCost(s SegmentStats, w CostWeights) float64 {
	tailPremium := s.P95Micros - s.P50Micros
	if tailPremium < 0 {
		// Keep the tail premium non-negative if the two quantile estimates
		// temporarily violate their expected ordering.
		tailPremium = 0
	}
	latency := s.P50Micros + w.TailWeight*tailPremium

	if s.LossRate >= 1 {
		return math.Inf(1)
	}
	lossPenalty := -math.Log(1-s.LossRate) * w.LossWeight

	return latency + lossPenalty
}

type GateReason int

const (
	GateNone GateReason = iota
	GateLoss
	GateCapacity
)

func (r GateReason) String() string {
	switch r {
	case GateNone:
		return "none"
	case GateLoss:
		return "loss"
	case GateCapacity:
		return "capacity"
	default:
		return "unknown"
	}
}

// PathCandidate describes a route as an ordered sequence of measured
// segments together with the current egress capacity usage.
type PathCandidate struct {
	EgressID string
	Segments []SegmentStats
	// CapacityFraction is how loaded EgressID currently is, 0..1.
	CapacityFraction float64
}

// PathScore contains the result of scoring a path.
type PathScore struct {
	// Cost is the total path cost. It is +Inf when the path is gated.
	Cost float64

	// Gate identifies the reason the path was gated.
	Gate GateReason

	// GatedSegment is the index of the segment that triggered a loss gate,
	// or -1 when the path was not gated by a segment.
	GatedSegment int
}

// ScorePath computes the total cost of a candidate path.
// Capacity is checked before individual segments. A capacity gate applies
// to the entire candidate, while a loss gate applies to the segment that
// exceeds LossGate.
func ScorePath(c PathCandidate, w CostWeights) PathScore {
	if c.CapacityFraction >= w.MaxCapacityFraction {
		return PathScore{Cost: math.Inf(1), Gate: GateCapacity, GatedSegment: -1}
	}
	total := 0.0
	for i, seg := range c.Segments {
		if seg.LossRate >= w.LossGate {
			return PathScore{Cost: math.Inf(1), Gate: GateLoss, GatedSegment: i}
		}
		total += SegmentCost(seg, w)
	}
	return PathScore{Cost: total, Gate: GateNone, GatedSegment: -1}
}

// PathDifferential computes the cost difference between two candidates that
// use the same egress and share the final sharedSuffixLen segments.
//
// Only the differing prefixes are included in the returned difference.
// Because SegmentCost is additive, the shared suffix cancels exactly.
//
// The shared suffix is validated for loss and the egress capacity is checked
// before computing the differential. A gate in one candidate's differing
// prefix contributes +Inf rather than returning an error.
//
// The caller must ensure that the specified suffix is semantically shared
// by both candidates; this function only validates its structural bounds.
func PathDifferential(a, b PathCandidate, sharedSuffixLen int, w CostWeights) (float64, error) {
	if a.EgressID != b.EgressID {
		return 0, fmt.Errorf("measurement: PathDifferential requires the same egress, got %q and %q", a.EgressID, b.EgressID)
	}
	if sharedSuffixLen < 0 {
		return 0, fmt.Errorf("measurement: sharedSuffixLen must be >= 0, got %d", sharedSuffixLen)
	}
	if sharedSuffixLen > len(a.Segments) || sharedSuffixLen > len(b.Segments) {
		return 0, fmt.Errorf("measurement: sharedSuffixLen %d exceeds a candidate's segment count (a has %d, b has %d)", sharedSuffixLen, len(a.Segments), len(b.Segments))
	}

	if sharedSuffixLen > 0 {
		for _, seg := range a.Segments[len(a.Segments)-sharedSuffixLen:] {
			if seg.LossRate >= w.LossGate {
				return 0, fmt.Errorf("measurement: PathDifferential: shared suffix is gated (loss %.4f >= %.4f) -- this egress cannot serve this destination, not a differential decision", seg.LossRate, w.LossGate)
			}
		}
	}
	if a.CapacityFraction >= w.MaxCapacityFraction || b.CapacityFraction >= w.MaxCapacityFraction {
		return 0, fmt.Errorf("measurement: PathDifferential: the shared egress is at/over capacity -- this egress cannot serve this destination, not a differential decision")
	}

	diffA := differingCost(a.Segments, sharedSuffixLen, w)
	diffB := differingCost(b.Segments, sharedSuffixLen, w)
	return diffA - diffB, nil
}

// differingCost returns the cost of the non-shared prefix.
// A loss-gated segment makes the prefix cost +Inf.
func differingCost(segs []SegmentStats, sharedSuffixLen int, w CostWeights) float64 {
	differing := segs[:len(segs)-sharedSuffixLen]
	total := 0.0
	for _, seg := range differing {
		if seg.LossRate >= w.LossGate {
			return math.Inf(1)
		}
		total += SegmentCost(seg, w)
	}
	return total
}
