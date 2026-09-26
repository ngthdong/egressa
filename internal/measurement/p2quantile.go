package measurement

import "sort"

// p2Quantile estimates a single streaming quantile using the P² algorithm.
//
// It maintains five markers and uses O(1) memory regardless of the number
// of observations. The estimate is updated incrementally without retaining
// the full sample history.
//
// P² has no decay, so the estimate reflects the cumulative history of the
// stream. It is not safe for concurrent use.
type p2Quantile struct {
	p       float64
	n       [5]float64 // marker positions
	npos    [5]float64 // desired marker positions
	dn      [5]float64 // increment to npos per observation
	heights [5]float64 // marker values
	initBuf []float64  // samples used to initialize the markers
	count   int
}

func newP2Quantile(p float64) *p2Quantile {
	return &p2Quantile{
		p:  p,
		dn: [5]float64{0, p / 2, p, (1 + p) / 2, 1},
	}
}

// Observe folds one more observation into the estimate.
func (q *p2Quantile) Observe(x float64) {
	q.count++

	if len(q.initBuf) < 5 {
		q.initBuf = append(q.initBuf, x)
		if len(q.initBuf) == 5 {
			sort.Float64s(q.initBuf)
			for i := 0; i < 5; i++ {
				q.heights[i] = q.initBuf[i]
				q.n[i] = float64(i + 1)
			}
			q.npos = [5]float64{1, 1 + 2*q.p, 1 + 4*q.p, 3 + 2*q.p, 5}
		}
		return
	}

	k := q.cell(x)
	for i := k + 1; i < 5; i++ {
		q.n[i]++
	}
	for i := 0; i < 5; i++ {
		q.npos[i] += q.dn[i]
	}
	for i := 1; i < 4; i++ {
		q.maybeAdjust(i)
	}
}

// cell finds which of the 4 intervals x falls into (0..3), extending the
// outer markers first if x lies outside the currently known range.
func (q *p2Quantile) cell(x float64) int {
	switch {
	case x < q.heights[0]:
		q.heights[0] = x
		return 0
	case x >= q.heights[4]:
		q.heights[4] = x
		return 3
	default:
		for i := 0; i < 4; i++ {
			if x < q.heights[i+1] {
				return i
			}
		}
		return 3
	}
}

// maybeAdjust nudges interior marker i (1..3) one step toward its
// desired position when it has drifted too far, per the P² paper's
// adjustment rule.
func (q *p2Quantile) maybeAdjust(i int) {
	diff := q.npos[i] - q.n[i]
	if diff >= 1 && q.n[i+1]-q.n[i] > 1 {
		q.move(i, 1)
	} else if diff <= -1 && q.n[i-1]-q.n[i] < -1 {
		q.move(i, -1)
	}
}

// move adjusts marker i's height and position by d (+1 or -1), preferring
// the parabolic (P²) prediction and falling back to linear interpolation
// whenever the parabolic estimate would not stay strictly between its
// neighbors (the paper's own safeguard against a non-monotonic result).
func (q *p2Quantile) move(i int, d float64) {
	parabolic := q.heights[i] + d/(q.n[i+1]-q.n[i-1])*((q.n[i]-q.n[i-1]+d)*(q.heights[i+1]-q.heights[i])/(q.n[i+1]-q.n[i])+
		(q.n[i+1]-q.n[i]-d)*(q.heights[i]-q.heights[i-1])/(q.n[i]-q.n[i-1]))
	if q.heights[i-1] < parabolic && parabolic < q.heights[i+1] {
		q.heights[i] = parabolic
	} else {
		j := i + int(d)
		q.heights[i] += d * (q.heights[j] - q.heights[i]) / (q.n[j] - q.n[i])
	}
	q.n[i] += d
}

// Value returns the current quantile estimate. Before 5 observations
// have been seen (P² needs all 5 markers seeded to operate), it falls
// back to linear interpolation over whatever has been observed so far --
// exact for that tiny sample, and consistent with SegmentStats.Confidence
// already reporting very low trust for an N this small.
func (q *p2Quantile) Value() float64 {
	if q.count == 0 {
		return 0
	}
	if len(q.initBuf) < 5 {
		sorted := append([]float64(nil), q.initBuf...)
		sort.Float64s(sorted)
		idx := int(q.p * float64(len(sorted)-1))
		return sorted[idx]
	}
	return q.heights[2]
}
