package measurement

import (
	"fmt"
	"sync"
	"time"
)

type LinkQuality struct {
	RTTMicros float64
	LossRate  float64 // in [0, 1]
	Updated   time.Time
}

func LinkQualityFromPassive(s Snapshot) LinkQuality {
	return LinkQuality{LossRate: s.LossRate()}
}

func LinkQualityFromProbe(s ProbeStats) LinkQuality {
	return LinkQuality{RTTMicros: s.RTTMicros, LossRate: s.LossRate()}
}

type LinkID struct {
	A, B string
}

func canonicalLinkID(a, b string) LinkID {
	if a > b {
		a, b = b, a
	}
	return LinkID{A: a, B: b}
}

// PathQuality contains the composed quality of a multi-hop path.
type PathQuality struct {
	RTTMicros         float64
	LossRate          float64
	OldestLinkUpdated time.Time
}

// LinkStateTable stores the latest measurement for each known direct link.
// Path quality is derived from the constituent links on demand.
type LinkStateTable struct {
	mu    sync.Mutex
	links map[LinkID]LinkQuality
	now   func() time.Time
}

func NewLinkStateTable() *LinkStateTable {
	return &LinkStateTable{links: make(map[LinkID]LinkQuality), now: time.Now}
}

func (t *LinkStateTable) UpdateLink(a, b string, q LinkQuality) {
	t.mu.Lock()
	defer t.mu.Unlock()
	q.Updated = t.now()
	t.links[canonicalLinkID(a, b)] = q
}

func (t *LinkStateTable) Link(a, b string) (LinkQuality, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	q, ok := t.links[canonicalLinkID(a, b)]
	return q, ok
}

func (t *LinkStateTable) Links() []LinkID {
	t.mu.Lock()
	defer t.mu.Unlock()
	ids := make([]LinkID, 0, len(t.links))
	for id := range t.links {
		ids = append(ids, id)
	}
	return ids
}

func (t *LinkStateTable) Neighbors(node string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for id := range t.links {
		switch node {
		case id.A:
			out = append(out, id.B)
		case id.B:
			out = append(out, id.A)
		}
	}
	return out
}

// PathCost composes the quality of a multi-hop path from its measured links.
// RTT is summed across links. Loss is composed as the probability that at
// least one link drops the packet. The call fails if any link is unknown.
func (t *LinkStateTable) PathCost(path []string) (PathQuality, error) {
	if len(path) < 2 {
		return PathQuality{}, fmt.Errorf("measurement: PathCost needs at least 2 nodes, got %d", len(path))
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	var totalRTT float64
	survival := 1.0
	var oldest time.Time
	for i := 0; i+1 < len(path); i++ {
		q, ok := t.links[canonicalLinkID(path[i], path[i+1])]
		if !ok {
			return PathQuality{}, fmt.Errorf("measurement: no measurement for link %s<->%s", path[i], path[i+1])
		}
		totalRTT += q.RTTMicros
		survival *= 1 - q.LossRate
		if oldest.IsZero() || q.Updated.Before(oldest) {
			oldest = q.Updated
		}
	}
	return PathQuality{RTTMicros: totalRTT, LossRate: 1 - survival, OldestLinkUpdated: oldest}, nil
}
