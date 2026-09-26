package measurement

import (
	"net/netip"
	"sync"
)

// PortClass groups destination traffic into a small number of protocol/port
// categories. It is intentionally coarse to avoid fragmenting measurements
// into too many low-sample groups.
type PortClass string

const (
	// PortClassDNS represents DNS traffic on port 53.
	PortClassDNS PortClass = "dns"

	// PortClassWeb represents HTTP and HTTPS traffic over TCP.
	PortClassWeb PortClass = "web"

	// PortClassQUIC represents UDP traffic on port 443.
	PortClassQUIC PortClass = "quic"

	// PortClassOther represents traffic that does not match another class.
	PortClassOther PortClass = "other"
)

// ClassifyPort classifies traffic using its destination port and transport
// protocol. The default classification is intentionally simple and can be
// replaced with a deployment-specific classifier when finer-grained grouping
// is required.
func ClassifyPort(port uint16, udp bool) PortClass {
	switch {
	case port == 53:
		return PortClassDNS
	case udp && port == 443:
		return PortClassQUIC
	case !udp && (port == 80 || port == 443):
		return PortClassWeb
	default:
		return PortClassOther
	}
}

// GroupKey identifies a destination measurement group.
// A group is defined by the destination prefix and traffic class. Multiple
// destinations within the same prefix share measurements when they belong
// to the same PortClass.
type GroupKey struct {
	Prefix    netip.Prefix
	PortClass PortClass
}

// MatchTier records which mechanism resolved a destination to a GroupKey.
type MatchTier int

const (
	// MatchNone indicates that the destination address is invalid.
	MatchNone MatchTier = iota

	// MatchRIB indicates that the destination matched a prefix in the RIB.
	MatchRIB

	// MatchCoarseFallback indicates that no RIB prefix matched and the
	// configured coarse prefix mask was used instead.
	MatchCoarseFallback
)

func (m MatchTier) String() string {
	switch m {
	case MatchNone:
		return "none"
	case MatchRIB:
		return "rib"
	case MatchCoarseFallback:
		return "coarse-fallback"
	default:
		return "unknown"
	}
}

// DestinationGroups maps destination traffic to measurement groups.
//
// Destinations are first resolved using the RIB's longest-prefix match.
// When no RIB prefix covers the destination, the configured coarse prefix
// mask is used as a fallback.
//
// SegmentTrackers are created lazily when a group is first accessed, so
// memory usage scales with observed groups rather than the size of the RIB.
type DestinationGroups struct {
	mu         sync.Mutex
	rib        *RIB
	classify   func(port uint16, udp bool) PortClass
	fallback   PrefixBits
	trackerCfg SegmentTrackerConfig
	buckets    map[GroupKey]*SegmentTracker
}

func NewDestinationGroups(rib *RIB, classify func(port uint16, udp bool) PortClass, fallback PrefixBits, trackerCfg SegmentTrackerConfig) *DestinationGroups {
	if classify == nil {
		classify = ClassifyPort
	}
	if fallback.IPv4 <= 0 {
		fallback.IPv4 = DefaultPrefixBits.IPv4
	}
	if fallback.IPv6 <= 0 {
		fallback.IPv6 = DefaultPrefixBits.IPv6
	}
	return &DestinationGroups{
		rib:        rib,
		classify:   classify,
		fallback:   fallback,
		trackerCfg: trackerCfg,
		buckets:    make(map[GroupKey]*SegmentTracker),
	}
}

// Lookup resolves a destination address/port/protocol to its GroupKey
// and the tier that produced it.
func (g *DestinationGroups) Lookup(addr netip.Addr, port uint16, udp bool) (GroupKey, MatchTier) {
	if !addr.IsValid() {
		return GroupKey{}, MatchNone
	}
	if prefix, ok := g.rib.Lookup(addr); ok {
		return GroupKey{Prefix: prefix, PortClass: g.classify(port, udp)}, MatchRIB
	}
	return GroupKey{Prefix: g.fallback.Mask(addr), PortClass: g.classify(port, udp)}, MatchCoarseFallback
}

// Tracker returns the SegmentTracker bucket for key, creating it
// (lazily, with this DestinationGroups' trackerCfg) on first access. The
// same key always returns the same *SegmentTracker.
func (g *DestinationGroups) Tracker(key GroupKey) *SegmentTracker {
	g.mu.Lock()
	defer g.mu.Unlock()
	t, ok := g.buckets[key]
	if !ok {
		t = NewSegmentTracker(g.trackerCfg)
		g.buckets[key] = t
	}
	return t
}

func (g *DestinationGroups) Groups() []GroupKey {
	g.mu.Lock()
	defer g.mu.Unlock()
	keys := make([]GroupKey, 0, len(g.buckets))
	for k := range g.buckets {
		keys = append(keys, k)
	}
	return keys
}

func (g *DestinationGroups) Len() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.buckets)
}
