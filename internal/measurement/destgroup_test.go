package measurement

import (
	"net/netip"
	"sync"
	"testing"
)

func TestClassifyPort(t *testing.T) {
	cases := []struct {
		name string
		port uint16
		udp  bool
		want PortClass
	}{
		{"dns tcp", 53, false, PortClassDNS},
		{"dns udp", 53, true, PortClassDNS},
		{"https tcp", 443, false, PortClassWeb},
		{"http tcp", 80, false, PortClassWeb},
		{"https udp (quic)", 443, true, PortClassQUIC},
		{"http udp is not web", 80, true, PortClassOther},
		{"random tcp port", 8443, false, PortClassOther},
		{"random udp port", 51820, true, PortClassOther},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ClassifyPort(c.port, c.udp); got != c.want {
				t.Fatalf("ClassifyPort(%d, udp=%v) = %s, want %s", c.port, c.udp, got, c.want)
			}
		})
	}
}

func newTestDestinationGroups(t *testing.T) *DestinationGroups {
	t.Helper()
	rib := NewRIB()
	if err := rib.LoadPrefixes([]netip.Prefix{
		mustPrefix(t, "93.184.216.0/24"),
		mustPrefix(t, "93.184.0.0/16"),
	}); err != nil {
		t.Fatal(err)
	}
	return NewDestinationGroups(rib, nil, PrefixBits{}, SegmentTrackerConfig{})
}

func TestDestinationGroups_Lookup_RIBMatch_UsesLongestPrefix(t *testing.T) {
	g := newTestDestinationGroups(t)

	key, tier := g.Lookup(netip.MustParseAddr("93.184.216.34"), 443, false)
	if tier != MatchRIB {
		t.Fatalf("tier = %v, want MatchRIB", tier)
	}
	if key.Prefix != mustPrefix(t, "93.184.216.0/24") {
		t.Fatalf("Prefix = %s, want the more specific /24, not the /16", key.Prefix)
	}
	if key.PortClass != PortClassWeb {
		t.Fatalf("PortClass = %s, want web", key.PortClass)
	}
}

func TestDestinationGroups_Lookup_UnknownDestination_UsesCoarseFallback(t *testing.T) {
	g := newTestDestinationGroups(t)

	key, tier := g.Lookup(netip.MustParseAddr("198.51.100.7"), 443, false)
	if tier != MatchCoarseFallback {
		t.Fatalf("tier = %v, want MatchCoarseFallback", tier)
	}
	if key.Prefix != mustPrefix(t, "198.51.100.0/24") {
		t.Fatalf("Prefix = %s, want the default /24 fallback mask", key.Prefix)
	}
}

func TestDestinationGroups_Lookup_InvalidAddr_MatchNone(t *testing.T) {
	g := newTestDestinationGroups(t)
	key, tier := g.Lookup(netip.Addr{}, 443, false)
	if tier != MatchNone {
		t.Fatalf("tier = %v, want MatchNone for an invalid address", tier)
	}
	if key != (GroupKey{}) {
		t.Fatalf("key = %+v, want the zero GroupKey", key)
	}
}

func TestDestinationGroups_Tracker_LazyCreation(t *testing.T) {
	g := newTestDestinationGroups(t)
	if got := g.Len(); got != 0 {
		t.Fatalf("Len() before any Tracker call = %d, want 0", got)
	}

	key, _ := g.Lookup(netip.MustParseAddr("93.184.216.34"), 443, false)
	tr := g.Tracker(key)
	if got := g.Len(); got != 1 {
		t.Fatalf("Len() after first Tracker call = %d, want 1", got)
	}

	tr2 := g.Tracker(key)
	if tr != tr2 {
		t.Fatal("Tracker(key) called twice with the same key returned different *SegmentTracker instances")
	}
	if got := g.Len(); got != 1 {
		t.Fatalf("Len() after a repeat Tracker call = %d, want still 1 (no duplicate bucket)", got)
	}
}

func TestDestinationGroups_Tracker_PortClassSplitsBucket(t *testing.T) {
	g := newTestDestinationGroups(t)

	webKey, _ := g.Lookup(netip.MustParseAddr("93.184.216.34"), 443, false)
	quicKey, _ := g.Lookup(netip.MustParseAddr("93.184.216.34"), 443, true)

	if webKey.Prefix != quicKey.Prefix {
		t.Fatal("same destination address must resolve to the same prefix regardless of port class")
	}
	if webKey.PortClass == quicKey.PortClass {
		t.Fatal("TCP/443 and UDP/443 to the same address must classify to different port classes")
	}

	webTracker := g.Tracker(webKey)
	quicTracker := g.Tracker(quicKey)
	if webTracker == quicTracker {
		t.Fatal("web and quic traffic to the same prefix must get separate SegmentTracker buckets")
	}
	if got := g.Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2 (prefix x port-class split)", got)
	}
}

func TestDestinationGroups_Groups_ListsOnlyCreatedBuckets(t *testing.T) {
	g := newTestDestinationGroups(t)
	key1, _ := g.Lookup(netip.MustParseAddr("93.184.216.34"), 443, false)
	g.Tracker(key1)

	// A lookup alone, without ever calling Tracker, must not create a
	// bucket, this is the "lazy hot buckets" requirement.
	key2, _ := g.Lookup(netip.MustParseAddr("198.51.100.7"), 443, false)
	_ = key2

	groups := g.Groups()
	if len(groups) != 1 || groups[0] != key1 {
		t.Fatalf("Groups() = %+v, want exactly [%+v]", groups, key1)
	}
}

func TestDestinationGroups_CustomClassifier(t *testing.T) {
	rib := NewRIB()
	custom := func(port uint16, udp bool) PortClass {
		if port == 12345 {
			return PortClass("custom")
		}
		return PortClassOther
	}
	g := NewDestinationGroups(rib, custom, PrefixBits{}, SegmentTrackerConfig{})

	key, _ := g.Lookup(netip.MustParseAddr("1.2.3.4"), 12345, false)
	if key.PortClass != PortClass("custom") {
		t.Fatalf("PortClass = %s, want the custom classifier's result", key.PortClass)
	}
}

func TestDestinationGroups_TrackerCfgPropagates(t *testing.T) {
	rib := NewRIB()
	cfg := SegmentTrackerConfig{SampleHalfCount: 5}
	g := NewDestinationGroups(rib, nil, PrefixBits{}, cfg)

	key, _ := g.Lookup(netip.MustParseAddr("1.2.3.4"), 443, false)
	tr := g.Tracker(key)
	if tr.cfg.SampleHalfCount != 5 {
		t.Fatalf("tracker cfg.SampleHalfCount = %f, want 5 (propagated from NewDestinationGroups)", tr.cfg.SampleHalfCount)
	}
}

func TestDestinationGroups_NewDestinationTracker_UnknownDestinationStartsAtZeroConfidence(t *testing.T) {
	g := newTestDestinationGroups(t)
	key, tier := g.Lookup(netip.MustParseAddr("198.51.100.7"), 443, false)
	if tier != MatchCoarseFallback {
		t.Fatalf("tier = %v, want MatchCoarseFallback", tier)
	}
	snap := g.Tracker(key).Snapshot()
	if snap.N != 0 || snap.Confidence != 0 {
		t.Fatalf("a never-before-seen destination's bucket = %+v, want N=0 Confidence=0 (the signal a caller uses to fall back to default egress)", snap)
	}
}

func TestDestinationGroups_ConcurrentTracker_NoRace(t *testing.T) {
	g := newTestDestinationGroups(t)
	key, _ := g.Lookup(netip.MustParseAddr("93.184.216.34"), 443, false)

	var wg sync.WaitGroup
	const goroutines = 30
	trackers := make([]*SegmentTracker, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			trackers[i] = g.Tracker(key)
		}(i)
	}
	wg.Wait()

	for i := 1; i < goroutines; i++ {
		if trackers[i] != trackers[0] {
			t.Fatal("concurrent Tracker(key) calls returned different instances: a bucket was created more than once")
		}
	}
	if got := g.Len(); got != 1 {
		t.Fatalf("Len() = %d, want 1", got)
	}
}
