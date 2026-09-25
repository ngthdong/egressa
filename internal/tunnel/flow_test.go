package tunnel

import (
	"net/netip"
	"testing"
	"time"
)

func buildIPv4(t *testing.T, proto byte, optionWords int, src, dst [4]byte, payload []byte) []byte {
	t.Helper()
	ihl := 5 + optionWords
	if ihl > 15 {
		t.Fatalf("ihl %d exceeds the 4-bit field", ihl)
	}
	header := make([]byte, ihl*4)
	header[0] = 0x40 | byte(ihl) // version 4, IHL
	header[9] = proto
	copy(header[12:16], src[:])
	copy(header[16:20], dst[:])
	return append(header, payload...)
}

func buildIPv6(t *testing.T, nextHeader byte, src, dst [16]byte, payload []byte) []byte {
	t.Helper()
	header := make([]byte, 40)
	header[0] = 0x60 // version 6
	header[6] = nextHeader
	copy(header[8:24], src[:])
	copy(header[24:40], dst[:])
	return append(header, payload...)
}

// buildTCP returns a full, real 20-byte TCP header (no options) with the
// given ports; the rest of the fields are zeroed, which ParseFlowKey does
// not look at.
func buildTCP(srcPort, dstPort uint16) []byte {
	h := make([]byte, 20)
	h[0], h[1] = byte(srcPort>>8), byte(srcPort)
	h[2], h[3] = byte(dstPort>>8), byte(dstPort)
	h[12] = 5 << 4 // data offset = 5 words, no options
	return h
}

func buildUDP(srcPort, dstPort uint16, payloadLen int) []byte {
	h := make([]byte, 8)
	h[0], h[1] = byte(srcPort>>8), byte(srcPort)
	h[2], h[3] = byte(dstPort>>8), byte(dstPort)
	length := uint16(8 + payloadLen)
	h[4], h[5] = byte(length>>8), byte(length)
	return h
}

func addr4(s string) [4]byte { a := netip.MustParseAddr(s); return a.As4() }
func addr6(s string) [16]byte {
	a := netip.MustParseAddr(s)
	return a.As16()
}

func TestParseFlowKey_IPv4TCP(t *testing.T) {
	pkt := buildIPv4(t, byte(ProtoTCP), 0, addr4("10.0.0.2"), addr4("93.184.216.34"), buildTCP(54321, 443))

	key, err := ParseFlowKey(pkt)
	if err != nil {
		t.Fatalf("ParseFlowKey: %v", err)
	}
	want := FlowKey{
		Proto:   ProtoTCP,
		SrcAddr: netip.MustParseAddr("10.0.0.2"),
		SrcPort: 54321,
		DstAddr: netip.MustParseAddr("93.184.216.34"),
		DstPort: 443,
	}
	if key != want {
		t.Fatalf("ParseFlowKey = %+v, want %+v", key, want)
	}
}

func TestParseFlowKey_IPv4TCPWithOptions(t *testing.T) {
	// A naive parser that hardcodes a 20-byte IPv4 header would read the
	// start of the options as if it were the TCP header and get the
	// wrong ports; this is the case that catches that bug.
	pkt := buildIPv4(t, byte(ProtoTCP), 2, addr4("10.0.0.2"), addr4("93.184.216.34"), buildTCP(11111, 22222))

	key, err := ParseFlowKey(pkt)
	if err != nil {
		t.Fatalf("ParseFlowKey: %v", err)
	}
	if key.SrcPort != 11111 || key.DstPort != 22222 {
		t.Fatalf("ports = %d/%d, want 11111/22222 (IHL with options not honored)", key.SrcPort, key.DstPort)
	}
}

func TestParseFlowKey_IPv4UDP(t *testing.T) {
	pkt := buildIPv4(t, byte(ProtoUDP), 0, addr4("10.0.0.2"), addr4("8.8.8.8"), buildUDP(33333, 53, 0))

	key, err := ParseFlowKey(pkt)
	if err != nil {
		t.Fatalf("ParseFlowKey: %v", err)
	}
	if key.Proto != ProtoUDP || key.SrcPort != 33333 || key.DstPort != 53 {
		t.Fatalf("ParseFlowKey = %+v", key)
	}
}

func TestParseFlowKey_IPv4ICMPHasNoPorts(t *testing.T) {
	pkt := buildIPv4(t, byte(ProtoICMP), 0, addr4("10.0.0.2"), addr4("1.1.1.1"), []byte{8, 0, 0, 0, 0, 0, 0, 0})

	key, err := ParseFlowKey(pkt)
	if err != nil {
		t.Fatalf("ParseFlowKey: %v", err)
	}
	if key.SrcPort != 0 || key.DstPort != 0 {
		t.Fatalf("ICMP key has nonzero ports: %+v", key)
	}
	if key.Proto != ProtoICMP {
		t.Fatalf("Proto = %d, want ICMP", key.Proto)
	}
}

func TestParseFlowKey_IPv6TCP(t *testing.T) {
	pkt := buildIPv6(t, byte(ProtoTCP), addr6("fd00::2"), addr6("2606:4700:4700::1111"), buildTCP(4444, 443))

	key, err := ParseFlowKey(pkt)
	if err != nil {
		t.Fatalf("ParseFlowKey: %v", err)
	}
	want := FlowKey{
		Proto:   ProtoTCP,
		SrcAddr: netip.MustParseAddr("fd00::2"),
		SrcPort: 4444,
		DstAddr: netip.MustParseAddr("2606:4700:4700::1111"),
		DstPort: 443,
	}
	if key != want {
		t.Fatalf("ParseFlowKey = %+v, want %+v", key, want)
	}
}

func TestParseFlowKey_Reverse(t *testing.T) {
	fwd := FlowKey{Proto: ProtoTCP, SrcAddr: netip.MustParseAddr("10.0.0.2"), SrcPort: 1234,
		DstAddr: netip.MustParseAddr("1.1.1.1"), DstPort: 443}
	rev := fwd.Reverse()
	want := FlowKey{Proto: ProtoTCP, SrcAddr: netip.MustParseAddr("1.1.1.1"), SrcPort: 443,
		DstAddr: netip.MustParseAddr("10.0.0.2"), DstPort: 1234}
	if rev != want {
		t.Fatalf("Reverse = %+v, want %+v", rev, want)
	}
	if rev.Reverse() != fwd {
		t.Fatal("Reverse is not its own inverse")
	}
}

func TestParseFlowKey_Errors(t *testing.T) {
	cases := map[string][]byte{
		"empty":                    {},
		"bad version nibble":       {0x00},
		"truncated IPv4 header":    buildIPv4(t, byte(ProtoTCP), 0, addr4("10.0.0.2"), addr4("1.1.1.1"), nil)[:10],
		"truncated IPv6 header":    buildIPv6(t, byte(ProtoTCP), addr6("fd00::2"), addr6("fd00::1"), nil)[:20],
		"truncated TCP header":     buildIPv4(t, byte(ProtoTCP), 0, addr4("10.0.0.2"), addr4("1.1.1.1"), []byte{0, 1}),
		"unsupported IPv4 proto":   buildIPv4(t, 132 /* SCTP */, 0, addr4("10.0.0.2"), addr4("1.1.1.1"), nil),
		"unsupported IPv6 next hd": buildIPv6(t, 132, addr6("fd00::2"), addr6("fd00::1"), nil),
		"IHL smaller than 5 words": func() []byte {
			p := buildIPv4(t, byte(ProtoTCP), 0, addr4("10.0.0.2"), addr4("1.1.1.1"), buildTCP(1, 2))
			p[0] = 0x40 | 4 // IHL = 4 words = 16 bytes, invalid (min is 20)
			return p
		}(),
	}
	for name, pkt := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseFlowKey(pkt); err == nil {
				t.Fatalf("ParseFlowKey(%s): expected an error, got nil", name)
			}
		})
	}
}

func TestFlowTable_PinsOnce(t *testing.T) {
	calls := 0
	policy := func(FlowKey) string {
		calls++
		return "egress-1"
	}
	ft := NewFlowTable(policy, 0)

	key := FlowKey{Proto: ProtoTCP, SrcAddr: netip.MustParseAddr("10.0.0.2"), SrcPort: 1,
		DstAddr: netip.MustParseAddr("1.1.1.1"), DstPort: 443}

	for i := 0; i < 5; i++ {
		if got := ft.Egress(key); got != "egress-1" {
			t.Fatalf("Egress call %d = %q, want egress-1", i, got)
		}
	}
	if calls != 1 {
		t.Fatalf("policy called %d times, want exactly 1 (pinning must happen once per flow)", calls)
	}
}

func TestFlowTable_DifferentFlowsGetIndependentPins(t *testing.T) {
	next := 0
	policy := func(FlowKey) string {
		next++
		return []string{"egress-1", "egress-2"}[next-1]
	}
	ft := NewFlowTable(policy, 0)

	a := FlowKey{Proto: ProtoTCP, SrcPort: 1, DstPort: 443,
		SrcAddr: netip.MustParseAddr("10.0.0.2"), DstAddr: netip.MustParseAddr("1.1.1.1")}
	b := FlowKey{Proto: ProtoTCP, SrcPort: 2, DstPort: 443,
		SrcAddr: netip.MustParseAddr("10.0.0.2"), DstAddr: netip.MustParseAddr("1.1.1.1")}

	if got := ft.Egress(a); got != "egress-1" {
		t.Fatalf("flow a = %q, want egress-1", got)
	}
	if got := ft.Egress(b); got != "egress-2" {
		t.Fatalf("flow b = %q, want egress-2", got)
	}
	// Re-asking for `a` must still return its original pin, not
	// whatever the policy would say now.
	if got := ft.Egress(a); got != "egress-1" {
		t.Fatalf("flow a on re-lookup = %q, want egress-1 (must stay pinned)", got)
	}
}

func TestFlowTable_LookupDoesNotCreate(t *testing.T) {
	ft := NewFlowTable(StaticEgressPolicy("egress-1"), 0)
	key := FlowKey{Proto: ProtoUDP, SrcAddr: netip.MustParseAddr("10.0.0.2"), DstAddr: netip.MustParseAddr("8.8.8.8"), DstPort: 53}

	if _, ok := ft.Lookup(key); ok {
		t.Fatal("Lookup found an entry before any Egress call")
	}
	if ft.Len() != 0 {
		t.Fatalf("Len = %d, want 0", ft.Len())
	}

	ft.Egress(key)
	got, ok := ft.Lookup(key)
	if !ok || got != "egress-1" {
		t.Fatalf("Lookup after Egress = (%q, %v), want (egress-1, true)", got, ok)
	}
}

func TestFlowTable_EvictIdle(t *testing.T) {
	fakeNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ft := NewFlowTable(StaticEgressPolicy("egress-1"), 30*time.Second)
	ft.now = func() time.Time { return fakeNow }

	key := FlowKey{Proto: ProtoTCP, SrcAddr: netip.MustParseAddr("10.0.0.2"), DstAddr: netip.MustParseAddr("1.1.1.1"), DstPort: 443}
	ft.Egress(key)

	if removed := ft.EvictIdle(); removed != 0 {
		t.Fatalf("EvictIdle removed %d flows immediately after creation, want 0", removed)
	}

	fakeNow = fakeNow.Add(31 * time.Second)
	removed := ft.EvictIdle()
	if removed != 1 {
		t.Fatalf("EvictIdle removed %d, want 1", removed)
	}
	if ft.Len() != 0 {
		t.Fatalf("Len after eviction = %d, want 0", ft.Len())
	}
}

func TestFlowTable_EvictIdle_RefreshedByLookupNotByPlainLookup(t *testing.T) {
	fakeNow := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ft := NewFlowTable(StaticEgressPolicy("egress-1"), 10*time.Second)
	ft.now = func() time.Time { return fakeNow }

	key := FlowKey{Proto: ProtoTCP, SrcAddr: netip.MustParseAddr("10.0.0.2"), DstAddr: netip.MustParseAddr("1.1.1.1"), DstPort: 443}
	ft.Egress(key)

	// Advance partway, keep the flow alive via Egress (as real traffic
	// would, one call per packet), and confirm it survives past its
	// original TTL.
	fakeNow = fakeNow.Add(6 * time.Second)
	ft.Egress(key)
	fakeNow = fakeNow.Add(6 * time.Second) // 12s since Egress, but only 6s since the refresh
	if removed := ft.EvictIdle(); removed != 0 {
		t.Fatalf("EvictIdle removed a flow kept alive by traffic: removed=%d", removed)
	}

	// A plain Lookup must NOT refresh the clock, only genuine traffic
	// (Egress) should keep a flow alive.
	fakeNow = fakeNow.Add(9 * time.Second) // 15s since the last Egress
	ft.Lookup(key)
	fakeNow = fakeNow.Add(2 * time.Second) // 17s since the last Egress
	if removed := ft.EvictIdle(); removed != 1 {
		t.Fatalf("EvictIdle removed %d, want 1 (Lookup must not refresh LastSeen)", removed)
	}
}

func TestFlowTable_EvictIdle_DisabledWhenTTLNonPositive(t *testing.T) {
	ft := NewFlowTable(StaticEgressPolicy("egress-1"), 0)
	key := FlowKey{Proto: ProtoTCP, SrcAddr: netip.MustParseAddr("10.0.0.2"), DstAddr: netip.MustParseAddr("1.1.1.1"), DstPort: 443}
	ft.Egress(key)
	if removed := ft.EvictIdle(); removed != 0 {
		t.Fatalf("EvictIdle with idleTTL<=0 removed %d, want 0 (must be a no-op)", removed)
	}
	if ft.Len() != 1 {
		t.Fatal("EvictIdle must not remove flows when idleTTL <= 0")
	}
}

func TestFlowTable_ConcurrentFirstPacketPinsOnce(t *testing.T) {
	var calls int
	var mu = make(chan struct{}, 1)
	mu <- struct{}{}
	policy := func(FlowKey) string {
		<-mu
		calls++
		mu <- struct{}{}
		return "egress-1"
	}
	ft := NewFlowTable(policy, 0)
	key := FlowKey{Proto: ProtoTCP, SrcAddr: netip.MustParseAddr("10.0.0.2"), DstAddr: netip.MustParseAddr("1.1.1.1"), DstPort: 443}

	const n = 50
	done := make(chan string, n)
	for i := 0; i < n; i++ {
		go func() { done <- ft.Egress(key) }()
	}
	for i := 0; i < n; i++ {
		if got := <-done; got != "egress-1" {
			t.Fatalf("concurrent Egress returned %q, want egress-1", got)
		}
	}
	if calls != 1 {
		t.Fatalf("policy invoked %d times under concurrent first-packet race, want exactly 1", calls)
	}
}
