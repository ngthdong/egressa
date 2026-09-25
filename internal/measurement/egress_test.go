package measurement

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func buildIPv4Packet(proto byte, src, dst [4]byte, payload []byte) []byte {
	header := make([]byte, 20)
	header[0] = 0x45 // version 4, IHL 5 (20 bytes, no options)
	header[9] = proto
	copy(header[12:16], src[:])
	copy(header[16:20], dst[:])
	return append(header, payload...)
}

// buildIPv4PacketWithOptions builds an IPv4 packet with a non-default IHL,
// to check that TCP header offsets are computed from IHL, not assumed to
// always be 20 bytes.
func buildIPv4PacketWithOptions(proto byte, src, dst [4]byte, payload []byte) []byte {
	const ihlWords = 6 // 24-byte header (4 bytes of options)
	header := make([]byte, ihlWords*4)
	header[0] = 0x40 | byte(ihlWords)
	header[9] = proto
	copy(header[12:16], src[:])
	copy(header[16:20], dst[:])
	return append(header, payload...)
}

func buildIPv6Packet(proto byte, src, dst [16]byte, payload []byte) []byte {
	header := make([]byte, 40)
	header[0] = 0x60 // version 6
	header[6] = proto
	copy(header[8:24], src[:])
	copy(header[24:40], dst[:])
	return append(header, payload...)
}

func buildTCPHeader(srcPort, dstPort uint16, seq uint32, syn, ack bool) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:2], srcPort)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	binary.BigEndian.PutUint32(h[4:8], seq)
	h[12] = 5 << 4 // data offset: 5 words, no options
	var flags byte
	if syn {
		flags |= tcpFlagSYN
	}
	if ack {
		flags |= tcpFlagACK
	}
	h[13] = flags
	return h
}

func buildUDPHeader(srcPort, dstPort uint16) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:2], srcPort)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	return h
}

func syn4(src, dst [4]byte, srcPort, dstPort uint16, seq uint32) []byte {
	return buildIPv4Packet(protoTCP, src, dst, buildTCPHeader(srcPort, dstPort, seq, true, false))
}

func synAck4(src, dst [4]byte, srcPort, dstPort uint16, seq uint32) []byte {
	return buildIPv4Packet(protoTCP, src, dst, buildTCPHeader(srcPort, dstPort, seq, true, true))
}

func udp4(src, dst [4]byte, srcPort, dstPort uint16) []byte {
	return buildIPv4Packet(protoUDP, src, dst, buildUDPHeader(srcPort, dstPort))
}

var (
	egressAddr = [4]byte{10, 0, 0, 5}
	dest1Addr  = [4]byte{93, 184, 216, 34} // example.com-ish
	dest2Addr  = [4]byte{93, 184, 216, 99} // same /24 as dest1
	dest3Addr  = [4]byte{198, 51, 100, 10} // different /24
)

func newTestEgressObserver() (*EgressObserver, *fakeClock) {
	fc := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	o := NewEgressObserver(DefaultPrefixBits)
	o.now = fc.now
	return o, fc
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p
}

func TestEgressObserver_HandshakeRTT(t *testing.T) {
	o, fc := newTestEgressObserver()

	if err := o.ObservePacket(syn4(egressAddr, dest1Addr, 40000, 443, 1000)); err != nil {
		t.Fatalf("ObservePacket(SYN): %v", err)
	}
	fc.advance(25 * time.Millisecond)
	if err := o.ObservePacket(synAck4(dest1Addr, egressAddr, 443, 40000, 5000)); err != nil {
		t.Fatalf("ObservePacket(SYN-ACK): %v", err)
	}

	prefix := mustPrefix(t, "93.184.216.0/24")
	s, ok := o.Snapshot(prefix)
	if !ok {
		t.Fatalf("no stats recorded for %s", prefix)
	}
	if s.Handshakes != 1 {
		t.Fatalf("Handshakes = %d, want 1", s.Handshakes)
	}
	if want := float64(25 * time.Millisecond / time.Microsecond); s.RTTMicros != want {
		t.Fatalf("RTTMicros = %f, want %f", s.RTTMicros, want)
	}
	if s.Confidence() != ConfidenceHigh {
		t.Fatalf("Confidence = %v, want ConfidenceHigh", s.Confidence())
	}
}

func TestEgressObserver_Retransmit_CountsLoss(t *testing.T) {
	o, fc := newTestEgressObserver()

	if err := o.ObservePacket(syn4(egressAddr, dest1Addr, 40000, 443, 1000)); err != nil {
		t.Fatal(err)
	}
	fc.advance(1 * time.Second)
	// Same 4-tuple, same sequence number: a retransmission of the SYN.
	if err := o.ObservePacket(syn4(egressAddr, dest1Addr, 40000, 443, 1000)); err != nil {
		t.Fatal(err)
	}
	fc.advance(20 * time.Millisecond)
	if err := o.ObservePacket(synAck4(dest1Addr, egressAddr, 443, 40000, 5000)); err != nil {
		t.Fatal(err)
	}

	s, ok := o.Snapshot(mustPrefix(t, "93.184.216.0/24"))
	if !ok {
		t.Fatal("no stats recorded")
	}
	if s.Retransmits != 1 {
		t.Fatalf("Retransmits = %d, want 1", s.Retransmits)
	}
	if s.Handshakes != 1 {
		t.Fatalf("Handshakes = %d, want 1", s.Handshakes)
	}
	// RTT must be measured from the retransmission (most recent SYN),
	// not the original: 20ms, not 1.02s.
	if want := float64(20 * time.Millisecond / time.Microsecond); s.RTTMicros != want {
		t.Fatalf("RTTMicros = %f, want %f (measured from the retransmit, not the original SYN)", s.RTTMicros, want)
	}
	if got, want := s.LossRate(), 0.5; got != want {
		t.Fatalf("LossRate = %f, want %f (1 retransmit / (1 handshake + 1 retransmit))", got, want)
	}
}

func TestEgressObserver_DifferentSeqSameFourTuple_TreatedAsNewAttempt(t *testing.T) {
	o, fc := newTestEgressObserver()

	// First connection completes.
	if err := o.ObservePacket(syn4(egressAddr, dest1Addr, 40000, 443, 1000)); err != nil {
		t.Fatal(err)
	}
	fc.advance(10 * time.Millisecond)
	if err := o.ObservePacket(synAck4(dest1Addr, egressAddr, 443, 40000, 5000)); err != nil {
		t.Fatal(err)
	}

	// Port reused for an unrelated new connection (different sequence
	// number) to the same destination.
	if err := o.ObservePacket(syn4(egressAddr, dest1Addr, 40000, 443, 9999)); err != nil {
		t.Fatal(err)
	}
	fc.advance(15 * time.Millisecond)
	if err := o.ObservePacket(synAck4(dest1Addr, egressAddr, 443, 40000, 6000)); err != nil {
		t.Fatal(err)
	}

	s, _ := o.Snapshot(mustPrefix(t, "93.184.216.0/24"))
	if s.Retransmits != 0 {
		t.Fatalf("Retransmits = %d, want 0 (different seq = new attempt, not a retransmission)", s.Retransmits)
	}
	if s.Handshakes != 2 {
		t.Fatalf("Handshakes = %d, want 2", s.Handshakes)
	}
}

func TestEgressObserver_SYNACKWithNoOutstandingSYN_Ignored(t *testing.T) {
	o, _ := newTestEgressObserver()

	if err := o.ObservePacket(synAck4(dest1Addr, egressAddr, 443, 40000, 5000)); err != nil {
		t.Fatal(err)
	}

	if snaps := o.Snapshots(); len(snaps) != 0 {
		t.Fatalf("Snapshots() = %+v, want empty: an unmatched SYN-ACK must not fabricate a sample", snaps)
	}
}

func TestEgressObserver_PrefixAggregation(t *testing.T) {
	o, fc := newTestEgressObserver()

	// dest1 and dest2 share a /24; dest3 does not.
	for _, d := range [][4]byte{dest1Addr, dest2Addr, dest3Addr} {
		if err := o.ObservePacket(syn4(egressAddr, d, 40000, 443, 1000)); err != nil {
			t.Fatal(err)
		}
		fc.advance(10 * time.Millisecond)
		if err := o.ObservePacket(synAck4(d, egressAddr, 443, 40000, 5000)); err != nil {
			t.Fatal(err)
		}
	}

	sharedPrefix, _ := o.Snapshot(mustPrefix(t, "93.184.216.0/24"))
	if sharedPrefix.Handshakes != 2 {
		t.Fatalf("shared /24 Handshakes = %d, want 2 (dest1 + dest2 both fold into one bucket)", sharedPrefix.Handshakes)
	}

	otherPrefix, _ := o.Snapshot(mustPrefix(t, "198.51.100.0/24"))
	if otherPrefix.Handshakes != 1 {
		t.Fatalf("other /24 Handshakes = %d, want 1", otherPrefix.Handshakes)
	}

	if len(o.Snapshots()) != 2 {
		t.Fatalf("Snapshots() has %d entries, want 2 distinct prefixes", len(o.Snapshots()))
	}
}

func TestEgressObserver_UDP_LowConfidence(t *testing.T) {
	o, _ := newTestEgressObserver()

	if err := o.ObservePacket(udp4(egressAddr, dest1Addr, 50000, 443)); err != nil {
		t.Fatal(err)
	}

	s, ok := o.Snapshot(mustPrefix(t, "93.184.216.0/24"))
	if !ok {
		t.Fatal("no stats recorded for UDP-only prefix")
	}
	if s.Confidence() != ConfidenceLow {
		t.Fatalf("Confidence = %v, want ConfidenceLow", s.Confidence())
	}
	if s.UDPPackets != 1 {
		t.Fatalf("UDPPackets = %d, want 1", s.UDPPackets)
	}
	if s.RTTMicros != 0 || s.Handshakes != 0 {
		t.Fatalf("a UDP-only bucket must not report a fabricated RTT/handshake: got %+v", s)
	}
}

func TestEgressObserver_UDPThenTCP_BecomesHighConfidence(t *testing.T) {
	o, fc := newTestEgressObserver()

	if err := o.ObservePacket(udp4(egressAddr, dest1Addr, 50000, 443)); err != nil {
		t.Fatal(err)
	}
	// dest2 shares dest1's /24.
	if err := o.ObservePacket(syn4(egressAddr, dest2Addr, 40000, 443, 1000)); err != nil {
		t.Fatal(err)
	}
	fc.advance(10 * time.Millisecond)
	if err := o.ObservePacket(synAck4(dest2Addr, egressAddr, 443, 40000, 5000)); err != nil {
		t.Fatal(err)
	}

	s, _ := o.Snapshot(mustPrefix(t, "93.184.216.0/24"))
	if s.Confidence() != ConfidenceHigh {
		t.Fatalf("Confidence = %v, want ConfidenceHigh once real TCP evidence exists in the prefix", s.Confidence())
	}
}

func TestEgressObserver_LossRate_Table(t *testing.T) {
	cases := []struct {
		name             string
		handshakes, retx uint64
		want             float64
	}{
		{"no data", 0, 0, 0},
		{"no loss", 10, 0, 0},
		{"half loss", 1, 1, 0.5},
		{"all retransmits, none completed", 0, 3, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := PrefixStats{Handshakes: c.handshakes, Retransmits: c.retx}
			if got := s.LossRate(); got != c.want {
				t.Fatalf("LossRate() = %f, want %f", got, c.want)
			}
		})
	}
}

func TestEgressObserver_EvictStalePending(t *testing.T) {
	o, fc := newTestEgressObserver()

	if err := o.ObservePacket(syn4(egressAddr, dest1Addr, 40000, 443, 1000)); err != nil {
		t.Fatal(err)
	}
	fc.advance(time.Minute)
	// A second, fresh SYN to a different destination must survive.
	if err := o.ObservePacket(syn4(egressAddr, dest3Addr, 40001, 443, 2000)); err != nil {
		t.Fatal(err)
	}

	removed := o.EvictStalePending(30 * time.Second)
	if removed != 1 {
		t.Fatalf("EvictStalePending removed %d, want 1 (only the 1-minute-old pending SYN)", removed)
	}

	// The evicted SYN's belated SYN-ACK must not fabricate a sample.
	if err := o.ObservePacket(synAck4(dest1Addr, egressAddr, 443, 40000, 5000)); err != nil {
		t.Fatal(err)
	}
	if _, ok := o.Snapshot(mustPrefix(t, "93.184.216.0/24")); ok {
		t.Fatal("a SYN-ACK for an evicted pending SYN must not produce a sample")
	}

	// The fresh one must still be outstanding (not evicted).
	if removed2 := o.EvictStalePending(time.Hour); removed2 != 0 {
		t.Fatalf("second EvictStalePending(1h) removed %d, want 0 (the fresh SYN is only 1 minute old)", removed2)
	}
}

func TestPrefixBits_Mask(t *testing.T) {
	bits := PrefixBits{IPv4: 24, IPv6: 48}

	v4 := netip.MustParseAddr("93.184.216.34")
	if got := bits.Mask(v4); got != mustPrefix(t, "93.184.216.0/24") {
		t.Fatalf("Mask(v4) = %s, want 93.184.216.0/24", got)
	}

	v6 := netip.MustParseAddr("2001:db8:abcd:1234::1")
	if got := bits.Mask(v6); got != mustPrefix(t, "2001:db8:abcd::/48") {
		t.Fatalf("Mask(v6) = %s, want 2001:db8:abcd::/48", got)
	}
}

func TestParseIPHeader_Errors(t *testing.T) {
	cases := []struct {
		name   string
		packet []byte
	}{
		{"empty", nil},
		{"unsupported version", []byte{0x55, 0, 0, 0}},
		{"truncated IPv4", []byte{0x45, 0, 0, 0, 0, 0, 0, 0, 0, 6}},
		{"IPv4 IHL smaller than 20", append([]byte{0x44, 0, 0, 0, 0, 0, 0, 0, 0, 6}, make([]byte, 20)...)},
		{"truncated IPv6", make([]byte, 10)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, _, _, err := parseIPHeader(c.packet); err == nil {
				t.Fatalf("parseIPHeader(%s): expected an error", c.name)
			}
		})
	}
}

func TestEgressObserver_IPv4WithOptions_TCPOffsetCorrect(t *testing.T) {
	o, fc := newTestEgressObserver()

	packet := buildIPv4PacketWithOptions(protoTCP, egressAddr, dest1Addr, buildTCPHeader(40000, 443, 1000, true, false))
	if err := o.ObservePacket(packet); err != nil {
		t.Fatalf("ObservePacket with IPv4 options: %v", err)
	}
	fc.advance(5 * time.Millisecond)
	ackPacket := buildIPv4PacketWithOptions(protoTCP, dest1Addr, egressAddr, buildTCPHeader(443, 40000, 5000, true, true))
	if err := o.ObservePacket(ackPacket); err != nil {
		t.Fatalf("ObservePacket(SYN-ACK) with IPv4 options: %v", err)
	}

	s, ok := o.Snapshot(mustPrefix(t, "93.184.216.0/24"))
	if !ok || s.Handshakes != 1 {
		t.Fatalf("Snapshot = %+v, ok=%v; want 1 handshake (IHL-variable TCP offset must be respected)", s, ok)
	}
}

func TestEgressObserver_IPv6(t *testing.T) {
	o, fc := newTestEgressObserver()
	src := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	dst := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 1}

	syn := buildIPv6Packet(protoTCP, src, dst, buildTCPHeader(40000, 443, 1000, true, false))
	if err := o.ObservePacket(syn); err != nil {
		t.Fatal(err)
	}
	fc.advance(30 * time.Millisecond)
	synAck := buildIPv6Packet(protoTCP, dst, src, buildTCPHeader(443, 40000, 5000, true, true))
	if err := o.ObservePacket(synAck); err != nil {
		t.Fatal(err)
	}

	s, ok := o.Snapshot(mustPrefix(t, "2001:db8:abcd::/48"))
	if !ok || s.Handshakes != 1 {
		t.Fatalf("Snapshot = %+v, ok=%v; want 1 handshake in the IPv6 /48 bucket", s, ok)
	}
}

func TestEgressObserver_ConcurrentObservePacket_NoRace(t *testing.T) {
	o := NewEgressObserver(DefaultPrefixBits)
	var wg sync.WaitGroup
	const goroutines = 20
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i uint16) {
			defer wg.Done()
			_ = o.ObservePacket(syn4(egressAddr, dest1Addr, 40000+i, 443, uint32(i)))
			_ = o.ObservePacket(synAck4(dest1Addr, egressAddr, 443, 40000+i, uint32(i)+1))
			_ = o.ObservePacket(udp4(egressAddr, dest3Addr, 50000+i, 443))
			o.Snapshots()
			o.EvictStalePending(time.Second)
		}(uint16(i))
	}
	wg.Wait()
}
