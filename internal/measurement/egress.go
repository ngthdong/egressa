package measurement

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

const (
	protoTCP = 6
	protoUDP = 17
)

const (
	tcpFlagSYN = 0x02
	tcpFlagACK = 0x10
)

func parseIPHeader(packet []byte) (src, dst netip.Addr, proto uint8, payload []byte, err error) {
	if len(packet) < 1 {
		return netip.Addr{}, netip.Addr{}, 0, nil, fmt.Errorf("measurement: empty packet")
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return netip.Addr{}, netip.Addr{}, 0, nil, fmt.Errorf("measurement: IPv4 packet too short (%d bytes)", len(packet))
		}
		ihl := int(packet[0]&0x0f) * 4
		if ihl < 20 || len(packet) < ihl {
			return netip.Addr{}, netip.Addr{}, 0, nil, fmt.Errorf("measurement: invalid IPv4 header length %d (packet %d bytes)", ihl, len(packet))
		}
		return netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])), packet[9], packet[ihl:], nil
	case 6:
		const ipv6HeaderLen = 40
		if len(packet) < ipv6HeaderLen {
			return netip.Addr{}, netip.Addr{}, 0, nil, fmt.Errorf("measurement: IPv6 packet too short (%d bytes)", len(packet))
		}
		return netip.AddrFrom16([16]byte(packet[8:24])), netip.AddrFrom16([16]byte(packet[24:40])), packet[6], packet[ipv6HeaderLen:], nil
	default:
		return netip.Addr{}, netip.Addr{}, 0, nil, fmt.Errorf("measurement: unrecognized IP version %d", packet[0]>>4)
	}
}

type tcpSegment struct {
	SrcAddr netip.Addr
	SrcPort uint16
	DstAddr netip.Addr
	DstPort uint16
	Seq     uint32
	SYN     bool
	ACK     bool
}

type PrefixBits struct {
	IPv4 int
	IPv6 int
}

var DefaultPrefixBits = PrefixBits{IPv4: 24, IPv6: 48}

// Mask returns the prefix addr aggregates into.
func (b PrefixBits) Mask(addr netip.Addr) netip.Prefix {
	bits := b.IPv4
	if addr.Is6() && !addr.Is4In6() {
		bits = b.IPv6
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		// Fall back to the full address width for invalid configuration.
		p, _ = addr.Prefix(addr.BitLen())
	}
	return p
}

// Confidence marks how much an EgressObserver's PrefixStats sample for a
// destination prefix can be trusted.
type Confidence int

const (
	// ConfidenceNone indicates that no traffic has been observed.
	ConfidenceNone Confidence = iota

	// ConfidenceLow indicates that only UDP traffic has been observed.
	ConfidenceLow

	// ConfidenceHigh indicates that TCP handshake activity has been observed.
	ConfidenceHigh
)

func (c Confidence) String() string {
	switch c {
	case ConfidenceNone:
		return "none"
	case ConfidenceLow:
		return "low"
	case ConfidenceHigh:
		return "high"
	default:
		return fmt.Sprintf("Confidence(%d)", int(c))
	}
}

type PrefixStats struct {
	Prefix netip.Prefix

	// RTTMicros is the EWMA of completed TCP handshake RTTs.
	RTTMicros float64

	// Handshakes is the number of completed TCP handshake observations.
	Handshakes uint64

	// Retransmits is the number of observed SYN retransmissions.
	Retransmits uint64

	// UDPPackets is the number of observed UDP packets.
	UDPPackets uint64
}

func (s PrefixStats) Confidence() Confidence {
	if s.Handshakes > 0 || s.Retransmits > 0 {
		return ConfidenceHigh
	}
	if s.UDPPackets > 0 {
		return ConfidenceLow
	}
	return ConfidenceNone
}

// LossRate returns the observed SYN retransmission rate.
// It only reflects retransmissions visible to the observer; a SYN that is
// never answered or retransmitted is not included.
func (s PrefixStats) LossRate() float64 {
	total := s.Handshakes + s.Retransmits
	if total == 0 {
		return 0
	}
	return float64(s.Retransmits) / float64(total)
}

type fourTuple struct {
	SrcAddr, DstAddr netip.Addr
	SrcPort, DstPort uint16
}

type pendingHandshake struct {
	seq    uint32
	sentAt time.Time
}

// EgressObserver derives per-prefix TCP handshake RTT and retransmission
// metrics from observed IP/TCP/UDP headers without inspecting payloads.
type EgressObserver struct {
	mu       sync.Mutex
	prefix   PrefixBits
	outbound map[fourTuple]*pendingHandshake
	stats    map[netip.Prefix]*PrefixStats
	now      func() time.Time
}

func NewEgressObserver(prefix PrefixBits) *EgressObserver {
	return &EgressObserver{
		prefix:   prefix,
		outbound: make(map[fourTuple]*pendingHandshake),
		stats:    make(map[netip.Prefix]*PrefixStats),
		now:      time.Now,
	}
}

func (o *EgressObserver) ObservePacket(packet []byte) error {
	src, dst, proto, payload, err := parseIPHeader(packet)
	if err != nil {
		return err
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	switch proto {
	case protoTCP:
		if len(payload) < 14 {
			return fmt.Errorf("measurement: TCP header too short (%d bytes)", len(payload))
		}
		flags := payload[13]
		seg := tcpSegment{
			SrcAddr: src, SrcPort: binary.BigEndian.Uint16(payload[0:2]),
			DstAddr: dst, DstPort: binary.BigEndian.Uint16(payload[2:4]),
			Seq: binary.BigEndian.Uint32(payload[4:8]),
			SYN: flags&tcpFlagSYN != 0, ACK: flags&tcpFlagACK != 0,
		}
		o.observeTCPLocked(seg)
	case protoUDP:
		o.statsForLocked(dst).UDPPackets++
	}
	return nil
}

func (o *EgressObserver) observeTCPLocked(seg tcpSegment) {
	now := o.now()

	switch {
	case seg.SYN && !seg.ACK:
		key := fourTuple{SrcAddr: seg.SrcAddr, SrcPort: seg.SrcPort, DstAddr: seg.DstAddr, DstPort: seg.DstPort}
		if pending, ok := o.outbound[key]; ok && pending.seq == seg.Seq {
			// Repeated SYN with the same sequence number indicates a
			// retransmission of the same connection attempt.
			pending.sentAt = now
			o.statsForLocked(seg.DstAddr).Retransmits++
			return
		}

		o.outbound[key] = &pendingHandshake{seq: seg.Seq, sentAt: now}

	case seg.SYN && seg.ACK:
		// Reverse the tuple because the SYN-ACK travels in the opposite
		// direction from the original SYN.
		key := fourTuple{SrcAddr: seg.DstAddr, SrcPort: seg.DstPort, DstAddr: seg.SrcAddr, DstPort: seg.SrcPort}
		pending, ok := o.outbound[key]
		if !ok {
			return
		}

		delete(o.outbound, key)
		rtt := now.Sub(pending.sentAt)
		stats := o.statsForLocked(seg.SrcAddr)
		stats.Handshakes++
		if stats.Handshakes == 1 {
			stats.RTTMicros = float64(rtt.Microseconds())
		} else {
			stats.RTTMicros += (float64(rtt.Microseconds()) - stats.RTTMicros) * rttGain
		}
	}
}

func (o *EgressObserver) statsForLocked(addr netip.Addr) *PrefixStats {
	prefix := o.prefix.Mask(addr)
	s, ok := o.stats[prefix]
	if !ok {
		s = &PrefixStats{Prefix: prefix}
		o.stats[prefix] = s
	}
	return s
}

func (o *EgressObserver) Snapshot(prefix netip.Prefix) (PrefixStats, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	s, ok := o.stats[prefix]
	if !ok {
		return PrefixStats{}, false
	}
	return *s, true
}

func (o *EgressObserver) Snapshots() []PrefixStats {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]PrefixStats, 0, len(o.stats))
	for _, s := range o.stats {
		out = append(out, *s)
	}
	return out
}

// EvictStalePending removes outstanding SYNs older than ttl.
// Stale entries are not counted as loss because the observer cannot
// distinguish an unanswered SYN from a destination that was never reached.
func (o *EgressObserver) EvictStalePending(ttl time.Duration) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	cutoff := o.now().Add(-ttl)
	removed := 0
	for key, p := range o.outbound {
		if p.sentAt.Before(cutoff) {
			delete(o.outbound, key)
			removed++
		}
	}
	return removed
}
