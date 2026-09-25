package tunnel

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

type FlowProto uint8

const (
	ProtoICMP   FlowProto = 1
	ProtoTCP    FlowProto = 6
	ProtoUDP    FlowProto = 17
	ProtoICMPv6 FlowProto = 58
)

type FlowKey struct {
	Proto   FlowProto
	SrcAddr netip.Addr
	SrcPort uint16
	DstAddr netip.Addr
	DstPort uint16
}

func (k FlowKey) String() string {
	return fmt.Sprintf("proto=%d %s:%d->%s:%d", k.Proto, k.SrcAddr, k.SrcPort, k.DstAddr, k.DstPort)
}

// Reverse returns the key for a reply travelling the opposite direction of k.
func (k FlowKey) Reverse() FlowKey {
	return FlowKey{Proto: k.Proto, SrcAddr: k.DstAddr, SrcPort: k.DstPort, DstAddr: k.SrcAddr, DstPort: k.SrcPort}
}

func ParseFlowKey(packet []byte) (FlowKey, error) {
	if len(packet) < 1 {
		return FlowKey{}, fmt.Errorf("tunnel: empty packet")
	}
	switch packet[0] >> 4 {
	case 4:
		return parseFlowKeyIPv4(packet)
	case 6:
		return parseFlowKeyIPv6(packet)
	default:
		return FlowKey{}, fmt.Errorf("tunnel: unrecognized IP version %d", packet[0]>>4)
	}
}

func parseFlowKeyIPv4(packet []byte) (FlowKey, error) {
	if len(packet) < 20 {
		return FlowKey{}, fmt.Errorf("tunnel: IPv4 packet too short (%d bytes)", len(packet))
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return FlowKey{}, fmt.Errorf("tunnel: invalid IPv4 header length %d (packet %d bytes)", ihl, len(packet))
	}
	proto := FlowProto(packet[9])
	key := FlowKey{
		Proto:   proto,
		SrcAddr: netip.AddrFrom4([4]byte(packet[12:16])),
		DstAddr: netip.AddrFrom4([4]byte(packet[16:20])),
	}
	switch proto {
	case ProtoTCP, ProtoUDP:
		if err := setPorts(&key, packet[ihl:]); err != nil {
			return FlowKey{}, err
		}
	case ProtoICMP:
		// no ports
	default:
		return FlowKey{}, fmt.Errorf("tunnel: unsupported IPv4 protocol %d", proto)
	}
	return key, nil
}

func parseFlowKeyIPv6(packet []byte) (FlowKey, error) {
	const ipv6HeaderLen = 40
	if len(packet) < ipv6HeaderLen {
		return FlowKey{}, fmt.Errorf("tunnel: IPv6 packet too short (%d bytes)", len(packet))
	}
	proto := FlowProto(packet[6])
	key := FlowKey{
		Proto:   proto,
		SrcAddr: netip.AddrFrom16([16]byte(packet[8:24])),
		DstAddr: netip.AddrFrom16([16]byte(packet[24:40])),
	}
	switch proto {
	case ProtoTCP, ProtoUDP:
		if err := setPorts(&key, packet[ipv6HeaderLen:]); err != nil {
			return FlowKey{}, err
		}
	case ProtoICMPv6:
		// no ports
	default:
		return FlowKey{}, fmt.Errorf("tunnel: unsupported IPv6 next header %d", proto)
	}
	return key, nil
}

func setPorts(key *FlowKey, transport []byte) error {
	if len(transport) < 4 {
		return fmt.Errorf("tunnel: transport header too short (%d bytes) for proto %d", len(transport), key.Proto)
	}
	key.SrcPort = binary.BigEndian.Uint16(transport[0:2])
	key.DstPort = binary.BigEndian.Uint16(transport[2:4])
	return nil
}

type FlowPolicy func(FlowKey) (egressID string)

func StaticEgressPolicy(egressID string) FlowPolicy {
	return func(FlowKey) string { return egressID }
}

type FlowEntry struct {
	EgressID  string
	CreatedAt time.Time
	LastSeen  time.Time
}

// FlowTable pins each flow to the egress it was assigned when it was
// first seen, and keeps returning that same egress for every later
// packet of that flow. A FlowTable is safe for concurrent use.
type FlowTable struct {
	mu      sync.Mutex
	flows   map[FlowKey]*FlowEntry
	policy  FlowPolicy
	idleTTL time.Duration
	now     func() time.Time
}

func NewFlowTable(policy FlowPolicy, idleTTL time.Duration) *FlowTable {
	return &FlowTable{
		flows:   make(map[FlowKey]*FlowEntry),
		policy:  policy,
		idleTTL: idleTTL,
		now:     time.Now,
	}
}

func (t *FlowTable) Egress(key FlowKey) string {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	entry, ok := t.flows[key]
	if !ok {
		entry = &FlowEntry{EgressID: t.policy(key), CreatedAt: now}
		t.flows[key] = entry
	}
	entry.LastSeen = now
	return entry.EgressID
}

func (t *FlowTable) Lookup(key FlowKey) (egressID string, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.flows[key]
	if !ok {
		return "", false
	}
	return entry.EgressID, true
}

func (t *FlowTable) Snapshot(key FlowKey) (entry FlowEntry, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.flows[key]
	if !ok {
		return FlowEntry{}, false
	}
	return *e, true
}

func (t *FlowTable) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.flows)
}

func (t *FlowTable) EvictIdle() int {
	if t.idleTTL <= 0 {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := t.now().Add(-t.idleTTL)
	removed := 0
	for key, entry := range t.flows {
		if entry.LastSeen.Before(cutoff) {
			delete(t.flows, key)
			removed++
		}
	}
	return removed
}
