// Package wire defines the on-the-wire contract shared by every component
// of the system: client, gateway, and controller. Nothing outside this
// package may define a competing packet or control-message format — this
// is the single source of truth for "what a byte on the network means".
//
// There are two distinct encodings in this package, deliberately different:
//
//   - SessionHeader (this file) is the DATA-PLANE inner header. It rides
//     inside every tunnel packet (once wireguard-go is wired in),
//     so it is encoded/decoded per-packet, at line rate. It MUST be
//     fixed-size, allocation-free, and use explicit byte order. There is
//     no room here for reflection-based encoders (JSON, gob) without
//     paying a real throughput cost.
//
//   - Message (message.go) is the CONTROL-PLANE envelope
//     (PREPARE, READY, COMMIT, ...). Control messages are low-rate (a
//     handful per migration, not per packet), so that file deliberately
//     trades a little performance for debuggability and uses a
//     human-readable envelope instead.
//
// Conflating these two encodings is the single most common mistake
package wire

import (
	"encoding/binary"
	"fmt"
)

// SessionHeaderSize is the fixed, wire-exact size of an encoded SessionHeader,
// in bytes. Any change to this constant is a wire-format break and must bump
// Version.
const SessionHeaderSize = 24

// Version is the current wire-format version this build encodes. Decoders
// MUST accept any Version <= the version they understand and MUST NOT
// reject a packet solely for carrying a newer Version than expected, see
// Decode's forward-compatibility note.
const Version uint8 = 1

type PacketType uint8

const (
	PacketTypeData      PacketType = 0
	PacketTypeProbe     PacketType = 1
	PacketTypeKeepalive PacketType = 2
)

func (t PacketType) String() string {
	switch t {
	case PacketTypeData:
		return "DATA"
	case PacketTypeProbe:
		return "PROBE"
	case PacketTypeKeepalive:
		return "KEEPALIVE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", uint8(t))
	}
}

// Direction indicates which way a packet is travelling relative to the
// client. It is stored as a single bit in Flags rather than its own byte,
// see the "why a bit, not a byte" gotcha in header_test.go.
type Direction uint8

const (
	DirUpstream   Direction = 0 // client -> access
	DirDownstream Direction = 1 // access -> client
)

const flagDirectionBit = 1 << 0

// SessionHeader is the fixed 24-byte inner header carried by every
// data-plane datagram. Layout (all integers big-endian / network byte
// order, per RFC 1700 convention):
//
//	offset  size  field
//	0       1     Version
//	1       1     Type        (PacketType)
//	2       1     Flags       (bit0 = Direction; bits1-7 reserved, must be 0)
//	3       1     Reserved    (must be 0 on encode; ignored on decode)
//	4       8     SessionID
//	12      4     Epoch
//	16      8     SessionSeq
//
// SessionID is the stable logical-session identity and does NOT change
// across access/egress migration.
// Epoch is the fencing token: it changes exactly once per
// migration commit, and a receiver holding a higher epoch MUST reject a
// packet carrying a lower one. SessionSeq is the per-session sequence
// number used for cutover-time dedup/reorder. Tt is NOT a
// per-tunnel replay counter (that lives inside wireguard-go itself, one
// layer below this header).
type SessionHeader struct {
	Version    uint8
	Type       PacketType
	Direction  Direction
	SessionID  uint64
	Epoch      uint32
	SessionSeq uint64
}

// Encode serializes h into a newly allocated SessionHeaderSize-byte slice.
// Prefer EncodeTo on the data-plane hot path to avoid the allocation.
func (h SessionHeader) Encode() []byte {
	buf := make([]byte, SessionHeaderSize)
	// EncodeTo cannot fail for a correctly sized buffer; the error is
	// impossible here, but we still check it rather than discard it, so a
	// future refactor that CAN fail doesn't silently regress.
	if err := h.EncodeTo(buf); err != nil {
		panic(err) // unreachable with a freshly allocated correctly-sized buf
	}
	return buf
}

func (h SessionHeader) EncodeTo(buf []byte) error {
	if len(buf) < SessionHeaderSize {
		return fmt.Errorf("wire: EncodeTo: buffer too small: have %d bytes, need %d", len(buf), SessionHeaderSize)
	}
	buf[0] = h.Version
	buf[1] = uint8(h.Type)

	var flags uint8
	if h.Direction == DirDownstream {
		flags |= flagDirectionBit
	}
	buf[2] = flags
	buf[3] = 0 // reserved, must be zero on the wire

	binary.BigEndian.PutUint64(buf[4:12], h.SessionID)
	binary.BigEndian.PutUint32(buf[12:16], h.Epoch)
	binary.BigEndian.PutUint64(buf[16:24], h.SessionSeq)
	return nil
}

func Decode(buf []byte) (SessionHeader, int, error) {
	if len(buf) < SessionHeaderSize {
		return SessionHeader{}, 0, fmt.Errorf("wire: Decode: short buffer: have %d bytes, need %d", len(buf), SessionHeaderSize)
	}

	flags := buf[2]
	dir := DirUpstream
	if flags&flagDirectionBit != 0 {
		dir = DirDownstream
	}

	h := SessionHeader{
		Version:    buf[0],
		Type:       PacketType(buf[1]),
		Direction:  dir,
		SessionID:  binary.BigEndian.Uint64(buf[4:12]),
		Epoch:      binary.BigEndian.Uint32(buf[12:16]),
		SessionSeq: binary.BigEndian.Uint64(buf[16:24]),
	}
	return h, SessionHeaderSize, nil
}
