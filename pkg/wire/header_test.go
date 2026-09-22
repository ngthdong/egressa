package wire

import (
	"bytes"
	"testing"
)

func TestSessionHeader_RoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   SessionHeader
	}{
		{
			name: "zero value",
			in:   SessionHeader{},
		},
		{
			name: "typical upstream data packet",
			in: SessionHeader{
				Version:    Version,
				Type:       PacketTypeData,
				Direction:  DirUpstream,
				SessionID:  0x0123456789ABCDEF,
				Epoch:      42,
				SessionSeq: 1_000_000,
			},
		},
		{
			name: "downstream, max values (overflow boundary check)",
			in: SessionHeader{
				Version:    255,
				Type:       PacketTypeKeepalive,
				Direction:  DirDownstream,
				SessionID:  ^uint64(0),
				Epoch:      ^uint32(0),
				SessionSeq: ^uint64(0),
			},
		},
		{
			name: "probe packet",
			in: SessionHeader{
				Version:    Version,
				Type:       PacketTypeProbe,
				Direction:  DirUpstream,
				SessionID:  7,
				Epoch:      0,
				SessionSeq: 0,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := tc.in.Encode()
			if len(encoded) != SessionHeaderSize {
				t.Fatalf("Encode: got %d bytes, want %d", len(encoded), SessionHeaderSize)
			}

			got, n, err := Decode(encoded)
			if err != nil {
				t.Fatalf("Decode returned error: %v", err)
			}
			if n != SessionHeaderSize {
				t.Fatalf("Decode consumed %d bytes, want %d", n, SessionHeaderSize)
			}
			if got != tc.in {
				t.Fatalf("round-trip mismatch:\n  in:  %+v\n  out: %+v", tc.in, got)
			}
		})
	}
}

// TestSessionHeader_WireLayout pins the exact byte layout. If this test
// ever needs to change, that change IS a wire-format break: every other
// component (client, gateway, controller — and anything already deployed)
// must be recompiled and redeployed together. Treat a diff here as a
// five-alarm review item, not a routine refactor.
func TestSessionHeader_WireLayout(t *testing.T) {
	h := SessionHeader{
		Version:    1,
		Type:       PacketTypeData,
		Direction:  DirDownstream,
		SessionID:  0x1122334455667788,
		Epoch:      0xAABBCCDD,
		SessionSeq: 0x99887766554433,
	}

	want := []byte{
		0x01,                                           // Version
		0x00,                                           // Type = Data
		0x01,                                           // Flags: direction bit set
		0x00,                                           // Reserved
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // SessionID
		0xAA, 0xBB, 0xCC, 0xDD, // Epoch
		0x00, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, // SessionSeq
	}

	got := h.Encode()
	if !bytes.Equal(got, want) {
		t.Fatalf("wire layout changed:\n got:  % X\n want: % X", got, want)
	}
}

func TestPacketType_String(t *testing.T) {
	cases := []struct {
		in   PacketType
		want string
	}{
		{PacketTypeData, "DATA"},
		{PacketTypeProbe, "PROBE"},
		{PacketTypeKeepalive, "KEEPALIVE"},
		{PacketType(99), "UNKNOWN(99)"},
	}
	for _, tc := range cases {
		if got := tc.in.String(); got != tc.want {
			t.Errorf("PacketType(%d).String() = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDecode_ShortBuffer(t *testing.T) {
	for _, n := range []int{0, 1, 8, SessionHeaderSize - 1} {
		buf := make([]byte, n)
		if _, _, err := Decode(buf); err == nil {
			t.Errorf("Decode with %d-byte buffer: expected error, got nil", n)
		}
	}
}

func TestEncodeTo_ShortBuffer(t *testing.T) {
	h := SessionHeader{SessionID: 1}
	buf := make([]byte, SessionHeaderSize-1)
	if err := h.EncodeTo(buf); err == nil {
		t.Error("EncodeTo with undersized buffer: expected error, got nil")
	}
}

// TestDecode_ForwardCompatible documents, deliberately, that a header
// claiming a newer Version than this build understands is still decoded.
// See the Decode doc comment for why this is a correctness requirement,
// not an oversight: it is what makes a rolling upgrade possible.
func TestDecode_ForwardCompatible(t *testing.T) {
	h := SessionHeader{Version: Version + 1, SessionID: 99}
	got, _, err := Decode(h.Encode())
	if err != nil {
		t.Fatalf("Decode rejected a newer Version: %v", err)
	}
	if got.Version != Version+1 {
		t.Fatalf("Version not preserved through decode: got %d", got.Version)
	}
}

// TestDecode_IgnoresReservedBits documents that Decode must not choke on
// reserved flag bits a future sender might legitimately set.
func TestDecode_IgnoresReservedBits(t *testing.T) {
	buf := SessionHeader{SessionID: 5, Direction: DirUpstream}.Encode()
	buf[2] |= 0b1111_1110 // set every reserved flag bit
	got, _, err := Decode(buf)
	if err != nil {
		t.Fatalf("Decode rejected reserved flag bits: %v", err)
	}
	if got.Direction != DirUpstream {
		t.Fatalf("reserved bits corrupted Direction: got %v", got.Direction)
	}
}

func FuzzSessionHeader_RoundTrip(f *testing.F) {
	seed := SessionHeader{
		Version: Version, Type: PacketTypeData, Direction: DirUpstream,
		SessionID: 1, Epoch: 1, SessionSeq: 1,
	}
	f.Add(seed.Encode())

	f.Fuzz(func(t *testing.T, data []byte) {
		h, n, err := Decode(data)
		if err != nil {
			return // short/invalid input is an expected outcome, not a bug
		}
		if n != SessionHeaderSize {
			t.Fatalf("Decode reported n=%d, want %d", n, SessionHeaderSize)
		}
		reEncoded := h.Encode()
		h2, _, err := Decode(reEncoded)
		if err != nil {
			t.Fatalf("re-decoding a freshly re-encoded header failed: %v", err)
		}
		if h2 != h {
			t.Fatalf("decode->encode->decode not idempotent:\n  first:  %+v\n  second: %+v", h, h2)
		}
	})
}

// BenchmarkEncodeTo pins the zero-allocation claim made in the doc comment.
// Run with: go test ./pkg/wire/ -bench=EncodeTo -benchmem
// A regression here (allocs/op > 0) means someone changed EncodeTo to
// allocate, which is a real cost on the per-packet hot path.
func BenchmarkEncodeTo(b *testing.B) {
	h := SessionHeader{Version: Version, SessionID: 1, Epoch: 1, SessionSeq: 1}
	buf := make([]byte, SessionHeaderSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.EncodeTo(buf)
	}
}
