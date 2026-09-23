package tunnel

import (
	"fmt"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/ngthdong/egressa/pkg/wire"
)

// sessionBind wraps a real conn.Bind, prepending a wire.SessionHeader to
// every outbound UDP datagram and stripping it off every inbound one, in
// the datagram's cleartext framing, outside WireGuard's own encryption.
type sessionBind struct {
	real      conn.Bind
	sessionID uint64
	epoch     uint32
	seq       atomic.Uint64

	onRecv func(wire.SessionHeader)
}

func newSessionBind(real conn.Bind, sessionID uint64, epoch uint32, onRecv func(wire.SessionHeader)) *sessionBind {
	return &sessionBind{real: real, sessionID: sessionID, epoch: epoch, onRecv: onRecv}
}

func (b *sessionBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.real.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrapped[i] = b.wrapReceiveFunc(fn)
	}
	return wrapped, actualPort, nil
}

func (b *sessionBind) wrapReceiveFunc(real conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := real(packets, sizes, eps)
		if err != nil {
			return n, err
		}

		out := 0
		for i := 0; i < n; i++ {
			data := packets[i][:sizes[i]]
			if len(data) < wire.SessionHeaderSize {
				continue
			}
			h, consumed, err := wire.Decode(data)
			if err != nil {
				continue
			}
			if b.onRecv != nil {
				b.onRecv(h)
			}

			rest := data[consumed:]
			copy(packets[out], rest)
			sizes[out] = len(rest)
			eps[out] = eps[i]
			out++
		}
		return out, nil
	}
}

func (b *sessionBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	framed := make([][]byte, len(bufs))
	for i, buf := range bufs {
		h := wire.SessionHeader{
			Version:    wire.Version,
			Type:       wire.PacketTypeData,
			Direction:  wire.DirUpstream,
			SessionID:  b.sessionID,
			Epoch:      b.epoch,
			SessionSeq: b.seq.Add(1),
		}
		out := make([]byte, wire.SessionHeaderSize+len(buf))
		if err := h.EncodeTo(out[:wire.SessionHeaderSize]); err != nil {
			return fmt.Errorf("tunnel: encode session header: %w", err)
		}
		copy(out[wire.SessionHeaderSize:], buf)
		framed[i] = out
	}
	return b.real.Send(framed, ep)
}

func (b *sessionBind) Close() error                                  { return b.real.Close() }
func (b *sessionBind) SetMark(mark uint32) error                     { return b.real.SetMark(mark) }
func (b *sessionBind) ParseEndpoint(s string) (conn.Endpoint, error) { return b.real.ParseEndpoint(s) }
func (b *sessionBind) BatchSize() int                                { return b.real.BatchSize() }
