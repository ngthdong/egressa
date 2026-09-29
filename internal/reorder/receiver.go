package reorder

import (
	"fmt"
	"sort"
	"sync"
)

type Packet struct {
	Epoch   uint64
	Seq     uint64
	Payload []byte
}

type DropReason int

const (
	NotDropped DropReason = iota
	DropEpochStale
	DropDuplicate
	DropOutOfWindow
	DropClosed
)

func (r DropReason) String() string {
	switch r {
	case NotDropped:
		return "not dropped"
	case DropEpochStale:
		return "epoch stale"
	case DropDuplicate:
		return "duplicate"
	case DropOutOfWindow:
		return "out of window"
	default:
		return fmt.Sprintf("DropReason(%d)", int(r))
	}
}

type Config struct {
	WindowSize uint64 // bounds the reorder window
}

var DefaultConfig = Config{WindowSize: 64}

type Receiver struct {
	mu           sync.Mutex
	cfg          Config
	currentEpoch uint64
	delivered    uint64 // highest Seq delivered so far
	pending      map[uint64]Packet
	closed       bool
}

func NewReceiver(cfg Config, epoch uint64, seedSeq uint64) *Receiver {
	return &Receiver{
		cfg:          cfg,
		currentEpoch: epoch,
		delivered:    seedSeq,
		pending:      make(map[uint64]Packet),
	}
}

func (r *Receiver) AdvanceEpoch(epoch uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if epoch > r.currentEpoch {
		r.currentEpoch = epoch
	}
}

func (r *Receiver) Receive(pkt Packet) (deliverable []Packet, reason DropReason) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil, DropClosed
	}
	if pkt.Epoch < r.currentEpoch {
		return nil, DropEpochStale
	}
	if pkt.Seq <= r.delivered {
		return nil, DropDuplicate
	}
	if _, buffered := r.pending[pkt.Seq]; buffered {
		return nil, DropDuplicate
	}
	// pkt.Seq > r.delivered is established above, so this subtraction
	// cannot underflow.
	if pkt.Seq-r.delivered > r.cfg.WindowSize+1 {
		return nil, DropOutOfWindow
	}

	r.pending[pkt.Seq] = pkt

	var out []Packet
	for {
		next := r.delivered + 1
		p, ok := r.pending[next]
		if !ok {
			break
		}
		delete(r.pending, next)
		out = append(out, p)
		r.delivered = next
	}
	return out, NotDropped
}

func (r *Receiver) CurrentEpoch() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.currentEpoch
}

func (r *Receiver) Delivered() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.delivered
}

// PendingCount reports how many packets are currently buffered,
// waiting on an ealier gap.
func (r *Receiver) PendingCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

// Close stops the Receiver and returns packets still buffered at close.
func (r *Receiver) Close() (pendingAtClose []Packet) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true
	if len(r.pending) == 0 {
		return nil
	}

	seqs := make([]uint64, 0, len(r.pending))
	for seq := range r.pending {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

	out := make([]Packet, 0, len(seqs))
	for _, seq := range seqs {
		out = append(out, r.pending[seq])
		delete(r.pending, seq)
	}
	return out
}

func (r *Receiver) Closed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}
