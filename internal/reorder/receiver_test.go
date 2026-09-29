package reorder

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

func TestDropReason_String(t *testing.T) {
	cases := map[DropReason]string{
		NotDropped:      "not dropped",
		DropEpochStale:  "epoch stale",
		DropDuplicate:   "duplicate",
		DropOutOfWindow: "out of window",
		DropReason(99):  "DropReason(99)",
	}
	for reason, want := range cases {
		if got := reason.String(); got != want {
			t.Errorf("DropReason(%d).String() = %q, want %q", int(reason), got, want)
		}
	}
}

func pkt(epoch, seq uint64) Packet {
	return Packet{Epoch: epoch, Seq: seq, Payload: []byte(fmt.Sprintf("D%04d", seq))}
}

func TestReceiver_DeliversInOrderPacketsImmediately(t *testing.T) {
	r := NewReceiver(DefaultConfig, 1, 0)

	for seq := uint64(1); seq <= 3; seq++ {
		out, reason := r.Receive(pkt(1, seq))
		if reason != NotDropped {
			t.Fatalf("seq %d: reason = %v, want %v", seq, reason, NotDropped)
		}
		if len(out) != 1 || out[0].Seq != seq {
			t.Fatalf("seq %d: delivered = %+v, want exactly [seq %d]", seq, out, seq)
		}
	}
	if got := r.Delivered(); got != 3 {
		t.Fatalf("Delivered() = %d, want 3", got)
	}
	if got := r.PendingCount(); got != 0 {
		t.Fatalf("PendingCount() = %d, want 0", got)
	}
}

func TestReceiver_DuplicateExactRepeat_Dropped(t *testing.T) {
	r := NewReceiver(DefaultConfig, 1, 0)
	if _, reason := r.Receive(pkt(1, 1)); reason != NotDropped {
		t.Fatalf("first delivery: reason = %v", reason)
	}
	out, reason := r.Receive(pkt(1, 1))
	if reason != DropDuplicate {
		t.Fatalf("resend of an already-delivered seq: reason = %v, want %v", reason, DropDuplicate)
	}
	if out != nil {
		t.Fatalf("dropped packet returned non-nil deliverable: %+v", out)
	}
}

func TestReceiver_DuplicatePending_Dropped(t *testing.T) {
	r := NewReceiver(DefaultConfig, 1, 0)
	// seq 2 arrives first, leaving a gap at seq 1: it must sit pending,
	// not be delivered.
	if out, reason := r.Receive(pkt(1, 2)); reason != NotDropped || out != nil {
		t.Fatalf("Receive(seq 2): out=%+v reason=%v, want nil/NotDropped (buffered pending the gap)", out, reason)
	}
	if got := r.PendingCount(); got != 1 {
		t.Fatalf("PendingCount() = %d, want 1", got)
	}
	// A retransmit of the same still-pending seq 2 is a duplicate, not
	// a second buffered copy.
	out, reason := r.Receive(pkt(1, 2))
	if reason != DropDuplicate {
		t.Fatalf("resend of a pending seq: reason = %v, want %v", reason, DropDuplicate)
	}
	if out != nil {
		t.Fatalf("dropped packet returned non-nil deliverable: %+v", out)
	}
	if got := r.PendingCount(); got != 1 {
		t.Fatalf("PendingCount() after the duplicate = %d, want unchanged 1", got)
	}
}

func TestReceiver_ReordersWithinWindow(t *testing.T) {
	r := NewReceiver(Config{WindowSize: 4}, 1, 0)

	if out, reason := r.Receive(pkt(1, 3)); reason != NotDropped || out != nil {
		t.Fatalf("Receive(seq 3): out=%+v reason=%v, want buffered", out, reason)
	}
	if out, reason := r.Receive(pkt(1, 2)); reason != NotDropped || out != nil {
		t.Fatalf("Receive(seq 2): out=%+v reason=%v, want buffered", out, reason)
	}
	// seq 1 fills the gap and must drain 1, 2, 3 in order in one call.
	out, reason := r.Receive(pkt(1, 1))
	if reason != NotDropped {
		t.Fatalf("Receive(seq 1): reason = %v", reason)
	}
	if len(out) != 3 {
		t.Fatalf("Receive(seq 1) drained %d packets, want 3", len(out))
	}
	for i, want := range []uint64{1, 2, 3} {
		if out[i].Seq != want {
			t.Fatalf("drained[%d].Seq = %d, want %d (must be in order)", i, out[i].Seq, want)
		}
	}
	if got := r.PendingCount(); got != 0 {
		t.Fatalf("PendingCount() after draining = %d, want 0", got)
	}
}

func TestReceiver_OutOfWindow_Dropped(t *testing.T) {
	r := NewReceiver(Config{WindowSize: 2}, 1, 0)
	// Next expected is seq 1; seq 1+2+1=4 is the farthest still
	// admissible (WindowSize=2 => up to 2 past the next expected 1, so
	// seq 1,2,3 admissible, seq 4 is not).
	out, reason := r.Receive(pkt(1, 4))
	if reason != DropOutOfWindow {
		t.Fatalf("Receive(seq 4) with WindowSize=2: reason = %v, want %v", reason, DropOutOfWindow)
	}
	if out != nil {
		t.Fatalf("dropped packet returned non-nil deliverable: %+v", out)
	}
	if got := r.PendingCount(); got != 0 {
		t.Fatalf("PendingCount() = %d, want 0 (nothing should have been buffered)", got)
	}
	// The boundary case, seq 3, must be admitted (buffered).
	if _, reason := r.Receive(pkt(1, 3)); reason != NotDropped {
		t.Fatalf("Receive(seq 3), the window's boundary: reason = %v, want %v", reason, NotDropped)
	}
}

func TestReceiver_EpochStale_RejectsEvenAFreshNeverSeenSeq(t *testing.T) {
	// The "zombie owner" case: a packet claiming a seq number that was
	// never actually delivered before, but stamped with an epoch that
	// has already been superseded. Seq-based dedup alone would happily
	// admit this (it isn't a repeat of anything); only the epoch fence
	// catches it.
	r := NewReceiver(DefaultConfig, 5, 0)
	r.AdvanceEpoch(6)

	out, reason := r.Receive(Packet{Epoch: 5, Seq: 500, Payload: []byte("zombie")})
	if reason != DropEpochStale {
		t.Fatalf("reason = %v, want %v", reason, DropEpochStale)
	}
	if out != nil {
		t.Fatalf("dropped packet returned non-nil deliverable: %+v", out)
	}
	if got := r.PendingCount(); got != 0 {
		t.Fatalf("PendingCount() = %d, want 0 (a stale-epoch packet must never enter the reorder buffer)", got)
	}
}

func TestReceiver_AdvanceEpoch_NeverRegresses(t *testing.T) {
	r := NewReceiver(DefaultConfig, 5, 0)
	r.AdvanceEpoch(6)
	r.AdvanceEpoch(3) // must be ignored
	if got := r.CurrentEpoch(); got != 6 {
		t.Fatalf("CurrentEpoch() = %d, want unchanged 6 after a regressive AdvanceEpoch", got)
	}
	if _, reason := r.Receive(pkt(6, 1)); reason != NotDropped {
		t.Fatalf("Receive at the true current epoch: reason = %v, want %v", reason, NotDropped)
	}
}

func TestReceiver_SeedsFromTransferredSeqHighWater(t *testing.T) {
	r := NewReceiver(DefaultConfig, 1, 50)

	if _, reason := r.Receive(pkt(1, 50)); reason != DropDuplicate {
		t.Fatalf("Receive(seq 50) at the seeded high-water: reason = %v, want %v", reason, DropDuplicate)
	}
	if _, reason := r.Receive(pkt(1, 10)); reason != DropDuplicate {
		t.Fatalf("Receive(seq 10), below the seeded high-water: reason = %v, want %v", reason, DropDuplicate)
	}
	out, reason := r.Receive(pkt(1, 51))
	if reason != NotDropped || len(out) != 1 || out[0].Seq != 51 {
		t.Fatalf("Receive(seq 51), the first genuinely new packet: out=%+v reason=%v", out, reason)
	}
}

func TestReceiver_WindowBoundsPendingMapSize(t *testing.T) {
	r := NewReceiver(Config{WindowSize: 3}, 1, 0)
	// Feed every admissible out-of-order seq (2..4, next expected is 1)
	// plus one that should be rejected as out of window (5).
	for _, seq := range []uint64{2, 3, 4} {
		if _, reason := r.Receive(pkt(1, seq)); reason != NotDropped {
			t.Fatalf("Receive(seq %d): reason = %v, want %v", seq, reason, NotDropped)
		}
	}
	if _, reason := r.Receive(pkt(1, 5)); reason != DropOutOfWindow {
		t.Fatalf("Receive(seq 5): reason = %v, want %v", reason, DropOutOfWindow)
	}
	if got := r.PendingCount(); got != 3 {
		t.Fatalf("PendingCount() = %d, want 3 (bounded to WindowSize)", got)
	}
}

func TestReceiver_ConcurrentReceives_NoDuplicateNoRace(t *testing.T) {
	// Packets arriving from two overlapping paths (old access gateway's
	// tail, new access gateway's head) funneling into one Receiver
	// concurrently must still add up to exactly one delivery per Seq,
	// with no data race.
	r := NewReceiver(Config{WindowSize: 200}, 1, 0)
	const n = 100

	var mu sync.Mutex
	seen := make(map[uint64]int)
	var wg sync.WaitGroup
	// Every seq is sent exactly twice, from two different goroutines,
	// modeling the same packet reaching the merge point via both paths.
	for path := 0; path < 2; path++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for seq := uint64(1); seq <= n; seq++ {
				out, _ := r.Receive(pkt(1, seq))
				mu.Lock()
				for _, p := range out {
					seen[p.Seq]++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if got := r.Delivered(); got != n {
		t.Fatalf("Delivered() = %d, want %d", got, n)
	}
	for seq := uint64(1); seq <= n; seq++ {
		if seen[seq] != 1 {
			t.Fatalf("seq %d delivered %d times, want exactly 1", seq, seen[seq])
		}
	}
}

func TestReceiver_TCPStreamSurvivesCutover(t *testing.T) {
	const oldCount = 100 // seq 1..100, epoch 5 (pre-cutover)
	const newCount = 100 // seq 101..200, epoch 6 (post-cutover)
	const total = oldCount + newCount

	// The original stream this session is carrying, split into
	// fixed-width chunks so reconstruction can be checked byte for
	// byte.
	var want bytes.Buffer
	for seq := uint64(1); seq <= total; seq++ {
		want.Write(pkt(0, seq).Payload)
	}

	// Build the OLD-epoch arrival order: mostly sequential, with local
	// jitter (adjacent pairs swapped every few packets) to model
	// ordinary network reordering; entirely within epoch 5, since a
	// well-behaved client only starts stamping epoch 6 once it has
	// itself completed the handoff.
	oldArrival := make([]Packet, 0, oldCount)
	for seq := uint64(1); seq <= oldCount; seq++ {
		oldArrival = append(oldArrival, pkt(5, seq))
	}
	for i := 0; i+1 < len(oldArrival); i += 4 {
		oldArrival[i], oldArrival[i+1] = oldArrival[i+1], oldArrival[i]
	}

	// The NEW-epoch arrival order, same jitter pattern, epoch 6.
	newArrival := make([]Packet, 0, newCount)
	for seq := uint64(oldCount + 1); seq <= total; seq++ {
		newArrival = append(newArrival, pkt(6, seq))
	}
	for i := 0; i+1 < len(newArrival); i += 4 {
		newArrival[i], newArrival[i+1] = newArrival[i+1], newArrival[i]
	}

	r := NewReceiver(Config{WindowSize: 8}, 5, 0)

	var got bytes.Buffer
	feed := func(p Packet) {
		out, reason := r.Receive(p)
		if reason != NotDropped {
			t.Fatalf("legitimate packet seq %d epoch %d was dropped: %v", p.Seq, p.Epoch, reason)
		}
		for _, d := range out {
			got.Write(d.Payload)
		}
	}

	// Feed the whole pre-cutover stream, including one retransmit
	// duplicate partway through (an ordinary retransmit, nothing to do
	// with the cutover yet).
	for i, p := range oldArrival {
		feed(p)
		if i == 40 {
			if _, reason := r.Receive(oldArrival[35]); reason != DropDuplicate {
				t.Fatalf("retransmit duplicate mid-stream: reason = %v, want %v", reason, DropDuplicate)
			}
		}
	}

	r.AdvanceEpoch(6)

	// Feed the whole post-cutover stream, again with one retransmit
	// duplicate thrown in, plus a stale-epoch retransmit of an
	// already-delivered pre-cutover packet arriving late.
	if _, reason := r.Receive(pkt(5, 99)); reason != DropDuplicate && reason != DropEpochStale {
		t.Fatalf("a late duplicate of an already-delivered pre-cutover packet: reason = %v, want %v or %v", reason, DropDuplicate, DropEpochStale)
	}
	for i, p := range newArrival {
		feed(p)
		if i == 40 {
			if _, reason := r.Receive(newArrival[35]); reason != DropDuplicate {
				t.Fatalf("retransmit duplicate mid-stream (post-cutover): reason = %v, want %v", reason, DropDuplicate)
			}
		}
	}

	if got.String() != want.String() {
		t.Fatalf("reconstructed stream does not match the original: got %d bytes, want %d bytes", got.Len(), want.Len())
	}
	if delivered := r.Delivered(); delivered != total {
		t.Fatalf("Delivered() = %d, want %d (every packet in the stream accounted for)", delivered, total)
	}
	if pending := r.PendingCount(); pending != 0 {
		t.Fatalf("PendingCount() = %d, want 0 once the whole stream has drained", pending)
	}
}
