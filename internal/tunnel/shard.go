package tunnel

import (
	"runtime"
	"sync"
	"time"
)

func hashFlowKey(key FlowKey) uint64 {
	const offset64 = 14695981039346656037
	const prime64 = 1099511628211

	h := uint64(offset64)
	h = (h ^ uint64(key.Proto)) * prime64
	src := key.SrcAddr.As16()
	for _, b := range src {
		h = (h ^ uint64(b)) * prime64
	}
	h = (h ^ uint64(key.SrcPort)) * prime64
	dst := key.DstAddr.As16()
	for _, b := range dst {
		h = (h ^ uint64(b)) * prime64
	}
	h = (h ^ uint64(key.DstPort)) * prime64
	return h
}

type ShardedFlowTable struct {
	shards []*FlowTable
}

func NewShardedFlowTable(shardCount int, policy FlowPolicy, idleTTL time.Duration) *ShardedFlowTable {
	if shardCount <= 0 {
		shardCount = runtime.NumCPU()
	}
	shards := make([]*FlowTable, shardCount)
	for i := range shards {
		shards[i] = NewFlowTable(policy, idleTTL)
	}
	return &ShardedFlowTable{shards: shards}
}

func (s *ShardedFlowTable) ShardCount() int {
	return len(s.shards)
}

func (s *ShardedFlowTable) ShardIndex(key FlowKey) int {
	return int(hashFlowKey(key) % uint64(len(s.shards)))
}

func (s *ShardedFlowTable) Shard(i int) *FlowTable {
	return s.shards[i]
}

func (s *ShardedFlowTable) Egress(key FlowKey) string {
	return s.shards[s.ShardIndex(key)].Egress(key)
}

func (s *ShardedFlowTable) Lookup(key FlowKey) (egressID string, ok bool) {
	return s.shards[s.ShardIndex(key)].Lookup(key)
}

func (s *ShardedFlowTable) Snapshot(key FlowKey) (entry FlowEntry, ok bool) {
	return s.shards[s.ShardIndex(key)].Snapshot(key)
}

func (s *ShardedFlowTable) Len() int {
	total := 0
	for _, shard := range s.shards {
		total += shard.Len()
	}
	return total
}

func (s *ShardedFlowTable) EvictIdle() int {
	total := 0
	for _, shard := range s.shards {
		total += shard.EvictIdle()
	}
	return total
}

// FastPathDecide parses the packet flow key and resolves its pinned egress.
func FastPathDecide(table *ShardedFlowTable, packet []byte) (FlowKey, string, error) {
	key, err := ParseFlowKey(packet)
	if err != nil {
		return FlowKey{}, "", err
	}
	return key, table.Egress(key), nil
}

// PacketBatch is a reusable collection of packet slices processed together.
// It does not copy packet data; callers retain ownership of the backing arrays.
type PacketBatch struct {
	packets [][]byte
}

func NewPacketBatch(capacity int) *PacketBatch {
	return &PacketBatch{packets: make([][]byte, 0, capacity)}
}

func (b *PacketBatch) Reset() {
	b.packets = b.packets[:0]
}

func (b *PacketBatch) Add(pkt []byte) bool {
	if len(b.packets) >= cap(b.packets) {
		return false
	}
	b.packets = append(b.packets, pkt)
	return true
}

func (b *PacketBatch) Packets() [][]byte {
	return b.packets
}

func (b *PacketBatch) Len() int {
	return len(b.packets)
}

func (b *PacketBatch) Cap() int {
	return cap(b.packets)
}

type WorkerPool struct {
	table   *ShardedFlowTable
	handle  func(workerID int, key FlowKey, egress string, pkt []byte)
	scratch []*PacketBatch
	used    []bool
	work    []chan *PacketBatch
	done    []chan struct{}
	quit    chan struct{}
	wg      sync.WaitGroup
}

func NewWorkerPool(
	table *ShardedFlowTable,
	batchCapacity int,
	handle func(workerID int, key FlowKey, egress string, pkt []byte),
) *WorkerPool {
	n := table.ShardCount()
	p := &WorkerPool{
		table:   table,
		handle:  handle,
		scratch: make([]*PacketBatch, n),
		used:    make([]bool, n),
		work:    make([]chan *PacketBatch, n),
		done:    make([]chan struct{}, n),
		quit:    make(chan struct{}),
	}
	for i := 0; i < n; i++ {
		p.scratch[i] = NewPacketBatch(batchCapacity)
		p.work[i] = make(chan *PacketBatch)
		p.done[i] = make(chan struct{})
		p.wg.Add(1)
		go p.runWorker(i)
	}
	return p
}

func (p *WorkerPool) runWorker(id int) {
	defer p.wg.Done()
	shard := p.table.Shard((id))
	for {
		select {
		case batch := <-p.work[id]:
			for _, pkt := range batch.Packets() {
				key, err := ParseFlowKey(pkt)
				if err != nil {
					continue
				}
				egress := shard.Egress(key)
				p.handle(id, key, egress, pkt)
			}
			p.done[id] <- struct{}{}
		case <-p.quit:
			return
		}
	}
}

// Submit distributes packets to shard workers by FlowKey and waits
// for all active workers to finish processing the batch.
// It reuses preallocated scratch batches and tracking state.
func (p *WorkerPool) Submit(batch *PacketBatch) {
	for i, s := range p.scratch {
		s.Reset()
		p.used[i] = false
	}
	for _, pkt := range batch.Packets() {
		key, err := ParseFlowKey(pkt)
		if err != nil {
			continue
		}

		id := p.table.ShardIndex(key)
		if p.scratch[id].Add(pkt) {
			p.used[id] = true
		}
	}
	for i, used := range p.used {
		if used {
			p.work[i] <- p.scratch[i]
		}
	}
	for i, used := range p.used {
		if used {
			<-p.done[i]
		}
	}
}

func (p *WorkerPool) Close() {
	close(p.quit)
	p.wg.Wait()
}
