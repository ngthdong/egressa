package tunnel

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestShardedFlowTable_PinsFlowStably(t *testing.T) {
	calls := 0
	policy := func(FlowKey) string {
		calls++
		return fmt.Sprintf("eg-%d", calls)
	}
	table := NewShardedFlowTable(4, policy, 0)

	key := FlowKey{Proto: ProtoTCP, SrcAddr: mustAddr("10.0.0.1"), SrcPort: 1, DstAddr: mustAddr("93.184.216.34"), DstPort: 443}
	first := table.Egress(key)
	second := table.Egress(key)
	if first != second {
		t.Fatalf("Egress(key) returned different results on repeat calls: %q then %q", first, second)
	}
	if calls != 1 {
		t.Fatalf("policy called %d times, want exactly 1 (pinned after the first)", calls)
	}
}

func TestShardedFlowTable_ShardIndexAgreesWithDispatch(t *testing.T) {
	table := NewShardedFlowTable(8, StaticEgressPolicy("eg-1"), 0)
	key := FlowKey{Proto: ProtoUDP, SrcAddr: mustAddr("10.0.0.5"), SrcPort: 4000, DstAddr: mustAddr("8.8.8.8"), DstPort: 53}

	idx := table.ShardIndex(key)
	table.Egress(key) // pins on whichever shard Egress's own internal dispatch picks

	if _, ok := table.Shard(idx).Lookup(key); !ok {
		t.Fatalf("flow was not found on the shard ShardIndex(key)=%d reported", idx)
	}
}

func TestShardedFlowTable_LenAndEvictIdleAggregateAcrossShards(t *testing.T) {
	table := NewShardedFlowTable(4, StaticEgressPolicy("eg-1"), time.Nanosecond)
	now := time.Unix(1000, 0)
	for _, shard := range table.shards {
		shard.now = func() time.Time { return now }
	}

	for i := 0; i < 20; i++ {
		key := FlowKey{Proto: ProtoTCP, SrcAddr: mustAddr("10.0.0.1"), SrcPort: uint16(i + 1), DstAddr: mustAddr("1.1.1.1"), DstPort: 443}
		table.Egress(key)
	}
	if got := table.Len(); got != 20 {
		t.Fatalf("Len() = %d, want 20", got)
	}

	for _, shard := range table.shards {
		shard.now = func() time.Time { return now.Add(time.Hour) }
	}
	if removed := table.EvictIdle(); removed != 20 {
		t.Fatalf("EvictIdle() removed %d, want 20", removed)
	}
	if got := table.Len(); got != 0 {
		t.Fatalf("Len() after EvictIdle = %d, want 0", got)
	}
}

func TestShardedFlowTable_ShareNothing_ConcurrentDistinctFlows_NoRace(t *testing.T) {
	table := NewShardedFlowTable(8, func(k FlowKey) string { return fmt.Sprintf("eg-%d", k.SrcPort) }, 0)

	const goroutines = 32
	const flowsPer = 100
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < flowsPer; i++ {
				port := uint16(g*flowsPer + i + 1)
				key := FlowKey{Proto: ProtoTCP, SrcAddr: mustAddr("10.0.0.1"), SrcPort: port, DstAddr: mustAddr("93.184.216.34"), DstPort: 443}
				got := table.Egress(key)
				want := fmt.Sprintf("eg-%d", port)
				if got != want {
					t.Errorf("goroutine %d: Egress for port %d = %q, want %q", g, port, got, want)
				}
			}
		}(g)
	}
	wg.Wait()

	if want, got := goroutines*flowsPer, table.Len(); got != want {
		t.Fatalf("Len() = %d, want %d (every distinct flow from every goroutine must be tracked)", got, want)
	}
}

func TestPacketBatch_AddRespectsCapacityAndReset(t *testing.T) {
	b := NewPacketBatch(2)
	if !b.Add([]byte("a")) {
		t.Fatal("Add #1 refused, want accepted")
	}
	if !b.Add([]byte("b")) {
		t.Fatal("Add #2 refused, want accepted")
	}
	if b.Add([]byte("c")) {
		t.Fatal("Add #3 accepted, want refused (batch at capacity)")
	}
	if got := b.Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2", got)
	}
	if got := b.Cap(); got != 2 {
		t.Fatalf("Cap() = %d, want 2", got)
	}

	b.Reset()
	if got := b.Len(); got != 0 {
		t.Fatalf("Len() after Reset = %d, want 0", got)
	}
	if !b.Add([]byte("d")) {
		t.Fatal("Add after Reset refused, want accepted")
	}
	if got := b.Packets(); len(got) != 1 || string(got[0]) != "d" {
		t.Fatalf("Packets() after Reset+Add = %v, want exactly [\"d\"]", got)
	}
}

func TestFastPathDecide_ResolvesEgressForAValidPacket(t *testing.T) {
	table := NewShardedFlowTable(4, StaticEgressPolicy("eg-static"), 0)
	pkt := buildIPv4(t, byte(ProtoTCP), 0, addr4("10.0.0.2"), addr4("93.184.216.34"), buildTCP(54321, 443))

	key, egress, err := FastPathDecide(table, pkt)
	if err != nil {
		t.Fatalf("FastPathDecide: %v", err)
	}
	if egress != "eg-static" {
		t.Fatalf("egress = %q, want eg-static", egress)
	}
	if key.SrcPort != 54321 || key.DstPort != 443 {
		t.Fatalf("key = %+v, want SrcPort=54321 DstPort=443", key)
	}
}

func TestFastPathDecide_PropagatesParseError(t *testing.T) {
	table := NewShardedFlowTable(4, StaticEgressPolicy("eg-static"), 0)
	if _, _, err := FastPathDecide(table, []byte{0xff}); err == nil {
		t.Fatal("FastPathDecide on garbage input: expected an error, got nil")
	}
}

func TestWorkerPool_EveryPacketHandledExactlyOnceByItsOwnShard(t *testing.T) {
	table := NewShardedFlowTable(4, StaticEgressPolicy("eg-1"), 0)

	var mu sync.Mutex
	seen := map[string]int{}
	handle := func(workerID int, key FlowKey, egress string, pkt []byte) {
		mu.Lock()
		defer mu.Unlock()
		wantWorker := table.ShardIndex(key)
		if workerID != wantWorker {
			t.Errorf("packet for %s handled by worker %d, want %d", key, workerID, wantWorker)
		}
		if egress != "eg-1" {
			t.Errorf("packet for %s got egress %q, want eg-1", key, egress)
		}
		seen[key.String()]++
	}

	pool := NewWorkerPool(table, 64, handle)
	defer pool.Close()

	const n = 200
	batch := NewPacketBatch(n)
	wantKeys := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		pkt := buildIPv4(t, byte(ProtoTCP), 0, addr4("10.0.0.2"), addr4("93.184.216.34"), buildTCP(uint16(20000+i), 443))
		batch.Add(pkt)
		key, err := ParseFlowKey(pkt)
		if err != nil {
			t.Fatalf("ParseFlowKey (test setup): %v", err)
		}
		wantKeys[key.String()] = true
	}

	pool.Submit(batch)

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != n {
		t.Fatalf("distinct flows handled = %d, want %d", len(seen), n)
	}
	for k, count := range seen {
		if count != 1 {
			t.Errorf("flow %s handled %d times, want exactly 1", k, count)
		}
		if !wantKeys[k] {
			t.Errorf("handled an unexpected flow %s", k)
		}
	}
}

func TestWorkerPool_CloseStopsPromptly(t *testing.T) {
	table := NewShardedFlowTable(2, StaticEgressPolicy("eg-1"), 0)
	pool := NewWorkerPool(table, 8, func(int, FlowKey, string, []byte) {})

	done := make(chan struct{})
	go func() {
		pool.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return within 2s")
	}
}

func BenchmarkFastPathDecide(b *testing.B) {
	table := NewShardedFlowTable(0, StaticEgressPolicy("eg-1"), 0)

	const distinctFlows = 4096
	packets := make([][]byte, distinctFlows)
	for i := range packets {
		packets[i] = benchIPv4TCPPacket(uint16(1+i%60000), 443)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(packets[0])))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := packets[i%distinctFlows]
		if _, _, err := FastPathDecide(table, pkt); err != nil {
			b.Fatalf("FastPathDecide: %v", err)
		}
	}
}

func BenchmarkShardedFlowTable_Parallel(b *testing.B) {
	table := NewShardedFlowTable(0, StaticEgressPolicy("eg-1"), 0)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var port uint32
		for pb.Next() {
			port++
			key := FlowKey{
				Proto:   ProtoTCP,
				SrcAddr: netip.AddrFrom4([4]byte{10, 0, 0, 1}),
				SrcPort: uint16(port%60000 + 1),
				DstAddr: netip.AddrFrom4([4]byte{93, 184, 216, 34}),
				DstPort: 443,
			}
			table.Egress(key)
		}
	})
}

func BenchmarkSingleFlowTable_Parallel(b *testing.B) {
	table := NewShardedFlowTable(1, StaticEgressPolicy("eg-1"), 0)

	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var port uint32
		for pb.Next() {
			port++
			key := FlowKey{
				Proto:   ProtoTCP,
				SrcAddr: netip.AddrFrom4([4]byte{10, 0, 0, 1}),
				SrcPort: uint16(port%60000 + 1),
				DstAddr: netip.AddrFrom4([4]byte{93, 184, 216, 34}),
				DstPort: 443,
			}
			table.Egress(key)
		}
	})
}

func BenchmarkPacketBatch_AddReset(b *testing.B) {
	batch := NewPacketBatch(64)
	pkt := benchIPv4TCPPacket(1, 443)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch.Reset()
		for j := 0; j < 64; j++ {
			batch.Add(pkt)
		}
	}
}

func BenchmarkWorkerPool_Submit(b *testing.B) {
	table := NewShardedFlowTable(0, StaticEgressPolicy("eg-1"), 0)
	pool := NewWorkerPool(table, 256, func(int, FlowKey, string, []byte) {})
	defer pool.Close()

	const n = 256
	batch := NewPacketBatch(n)
	for i := 0; i < n; i++ {
		batch.Add(benchIPv4TCPPacket(uint16(1+i), 443))
	}

	b.ReportAllocs()
	b.SetBytes(int64(n * len(batch.Packets()[0])))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.Submit(batch)
	}
}

func benchIPv4TCPPacket(srcPort, dstPort uint16) []byte {
	const ihl = 20
	pkt := make([]byte, ihl+4)
	pkt[0] = 0x45 // version 4, IHL 5 words
	pkt[9] = byte(ProtoTCP)
	copy(pkt[12:16], []byte{10, 0, 0, 2})
	copy(pkt[16:20], []byte{93, 184, 216, 34})
	pkt[ihl+0] = byte(srcPort >> 8)
	pkt[ihl+1] = byte(srcPort)
	pkt[ihl+2] = byte(dstPort >> 8)
	pkt[ihl+3] = byte(dstPort)
	return pkt
}
