package measurement

import (
	"sort"
	"sync"
	"testing"
	"time"
)

func newTestLinkStateTable() (*LinkStateTable, *fakeClock) {
	fc := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	tbl := NewLinkStateTable()
	tbl.now = fc.now
	return tbl, fc
}

func TestLinkStateTable_UpdateAndRetrieve(t *testing.T) {
	tbl, _ := newTestLinkStateTable()
	tbl.UpdateLink("sg", "hk", LinkQuality{RTTMicros: 15_000, LossRate: 0.01})

	q, ok := tbl.Link("sg", "hk")
	if !ok {
		t.Fatal("Link(sg, hk) not found after UpdateLink")
	}
	if q.RTTMicros != 15_000 || q.LossRate != 0.01 {
		t.Fatalf("Link(sg, hk) = %+v, want RTTMicros=15000 LossRate=0.01", q)
	}
}

func TestLinkStateTable_UndirectedIdentity(t *testing.T) {
	tbl, _ := newTestLinkStateTable()
	tbl.UpdateLink("sg", "hk", LinkQuality{RTTMicros: 15_000})

	q, ok := tbl.Link("hk", "sg") // reversed order
	if !ok {
		t.Fatal("Link(hk, sg) not found: a link must be the same regardless of argument order")
	}
	if q.RTTMicros != 15_000 {
		t.Fatalf("Link(hk, sg) = %+v, want RTTMicros=15000", q)
	}
}

func TestLinkStateTable_UpdateReplacesPrevious(t *testing.T) {
	tbl, _ := newTestLinkStateTable()
	tbl.UpdateLink("sg", "hk", LinkQuality{RTTMicros: 15_000})
	tbl.UpdateLink("sg", "hk", LinkQuality{RTTMicros: 30_000})

	q, _ := tbl.Link("sg", "hk")
	if q.RTTMicros != 30_000 {
		t.Fatalf("RTTMicros = %f after a second UpdateLink, want 30000 (must replace, not average/accumulate)", q.RTTMicros)
	}
}

func TestLinkStateTable_Link_UnknownReturnsFalse(t *testing.T) {
	tbl, _ := newTestLinkStateTable()
	if _, ok := tbl.Link("sg", "hk"); ok {
		t.Fatal("Link on an untouched table returned ok=true")
	}
}

func TestLinkStateTable_PathCost_SingleLink(t *testing.T) {
	tbl, _ := newTestLinkStateTable()
	tbl.UpdateLink("access-sg", "egress-hk", LinkQuality{RTTMicros: 20_000, LossRate: 0.02})

	pq, err := tbl.PathCost([]string{"access-sg", "egress-hk"})
	if err != nil {
		t.Fatalf("PathCost: %v", err)
	}
	if pq.RTTMicros != 20_000 {
		t.Fatalf("RTTMicros = %f, want 20000", pq.RTTMicros)
	}
	if diff := pq.LossRate - 0.02; diff > 1e-9 || diff < -1e-9 {
		// Not a plain != comparison: LossRate is computed as 1 -
		// (1 - 0.02), and floating-point subtraction does not always
		// round-trip exactly back to the original literal.
		t.Fatalf("LossRate = %.10f, want ~0.02", pq.LossRate)
	}
}

func TestLinkStateTable_PathCost_MultiHop_RTTSumsAdditively(t *testing.T) {
	tbl, _ := newTestLinkStateTable()
	tbl.UpdateLink("client", "access-sg", LinkQuality{RTTMicros: 5_000})
	tbl.UpdateLink("access-sg", "egress-hk", LinkQuality{RTTMicros: 20_000})
	tbl.UpdateLink("egress-hk", "dest", LinkQuality{RTTMicros: 3_000})

	pq, err := tbl.PathCost([]string{"client", "access-sg", "egress-hk", "dest"})
	if err != nil {
		t.Fatalf("PathCost: %v", err)
	}
	want := 5_000.0 + 20_000.0 + 3_000.0
	if pq.RTTMicros != want {
		t.Fatalf("RTTMicros = %f, want %f (sum of the 3 segments)", pq.RTTMicros, want)
	}
}

func TestLinkStateTable_PathCost_LossComposesAsSurvivalProbability(t *testing.T) {
	tbl, _ := newTestLinkStateTable()
	tbl.UpdateLink("a", "b", LinkQuality{LossRate: 0.1})
	tbl.UpdateLink("b", "c", LinkQuality{LossRate: 0.1})
	tbl.UpdateLink("c", "d", LinkQuality{LossRate: 0.1})

	pq, err := tbl.PathCost([]string{"a", "b", "c", "d"})
	if err != nil {
		t.Fatalf("PathCost: %v", err)
	}
	// 1 - 0.9^3 = 0.271, NOT a naive sum of 0.3.
	want := 1 - 0.9*0.9*0.9
	if diff := pq.LossRate - want; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("LossRate = %.6f, want %.6f (independent-segment survival probability, not a naive sum)", pq.LossRate, want)
	}
}

func TestLinkStateTable_PathCost_MissingLinkErrors(t *testing.T) {
	tbl, _ := newTestLinkStateTable()
	tbl.UpdateLink("a", "b", LinkQuality{RTTMicros: 1})
	// "b"<->"c" was never measured.
	if _, err := tbl.PathCost([]string{"a", "b", "c"}); err == nil {
		t.Fatal("PathCost over an unmeasured link: expected an error")
	}
}

func TestLinkStateTable_PathCost_TooShortPathErrors(t *testing.T) {
	tbl, _ := newTestLinkStateTable()
	for _, path := range [][]string{nil, {}, {"a"}} {
		if _, err := tbl.PathCost(path); err == nil {
			t.Fatalf("PathCost(%v): expected an error for a path shorter than 2 nodes", path)
		}
	}
}

func TestLinkStateTable_PathCost_OldestLinkUpdated(t *testing.T) {
	tbl, fc := newTestLinkStateTable()
	tbl.UpdateLink("a", "b", LinkQuality{RTTMicros: 1}) // updated at t0
	fc.advance(time.Minute)
	tbl.UpdateLink("b", "c", LinkQuality{RTTMicros: 1}) // updated at t0+1m

	pq, err := tbl.PathCost([]string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("PathCost: %v", err)
	}
	wantOldest := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if !pq.OldestLinkUpdated.Equal(wantOldest) {
		t.Fatalf("OldestLinkUpdated = %v, want %v (the earlier of the two links' timestamps)", pq.OldestLinkUpdated, wantOldest)
	}
}

func TestLinkStateTable_Links_ListsAll(t *testing.T) {
	tbl, _ := newTestLinkStateTable()
	tbl.UpdateLink("a", "b", LinkQuality{})
	tbl.UpdateLink("b", "c", LinkQuality{})
	tbl.UpdateLink("a", "b", LinkQuality{RTTMicros: 99}) // re-update, must not duplicate

	links := tbl.Links()
	if len(links) != 2 {
		t.Fatalf("Links() returned %d entries, want 2 (re-updating a<->b must not add a duplicate)", len(links))
	}
}

func TestLinkStateTable_Neighbors(t *testing.T) {
	tbl, _ := newTestLinkStateTable()
	tbl.UpdateLink("hub", "sg", LinkQuality{})
	tbl.UpdateLink("sg", "hub", LinkQuality{}) // same link, reversed args, must not create a second neighbor
	tbl.UpdateLink("hub", "hk", LinkQuality{})
	tbl.UpdateLink("sg", "hk", LinkQuality{}) // not a neighbor of "hub"

	neighbors := tbl.Neighbors("hub")
	sort.Strings(neighbors)
	if len(neighbors) != 2 || neighbors[0] != "hk" || neighbors[1] != "sg" {
		t.Fatalf("Neighbors(hub) = %v, want [hk sg]", neighbors)
	}
}

func TestLinkStateTable_Neighbors_UnknownNode(t *testing.T) {
	tbl, _ := newTestLinkStateTable()
	tbl.UpdateLink("a", "b", LinkQuality{})
	if got := tbl.Neighbors("nowhere"); len(got) != 0 {
		t.Fatalf("Neighbors(nowhere) = %v, want empty", got)
	}
}

func TestLinkQualityFromPassive(t *testing.T) {
	snap := Snapshot{Received: 90, Lost: 10}
	q := LinkQualityFromPassive(snap)
	if q.LossRate != 0.1 {
		t.Fatalf("LossRate = %f, want 0.1", q.LossRate)
	}
	if q.RTTMicros != 0 {
		t.Fatalf("RTTMicros = %f, want 0 (PassiveTracker never measures RTT)", q.RTTMicros)
	}
}

func TestLinkQualityFromProbe(t *testing.T) {
	stats := ProbeStats{Sent: 100, Lost: 5, RTTMicros: 12_345}
	q := LinkQualityFromProbe(stats)
	if q.RTTMicros != 12_345 {
		t.Fatalf("RTTMicros = %f, want 12345", q.RTTMicros)
	}
	if q.LossRate != 0.05 {
		t.Fatalf("LossRate = %f, want 0.05", q.LossRate)
	}
}

func TestLinkStateTable_ConcurrentUpdateAndRead_NoRace(t *testing.T) {
	tbl := NewLinkStateTable()
	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			tbl.UpdateLink("a", "b", LinkQuality{RTTMicros: float64(i)})
		}(i)
		go func() {
			defer wg.Done()
			tbl.Link("a", "b")
			tbl.Links()
			tbl.Neighbors("a")
			_, _ = tbl.PathCost([]string{"a", "b"})
		}()
	}
	wg.Wait()
}
