package control

import (
	"sync"
	"testing"
)

func TestEpochGate_Admit_UnknownSessionAlwaysAdmitted(t *testing.T) {
	g := NewEpochGate()
	if !g.Admit("s1", 0) {
		t.Fatal("Admit on a never-seen session with epoch 0 = false, want true")
	}
	if !g.Admit("s1", 999) {
		t.Fatal("Admit on a never-seen session with a large epoch = false, want true")
	}
}

func TestEpochGate_Update_RecordsEpoch(t *testing.T) {
	g := NewEpochGate()
	g.Update("s1", 5)
	epoch, ok := g.Known("s1")
	if !ok || epoch != 5 {
		t.Fatalf("Known() = (%d, %v), want (5, true)", epoch, ok)
	}
}

func TestEpochGate_Update_NeverRegresses(t *testing.T) {
	g := NewEpochGate()
	g.Update("s1", 5)
	g.Update("s1", 3) // a stale/duplicate delivery
	epoch, _ := g.Known("s1")
	if epoch != 5 {
		t.Fatalf("Known() after Update(3) following Update(5) = %d, want 5 (never regress)", epoch)
	}
	g.Update("s1", 5) // exact duplicate
	if epoch, _ = g.Known("s1"); epoch != 5 {
		t.Fatalf("Known() after a duplicate Update(5) = %d, want 5", epoch)
	}
}

func TestEpochGate_Admit_RejectsStrictlyOlderEpoch(t *testing.T) {
	g := NewEpochGate()
	g.Update("s1", 5)
	if g.Admit("s1", 4) {
		t.Fatal("Admit(epoch=4) after Update(5) = true, want false (fencing the old epoch)")
	}
}

func TestEpochGate_Admit_AllowsEqualOrNewerEpoch(t *testing.T) {
	g := NewEpochGate()
	g.Update("s1", 5)
	if !g.Admit("s1", 5) {
		t.Fatal("Admit(epoch=5) after Update(5) = false, want true (the current owner's own epoch)")
	}
	if !g.Admit("s1", 6) {
		t.Fatal("Admit(epoch=6) after Update(5) = false, want true (a newer epoch)")
	}
}

func TestEpochGate_AdmitAndAdvance_RejectsOldOwnerAfterNewerCommitted(t *testing.T) {
	g := NewEpochGate()

	if !g.AdmitAndAdvance("s1", 5) {
		t.Fatal("AdmitAndAdvance(5) on a fresh session = false, want true")
	}
	if g.AdmitAndAdvance("s1", 3) {
		t.Fatal("AdmitAndAdvance(3) after 5 was already committed = true, want false (the old owner must be fenced)")
	}
	if !g.AdmitAndAdvance("s1", 5) {
		t.Fatal("AdmitAndAdvance(5) again (a retransmit at the current epoch) = false, want true")
	}
	if !g.AdmitAndAdvance("s1", 6) {
		t.Fatal("AdmitAndAdvance(6), a legitimately newer epoch, = false, want true")
	}
	if g.AdmitAndAdvance("s1", 5) {
		t.Fatal("AdmitAndAdvance(5) after 6 was committed = true, want false")
	}
	epoch, _ := g.Known("s1")
	if epoch != 6 {
		t.Fatalf("Known() = %d, want 6", epoch)
	}
}

func TestEpochGate_AdmitAndAdvance_UnknownSessionAlwaysAdmittedAndRecorded(t *testing.T) {
	g := NewEpochGate()
	if !g.AdmitAndAdvance("s1", 0) {
		t.Fatal("AdmitAndAdvance on a never-seen session with epoch 0 = false, want true")
	}
	epoch, ok := g.Known("s1")
	if !ok || epoch != 0 {
		t.Fatalf("Known() after the first AdmitAndAdvance = (%d, %v), want (0, true)", epoch, ok)
	}
}

func TestEpochGate_IndependentPerSession(t *testing.T) {
	g := NewEpochGate()
	g.Update("s1", 10)
	if !g.Admit("s2", 0) {
		t.Fatal("Admit(s2, 0) = false, want true, s2 has no recorded epoch of its own")
	}
	if !g.AdmitAndAdvance("s2", 0) {
		t.Fatal("AdmitAndAdvance(s2, 0) = false, want true")
	}
	if epoch, _ := g.Known("s1"); epoch != 10 {
		t.Fatalf("s1's Known() changed to %d after touching s2, want unchanged 10", epoch)
	}
}

func TestEpochGate_AdmitAndAdvance_ConcurrentCallers_RaceFree(t *testing.T) {
	g := NewEpochGate()
	const n = 50
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(epoch uint64) {
			defer wg.Done()
			g.AdmitAndAdvance("s1", epoch)
		}(uint64(i))
	}
	wg.Wait()

	epoch, ok := g.Known("s1")
	if !ok || epoch != n-1 {
		t.Fatalf("Known() after all concurrent advances = (%d, %v), want (%d, true)", epoch, ok, n-1)
	}
	if g.AdmitAndAdvance("s1", 0) {
		t.Fatal("AdmitAndAdvance(0) after concurrent advances up to a higher epoch = true, want false")
	}
}
