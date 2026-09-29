package handoff

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ngthdong/egressa/internal/control"
)

func TestCutover_RequiresReadyArm_NothingArmedAtAll(t *testing.T) {
	ctx := context.Background()
	ownership := control.NewOwnershipService(control.NewMemStore())
	armer := NewStandbyArmer()
	cc := NewCutoverController(armer, ownership)

	base := control.OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if applied, err := ownership.SetIfNewer(ctx, base); err != nil || !applied {
		t.Fatalf("seeding base record: applied=%v err=%v", applied, err)
	}

	_, ok, err := cc.Cutover(ctx, "s1", "a2", base, time.Now())
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("Cutover error = %v, want %v", err, ErrNotReady)
	}
	if ok {
		t.Fatal("Cutover ok = true with nothing armed")
	}
	// Nothing must have been attempted against the control plane.
	current, _, _ := ownership.Get(ctx, "s1")
	if current != base {
		t.Fatalf("control-plane record changed to %+v despite ErrNotReady, want unchanged %+v", current, base)
	}
}

func TestCutover_RequiresReadyNotJustPrepare(t *testing.T) {
	ctx := context.Background()
	ownership := control.NewOwnershipService(control.NewMemStore())
	armer := NewStandbyArmer()
	cc := NewCutoverController(armer, ownership)

	base := control.OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if _, err := ownership.SetIfNewer(ctx, base); err != nil {
		t.Fatalf("ownership.SetIfNewer: %v", err)
	}
	if err := armer.Prepare("s1", 0, AccessState{SessionID: "s1", VirtualIP: "10.0.0.1"}, time.Now()); err != nil {
		t.Fatalf("armer.Prepare: %v", err)
	}

	_, ok, err := cc.Cutover(ctx, "s1", "a2", base, time.Now())
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("Cutover error = %v, want %v", err, ErrNotReady)
	}
	if ok {
		t.Fatal("Cutover ok = true while the arm is only Prepare")
	}
	if phase := armer.Phase("s1"); phase != PhasePrepare {
		t.Fatalf("arm phase after rejected Cutover = %v, want unchanged %v", phase, PhasePrepare)
	}
}

func TestCutover_RequiresMatchingEpoch_LeavesArmUntouched(t *testing.T) {
	ctx := context.Background()
	ownership := control.NewOwnershipService(control.NewMemStore())
	armer := NewStandbyArmer()
	cc := NewCutoverController(armer, ownership)

	base := control.OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 5}
	if _, err := ownership.SetIfNewer(ctx, base); err != nil {
		t.Fatalf("ownership.SetIfNewer: %v", err)
	}
	if err := armer.Prepare("s1", 5, AccessState{SessionID: "s1", VirtualIP: "10.0.0.1"}, time.Now()); err != nil {
		t.Fatalf("armer.Prepare: %v", err)
	}
	if err := armer.MarkReady("s1", 6); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}

	stale := base
	stale.Epoch = 3 // wantEpoch would be 4, but the arm targets 6

	_, ok, err := cc.Cutover(ctx, "s1", "a2", stale, time.Now())
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("Cutover error = %v, want %v", err, ErrNotReady)
	}
	if ok {
		t.Fatal("Cutover ok = true against a stale current record")
	}
	if phase := armer.Phase("s1"); phase != PhaseReady {
		t.Fatalf("arm phase after rejected Cutover = %v, want unchanged %v", phase, PhaseReady)
	}
}

func TestCutover_Succeeds_ConsumesArmAndPreservesEgress(t *testing.T) {
	ctx := context.Background()
	ownership := control.NewOwnershipService(control.NewMemStore())
	armer := NewStandbyArmer()
	cc := NewCutoverController(armer, ownership)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	base := control.OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 5}
	if applied, err := ownership.SetIfNewer(ctx, base); err != nil || !applied {
		t.Fatalf("seeding base record: applied=%v err=%v", applied, err)
	}
	armedState := AccessState{SessionID: "s1", VirtualIP: "10.20.30.40", SeqHighWater: 999}
	if err := armer.Prepare("s1", 5, armedState, now); err != nil {
		t.Fatalf("armer.Prepare: %v", err)
	}
	if err := armer.MarkReady("s1", 6); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}

	result, ok, err := cc.Cutover(ctx, "s1", "a2", base, now)
	if err != nil {
		t.Fatalf("Cutover: %v", err)
	}
	if !ok {
		t.Fatal("Cutover ok = false on the happy path")
	}
	if result.Session != "s1" || result.OldAccess != "a1" || result.NewAccess != "a2" {
		t.Fatalf("result identity = %+v, want Session=s1 OldAccess=a1 NewAccess=a2", result)
	}
	if result.Egress != "hk" {
		t.Fatalf("result.Egress = %q, want unchanged %q", result.Egress, "hk")
	}
	if result.Epoch != 6 {
		t.Fatalf("result.Epoch = %d, want 6", result.Epoch)
	}
	if result.State != armedState {
		t.Fatalf("result.State = %+v, want the armed %+v", result.State, armedState)
	}
	if !result.CommittedAt.Equal(now) {
		t.Fatalf("result.CommittedAt = %v, want %v", result.CommittedAt, now)
	}

	// The control plane reflects exactly this: new Access, same Egress,
	// Epoch advanced by exactly one.
	committed, found, err := ownership.Get(ctx, "s1")
	if err != nil || !found {
		t.Fatalf("Get after Cutover: found=%v err=%v", found, err)
	}
	if committed.Access != "a2" || committed.Egress != "hk" || committed.Epoch != 6 {
		t.Fatalf("committed record = %+v, want Access=a2 Egress=hk Epoch=6", committed)
	}

	if phase := armer.Phase("s1"); phase != PhaseIdle {
		t.Fatalf("arm phase after a successful Cutover = %v, want %v", phase, PhaseIdle)
	}
}

func TestCutover_LosesCASRace_ArmConsumedNothingElseChanges(t *testing.T) {
	ctx := context.Background()
	ownership := control.NewOwnershipService(control.NewMemStore())
	armer := NewStandbyArmer()
	cc := NewCutoverController(armer, ownership)
	now := time.Now()

	base := control.OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if _, err := ownership.SetIfNewer(ctx, base); err != nil {
		t.Fatalf("ownership.SetIfNewer: %v", err)
	}
	if err := armer.Prepare("s1", 0, AccessState{SessionID: "s1", VirtualIP: "10.0.0.1"}, now); err != nil {
		t.Fatalf("armer.Prepare: %v", err)
	}
	if err := armer.MarkReady("s1", 1); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}

	// Some other writer commits Epoch=1 first (a legitimate concurrent
	// egress migration, or another gateway's cutover attempt winning).
	rival := base.NextEpoch("jp")
	if applied, err := ownership.SetIfNewer(ctx, rival); err != nil || !applied {
		t.Fatalf("seeding rival write: applied=%v err=%v", applied, err)
	}

	result, ok, err := cc.Cutover(ctx, "s1", "a2", base, now)
	if err != nil {
		t.Fatalf("Cutover returned an error for a lost CAS race (should be ok=false, err=nil): %v", err)
	}
	if ok {
		t.Fatal("Cutover ok = true despite losing the CAS race")
	}
	if result != (CutoverResult{}) {
		t.Fatalf("result = %+v, want the zero value on a lost race", result)
	}
	// Nothing this call did should have touched the rival's write.
	current, _, _ := ownership.Get(ctx, "s1")
	if current != rival {
		t.Fatalf("control-plane record = %+v, want unchanged rival write %+v", current, rival)
	}
	if phase := armer.Phase("s1"); phase != PhaseIdle {
		t.Fatalf("arm phase after a lost race = %v, want %v (ticket spent)", phase, PhaseIdle)
	}
}

func TestCutover_StoreError_ArmConsumed_ReturnsError(t *testing.T) {
	ctx := context.Background()
	ownership := control.NewOwnershipService(&erroringStore{setErr: errCutoverBoom})
	armer := NewStandbyArmer()
	cc := NewCutoverController(armer, ownership)
	now := time.Now()

	base := control.OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if err := armer.Prepare("s1", 0, AccessState{SessionID: "s1", VirtualIP: "10.0.0.1"}, now); err != nil {
		t.Fatalf("armer.Prepare: %v", err)
	}
	if err := armer.MarkReady("s1", 1); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}

	_, ok, err := cc.Cutover(ctx, "s1", "a2", base, now)
	if !errors.Is(err, errCutoverBoom) {
		t.Fatalf("Cutover error = %v, want %v", err, errCutoverBoom)
	}
	if ok {
		t.Fatal("Cutover ok = true despite a store error")
	}
	if phase := armer.Phase("s1"); phase != PhaseIdle {
		t.Fatalf("arm phase after a store error = %v, want %v (ticket spent, must re-arm)", phase, PhaseIdle)
	}
}

func TestCutover_ConcurrentAttempts_ExactlyOneSucceeds(t *testing.T) {
	ctx := context.Background()
	ownership := control.NewOwnershipService(control.NewMemStore())
	armer := NewStandbyArmer()
	cc := NewCutoverController(armer, ownership)
	now := time.Now()

	base := control.OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if applied, err := ownership.SetIfNewer(ctx, base); err != nil || !applied {
		t.Fatalf("seeding base record: applied=%v err=%v", applied, err)
	}
	if err := armer.Prepare("s1", 0, AccessState{SessionID: "s1", VirtualIP: "10.0.0.1"}, now); err != nil {
		t.Fatalf("armer.Prepare: %v", err)
	}
	if err := armer.MarkReady("s1", 1); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}

	const n = 20
	var wg sync.WaitGroup
	oks := make([]bool, n)
	results := make([]CutoverResult, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Every attempt targets a DIFFERENT candidate access
			// gateway, so if more than one ever "won" it would show up
			// as more than one distinct committed Access.
			res, ok, err := cc.Cutover(ctx, "s1", egressName(i), base, now)
			if err != nil && !errors.Is(err, ErrNotReady) {
				t.Errorf("Cutover(%d): unexpected error %v", i, err)
			}
			oks[i] = ok
			results[i] = res
		}(i)
	}
	wg.Wait()

	winners := 0
	var winner CutoverResult
	for i, ok := range oks {
		if ok {
			winners++
			winner = results[i]
		}
	}
	if winners != 1 {
		t.Fatalf("winners = %d, want exactly 1 among %d concurrent Cutover attempts", winners, n)
	}

	committed, found, err := ownership.Get(ctx, "s1")
	if err != nil || !found {
		t.Fatalf("Get: found=%v err=%v", found, err)
	}
	if committed.Epoch != 1 {
		t.Fatalf("committed.Epoch = %d, want 1 (exactly one cutover applied)", committed.Epoch)
	}
	if committed.Access != winner.NewAccess {
		t.Fatalf("committed.Access = %q, want the winner's NewAccess %q", committed.Access, winner.NewAccess)
	}
	if committed.Egress != "hk" {
		t.Fatalf("committed.Egress = %q, want unchanged %q even under concurrent cutover attempts", committed.Egress, "hk")
	}
	if phase := armer.Phase("s1"); phase != PhaseIdle {
		t.Fatalf("arm phase after the race = %v, want %v", phase, PhaseIdle)
	}
}

type erroringStore struct {
	setErr error
}

var errCutoverBoom = errors.New("handoff test: simulated control-plane error")

func (s *erroringStore) Put(ctx context.Context, key string, value []byte) error {
	return s.setErr
}

func (s *erroringStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	return nil, false, nil
}

func (s *erroringStore) List(ctx context.Context, prefix string) (map[string][]byte, error) {
	return nil, nil
}

func (s *erroringStore) Watch(ctx context.Context, prefix string) (<-chan control.Event, error) {
	ch := make(chan control.Event)
	close(ch)
	return ch, nil
}

func (s *erroringStore) Revision(ctx context.Context, key string) (int64, bool, error) {
	return 0, false, nil
}

func (s *erroringStore) CompareAndSwap(ctx context.Context, key string, expectedRevision int64, value []byte) (int64, bool, error) {
	return 0, false, s.setErr
}
