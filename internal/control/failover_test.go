package control

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type toggleStore struct {
	mu    sync.Mutex
	down  bool
	inner *MemStore
}

var errControllerDown = errors.New("simulated: controller unreachable")

func newToggleStore() *toggleStore {
	return &toggleStore{inner: NewMemStore()}
}

func (s *toggleStore) setDown(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = v
}

func (s *toggleStore) isDown() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.down
}

func (s *toggleStore) Put(ctx context.Context, key string, value []byte) error {
	if s.isDown() {
		return errControllerDown
	}
	return s.inner.Put(ctx, key, value)
}

func (s *toggleStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	if s.isDown() {
		return nil, false, errControllerDown
	}
	return s.inner.Get(ctx, key)
}

func (s *toggleStore) List(ctx context.Context, prefix string) (map[string][]byte, error) {
	if s.isDown() {
		return nil, errControllerDown
	}
	return s.inner.List(ctx, prefix)
}

func (s *toggleStore) Watch(ctx context.Context, prefix string) (<-chan Event, error) {
	if s.isDown() {
		return nil, errControllerDown
	}
	return s.inner.Watch(ctx, prefix)
}

func (s *toggleStore) Revision(ctx context.Context, key string) (int64, bool, error) {
	if s.isDown() {
		return 0, false, errControllerDown
	}
	return s.inner.Revision(ctx, key)
}

func (s *toggleStore) CompareAndSwap(ctx context.Context, key string, expectedRevision int64, value []byte) (int64, bool, error) {
	if s.isDown() {
		return 0, false, errControllerDown
	}
	return s.inner.CompareAndSwap(ctx, key, expectedRevision, value)
}

func TestFailoverController_Refresh_PopulatesCache(t *testing.T) {
	ctx := context.Background()
	store := newToggleStore()
	ownership := NewOwnershipService(store)
	cache := NewConfigCache()
	fc := NewFailoverController(cache, ownership)

	rec := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if applied, err := ownership.SetIfNewer(ctx, rec); err != nil || !applied {
		t.Fatalf("SetIfNewer: applied=%v err=%v", applied, err)
	}
	now := time.Now()
	if err := fc.Refresh(ctx, "s1", now); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	egress, epoch, ok := fc.Forward("s1", now)
	if !ok || egress != "hk" || epoch.Global != 0 {
		t.Fatalf("Forward() = (%q, %+v, %v), want (hk, {Global:0 Local:0}, true)", egress, epoch, ok)
	}
}

func TestFailoverController_Forward_UnknownSession(t *testing.T) {
	fc := NewFailoverController(NewConfigCache(), NewOwnershipService(NewMemStore()))
	if _, _, ok := fc.Forward("nope", time.Now()); ok {
		t.Fatal("Forward() ok = true for a session never cached")
	}
}

func TestFailoverController_EmergencyFailover_RequiresCachedSession(t *testing.T) {
	fc := NewFailoverController(NewConfigCache(), NewOwnershipService(NewMemStore()))
	_, err := fc.EmergencyFailover("nope", "sg", time.Now())
	if !errors.Is(err, ErrSessionNotCached) {
		t.Fatalf("EmergencyFailover error = %v, want %v", err, ErrSessionNotCached)
	}
}

func TestFailoverController_AttemptPlannedMigration_RequiresCachedSession(t *testing.T) {
	fc := NewFailoverController(NewConfigCache(), NewOwnershipService(NewMemStore()))
	_, _, err := fc.AttemptPlannedMigration(context.Background(), "nope", "sg", time.Now())
	if !errors.Is(err, ErrSessionNotCached) {
		t.Fatalf("AttemptPlannedMigration error = %v, want %v", err, ErrSessionNotCached)
	}
}

func TestFailoverController_Reconcile_RequiresCachedSession(t *testing.T) {
	fc := NewFailoverController(NewConfigCache(), NewOwnershipService(NewMemStore()))
	_, err := fc.Reconcile(context.Background(), "nope", time.Now())
	if !errors.Is(err, ErrSessionNotCached) {
		t.Fatalf("Reconcile error = %v, want %v", err, ErrSessionNotCached)
	}
}

func TestFailoverController_ControllerDown_FullScenario(t *testing.T) {
	ctx := context.Background()
	store := newToggleStore()
	ownership := NewOwnershipService(store)
	cache := NewConfigCache()
	fc := NewFailoverController(cache, ownership)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Normal operation: the session is established and cached while the
	// controller is reachable.
	base := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if applied, err := ownership.SetIfNewer(ctx, base); err != nil || !applied {
		t.Fatalf("seeding base record: applied=%v err=%v", applied, err)
	}
	if err := fc.Refresh(ctx, "s1", now); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// Controller unreachable
	store.setDown(true)

	egress, epoch, ok := fc.Forward("s1", now)
	if !ok || egress != "hk" || epoch != (LocalEpoch{Global: 0, Local: 0}) {
		t.Fatalf("Forward() while down = (%q, %+v, %v), want (hk, {0 0}, true)", egress, epoch, ok)
	}

	applied, deferred, err := fc.AttemptPlannedMigration(ctx, "s1", "sg", now)
	if err != nil {
		t.Fatalf("AttemptPlannedMigration returned an error instead of deferring: %v", err)
	}
	if applied {
		t.Fatal("AttemptPlannedMigration applied a migration while the controller is down")
	}
	if !deferred {
		t.Fatal("AttemptPlannedMigration did not report deferred=true while the controller is down")
	}
	// The cache must be completely unaffected by the deferred attempt.
	if egress, _, _ := fc.Forward("s1", now); egress != "hk" {
		t.Fatalf("cached Egress changed to %q after a deferred planned migration, want unchanged hk", egress)
	}

	newEpoch, err := fc.EmergencyFailover("s1", "jp", now)
	if err != nil {
		t.Fatalf("EmergencyFailover while controller is down: %v", err)
	}
	if newEpoch.Global != 0 || newEpoch.Local != 1 {
		t.Fatalf("EmergencyFailover epoch = %+v, want {Global:0 Local:1}", newEpoch)
	}
	egress, epoch, ok = fc.Forward("s1", now)
	if !ok || egress != "jp" || epoch != (LocalEpoch{Global: 0, Local: 1}) {
		t.Fatalf("Forward() after emergency failover = (%q, %+v, %v), want (jp, {0 1}, true)", egress, epoch, ok)
	}

	store.setDown(false)
	remoteBefore, foundBefore, err := ownership.Get(ctx, "s1")
	if err != nil || !foundBefore || remoteBefore != base {
		t.Fatalf("control plane's record changed during the outage to %+v (found=%v err=%v), want unchanged %+v", remoteBefore, foundBefore, err, base)
	}
	store.setDown(true) // put it back down for the rest of the scenario

	// Controller reachable again.
	store.setDown(false)
	reconciled, err := fc.Reconcile(ctx, "s1", now)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !reconciled {
		t.Fatal("Reconcile did not apply the emergency failover once the controller was reachable again")
	}

	// The emergency pick is now the durable, control-plane-confirmed
	// truth: exactly one owner, Epoch advanced by exactly 1, Local reset.
	final, found, err := ownership.Get(ctx, "s1")
	if err != nil || !found {
		t.Fatalf("Get after Reconcile: found=%v err=%v", found, err)
	}
	if final.Epoch != 1 || final.Egress != "jp" {
		t.Fatalf("final control-plane record = %+v, want Epoch=1 Egress=jp", final)
	}
	egress, epoch, ok = fc.Forward("s1", now)
	if !ok || egress != "jp" || epoch != (LocalEpoch{Global: 1, Local: 0}) {
		t.Fatalf("Forward() after Reconcile = (%q, %+v, %v), want (jp, {1 0}, true)", egress, epoch, ok)
	}
}

func TestFailoverController_Reconcile_NoOpWhenNoEmergencyHappened(t *testing.T) {
	ctx := context.Background()
	store := newToggleStore()
	ownership := NewOwnershipService(store)
	cache := NewConfigCache()
	fc := NewFailoverController(cache, ownership)
	now := time.Now()

	base := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if _, err := ownership.SetIfNewer(ctx, base); err != nil {
		t.Fatalf("SetIfNewer: %v", err)
	}
	if err := fc.Refresh(ctx, "s1", now); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	applied, err := fc.Reconcile(ctx, "s1", now)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if applied {
		t.Fatal("Reconcile applied something despite no emergency failover having happened")
	}
}

func TestFailoverController_Reconcile_DefersToRemoteWhenGlobalAdvancedDuringOutage(t *testing.T) {
	ctx := context.Background()
	store := newToggleStore()
	ownership := NewOwnershipService(store)
	cache := NewConfigCache()
	fc := NewFailoverController(cache, ownership)
	now := time.Now()

	base := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if _, err := ownership.SetIfNewer(ctx, base); err != nil {
		t.Fatalf("SetIfNewer: %v", err)
	}
	if err := fc.Refresh(ctx, "s1", now); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// This process takes an emergency failover to "jp" while cut off...
	if _, err := fc.EmergencyFailover("s1", "jp", now); err != nil {
		t.Fatalf("EmergencyFailover: %v", err)
	}

	elsewhere := base.NextEpoch("sg")
	if applied, err := ownership.SetIfNewer(ctx, elsewhere); err != nil || !applied {
		t.Fatalf("simulating another writer: applied=%v err=%v", applied, err)
	}

	applied, err := fc.Reconcile(ctx, "s1", now)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if applied {
		t.Fatal("Reconcile applied the local emergency pick despite a newer remote epoch existing")
	}
	egress, epoch, ok := fc.Forward("s1", now)
	if !ok || egress != "sg" || epoch != (LocalEpoch{Global: 1, Local: 0}) {
		t.Fatalf("Forward() after deferring to the remote epoch = (%q, %+v, %v), want (sg, {1 0}, true)", egress, epoch, ok)
	}

	final, _, _ := ownership.Get(ctx, "s1")
	if final != elsewhere {
		t.Fatalf("control-plane record = %+v, want unchanged %+v", final, elsewhere)
	}
}

func TestFailoverController_Reconcile_ConcurrentReconciliations_ExactlyOneWins(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	ownership := NewOwnershipService(store)
	now := time.Now()

	base := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if applied, err := ownership.SetIfNewer(ctx, base); err != nil || !applied {
		t.Fatalf("seeding base record: applied=%v err=%v", applied, err)
	}

	const n = 6
	controllers := make([]*FailoverController, n)
	for i := range controllers {
		cache := NewConfigCache()
		cache.StoreOwnership(base, now)
		controllers[i] = NewFailoverController(cache, ownership)
		if _, err := controllers[i].EmergencyFailover("s1", egressName(i), now); err != nil {
			t.Fatalf("EmergencyFailover: %v", err)
		}
	}

	var wg sync.WaitGroup
	applied := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ok, err := controllers[i].Reconcile(ctx, "s1", now)
			if err != nil {
				t.Errorf("Reconcile: %v", err)
			}
			applied[i] = ok
		}(i)
	}
	wg.Wait()

	winners := 0
	for _, ok := range applied {
		if ok {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("winners = %d, want exactly 1 (no double owner among concurrently reconciling emergency failovers)", winners)
	}
	final, _, err := ownership.Get(ctx, "s1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if final.Epoch != 1 {
		t.Fatalf("final Epoch = %d, want 1 (exactly one emergency pick became durable)", final.Epoch)
	}
}

func TestFailoverController_Refresh_NotFoundIsNotError(t *testing.T) {
	fc := NewFailoverController(NewConfigCache(), NewOwnershipService(NewMemStore()))
	if err := fc.Refresh(context.Background(), "never-seen", time.Now()); err != nil {
		t.Fatalf("Refresh on an unknown session returned an error: %v", err)
	}
	if _, _, ok := fc.Forward("never-seen", time.Now()); ok {
		t.Fatal("Forward() ok = true after Refresh found nothing")
	}
}

func TestFailoverController_Refresh_PropagatesStoreError(t *testing.T) {
	fc := NewFailoverController(NewConfigCache(), NewOwnershipService(&errStore{getErr: errBoom}))
	if err := fc.Refresh(context.Background(), "s1", time.Now()); !errors.Is(err, errBoom) {
		t.Fatalf("Refresh error = %v, want %v", err, errBoom)
	}
}

func TestFailoverController_AttemptPlannedMigration_Succeeds(t *testing.T) {
	ctx := context.Background()
	store := newToggleStore()
	ownership := NewOwnershipService(store)
	cache := NewConfigCache()
	fc := NewFailoverController(cache, ownership)
	now := time.Now()

	base := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if _, err := ownership.SetIfNewer(ctx, base); err != nil {
		t.Fatalf("SetIfNewer: %v", err)
	}
	if err := fc.Refresh(ctx, "s1", now); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	applied, deferred, err := fc.AttemptPlannedMigration(ctx, "s1", "sg", now)
	if err != nil {
		t.Fatalf("AttemptPlannedMigration: %v", err)
	}
	if deferred {
		t.Fatal("AttemptPlannedMigration deferred while the controller is up")
	}
	if !applied {
		t.Fatal("AttemptPlannedMigration did not apply while the controller is up")
	}
	egress, epoch, ok := fc.Forward("s1", now)
	if !ok || egress != "sg" || epoch.Global != 1 {
		t.Fatalf("Forward() after a successful planned migration = (%q, %+v, %v), want (sg, Global=1, true)", egress, epoch, ok)
	}
}

func TestFailoverController_AttemptPlannedMigration_LosesRaceRefreshesCache(t *testing.T) {
	ctx := context.Background()
	store := newToggleStore()
	ownership := NewOwnershipService(store)
	cache := NewConfigCache()
	fc := NewFailoverController(cache, ownership)
	now := time.Now()

	base := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if _, err := ownership.SetIfNewer(ctx, base); err != nil {
		t.Fatalf("SetIfNewer: %v", err)
	}
	if err := fc.Refresh(ctx, "s1", now); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// Someone else wins the epoch this attempt was aiming for.
	rival := base.NextEpoch("jp")
	if applied, err := ownership.SetIfNewer(ctx, rival); err != nil || !applied {
		t.Fatalf("seeding rival: applied=%v err=%v", applied, err)
	}

	applied, deferred, err := fc.AttemptPlannedMigration(ctx, "s1", "sg", now)
	if err != nil {
		t.Fatalf("AttemptPlannedMigration: %v", err)
	}
	if applied || deferred {
		t.Fatalf("AttemptPlannedMigration = (applied=%v deferred=%v), want both false (lost the race, not down)", applied, deferred)
	}
	// The cache should have been refreshed to the rival's winning record.
	egress, epoch, ok := fc.Forward("s1", now)
	if !ok || egress != "jp" || epoch.Global != 1 {
		t.Fatalf("Forward() after losing the race = (%q, %+v, %v), want (jp, Global=1, true)", egress, epoch, ok)
	}
}

func TestFollowOwnership_PropagatesWatchError(t *testing.T) {
	gate := NewEpochGate()
	ownership := NewOwnershipService(&errStore{watchErr: errBoom})
	if err := FollowOwnership(context.Background(), gate, ownership); !errors.Is(err, errBoom) {
		t.Fatalf("FollowOwnership error = %v, want %v", err, errBoom)
	}
}
