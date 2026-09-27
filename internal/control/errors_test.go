package control

import (
	"context"
	"errors"
	"testing"
)

type errStore struct {
	putErr, getErr, listErr, watchErr error
}

func (e *errStore) Put(ctx context.Context, key string, value []byte) error {
	return e.putErr
}
func (e *errStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	return nil, false, e.getErr
}
func (e *errStore) List(ctx context.Context, prefix string) (map[string][]byte, error) {
	return nil, e.listErr
}
func (e *errStore) Watch(ctx context.Context, prefix string) (<-chan Event, error) {
	return nil, e.watchErr
}

type plainKVStore struct {
	inner *MemStore
}

func (p *plainKVStore) Put(ctx context.Context, key string, value []byte) error {
	return p.inner.Put(ctx, key, value)
}
func (p *plainKVStore) Get(ctx context.Context, key string) ([]byte, bool, error) {
	return p.inner.Get(ctx, key)
}
func (p *plainKVStore) List(ctx context.Context, prefix string) (map[string][]byte, error) {
	return p.inner.List(ctx, prefix)
}
func (p *plainKVStore) Watch(ctx context.Context, prefix string) (<-chan Event, error) {
	return p.inner.Watch(ctx, prefix)
}

type failFirstCASStore struct {
	*MemStore
	calls int
}

func (f *failFirstCASStore) CompareAndSwap(ctx context.Context, key string, expectedRevision int64, value []byte) (int64, bool, error) {
	f.calls++
	if f.calls == 1 {
		return f.MemStore.CompareAndSwap(ctx, key, expectedRevision-1, value)
	}
	return f.MemStore.CompareAndSwap(ctx, key, expectedRevision, value)
}

type fencerErrStore struct {
	*MemStore
	revisionErr error
	casErr      error
}

func (f *fencerErrStore) Revision(ctx context.Context, key string) (int64, bool, error) {
	if f.revisionErr != nil {
		return 0, false, f.revisionErr
	}
	return f.MemStore.Revision(ctx, key)
}

func (f *fencerErrStore) CompareAndSwap(ctx context.Context, key string, expectedRevision int64, value []byte) (int64, bool, error) {
	if f.casErr != nil {
		return 0, false, f.casErr
	}
	return f.MemStore.CompareAndSwap(ctx, key, expectedRevision, value)
}

var errBoom = errors.New("boom")

func TestOwnershipService_Get_PropagatesStoreError(t *testing.T) {
	s := NewOwnershipService(&errStore{getErr: errBoom})
	_, _, err := s.Get(context.Background(), "s1")
	if !errors.Is(err, errBoom) {
		t.Fatalf("Get error = %v, want %v", err, errBoom)
	}
}

func TestOwnershipService_Get_PropagatesUnmarshalError(t *testing.T) {
	m := NewMemStore()
	if err := m.Put(context.Background(), SessionKey("s1"), []byte("not json")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s := NewOwnershipService(m)
	_, _, err := s.Get(context.Background(), "s1")
	if err == nil {
		t.Fatal("Get with a corrupted stored value returned no error")
	}
}

func TestOwnershipService_List_PropagatesStoreError(t *testing.T) {
	s := NewOwnershipService(&errStore{listErr: errBoom})
	_, err := s.List(context.Background())
	if !errors.Is(err, errBoom) {
		t.Fatalf("List error = %v, want %v", err, errBoom)
	}
}

func TestOwnershipService_List_PropagatesUnmarshalError(t *testing.T) {
	m := NewMemStore()
	if err := m.Put(context.Background(), SessionKey("s1"), []byte("not json")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s := NewOwnershipService(m)
	_, err := s.List(context.Background())
	if err == nil {
		t.Fatal("List with a corrupted stored entry returned no error")
	}
}

func TestOwnershipService_Watch_PropagatesStoreError(t *testing.T) {
	s := NewOwnershipService(&errStore{watchErr: errBoom})
	_, err := s.Watch(context.Background())
	if !errors.Is(err, errBoom) {
		t.Fatalf("Watch error = %v, want %v", err, errBoom)
	}
}

func TestOwnershipService_Watch_SkipsMalformedEntries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewMemStore()
	s := NewOwnershipService(m)

	events, err := s.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if err := m.Put(context.Background(), SessionKey("bad"), []byte("not json")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	good := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	if _, err := s.SetIfNewer(context.Background(), good); err != nil {
		t.Fatalf("SetIfNewer: %v", err)
	}

	got := <-events
	if got != good {
		t.Fatalf("Watch delivered %+v, want the malformed entry skipped and %+v delivered instead", got, good)
	}
}

func TestOwnershipService_SetIfNewer_NoFencer_FirstWriteApplies(t *testing.T) {
	store := &plainKVStore{inner: NewMemStore()}
	s := NewOwnershipService(store)
	rec := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	applied, err := s.SetIfNewer(context.Background(), rec)
	if err != nil || !applied {
		t.Fatalf("SetIfNewer (no Fencer) on an empty session = (%v, %v), want (true, nil)", applied, err)
	}
}

func TestOwnershipService_SetIfNewer_NoFencer_RejectsStale(t *testing.T) {
	ctx := context.Background()
	store := &plainKVStore{inner: NewMemStore()}
	s := NewOwnershipService(store)
	current := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 5}
	if _, err := s.SetIfNewer(ctx, current); err != nil {
		t.Fatalf("SetIfNewer (seed): %v", err)
	}

	applied, err := s.SetIfNewer(ctx, OwnershipRecord{Session: "s1", Access: "a1", Egress: "sg", Epoch: 5})
	if err != nil {
		t.Fatalf("SetIfNewer: %v", err)
	}
	if applied {
		t.Fatal("SetIfNewer (no Fencer) applied an equal-epoch write, want it rejected")
	}
}

func TestOwnershipService_SetIfNewer_NoFencer_PropagatesGetError(t *testing.T) {
	s := NewOwnershipService(&errStore{getErr: errBoom})
	_, err := s.SetIfNewer(context.Background(), OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk"})
	if !errors.Is(err, errBoom) {
		t.Fatalf("SetIfNewer error = %v, want %v", err, errBoom)
	}
}

func TestOwnershipService_SetIfNewer_NoFencer_PropagatesPutError(t *testing.T) {
	s := NewOwnershipService(&errStore{getErr: nil, putErr: errBoom})
	_, err := s.SetIfNewer(context.Background(), OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk"})
	if !errors.Is(err, errBoom) {
		t.Fatalf("SetIfNewer error = %v, want %v", err, errBoom)
	}
}

func TestOwnershipService_SetIfNewer_Fencer_PropagatesRevisionError(t *testing.T) {
	store := &fencerErrStore{MemStore: NewMemStore(), revisionErr: errBoom}
	s := NewOwnershipService(store)
	_, err := s.SetIfNewer(context.Background(), OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk"})
	if !errors.Is(err, errBoom) {
		t.Fatalf("SetIfNewer error = %v, want %v", err, errBoom)
	}
}

func TestOwnershipService_SetIfNewer_Fencer_PropagatesCompareAndSwapError(t *testing.T) {
	store := &fencerErrStore{MemStore: NewMemStore(), casErr: errBoom}
	s := NewOwnershipService(store)
	_, err := s.SetIfNewer(context.Background(), OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk"})
	if !errors.Is(err, errBoom) {
		t.Fatalf("SetIfNewer error = %v, want %v", err, errBoom)
	}
}

func TestOwnershipService_SetIfNewer_Fencer_RetriesAfterLostRace_AndStillSucceeds(t *testing.T) {
	ctx := context.Background()
	store := &failFirstCASStore{MemStore: NewMemStore()}
	s := NewOwnershipService(store)

	rec := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	applied, err := s.SetIfNewer(ctx, rec)
	if err != nil {
		t.Fatalf("SetIfNewer: %v", err)
	}
	if !applied {
		t.Fatal("SetIfNewer did not eventually apply after one lost-race retry")
	}
	if store.calls < 2 {
		t.Fatalf("CompareAndSwap was called %d time(s), want at least 2 (the retry loop must have actually looped)", store.calls)
	}
	got, found, err := s.Get(ctx, "s1")
	if err != nil || !found || got != rec {
		t.Fatalf("Get after the retried write = (%+v, %v, %v), want (%+v, true, nil)", got, found, err, rec)
	}
}

func TestOwnershipService_SetIfNewer_Fencer_LoopGivesUpIfInterloperIsNewer(t *testing.T) {
	ctx := context.Background()
	inner := NewMemStore()
	base := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}
	baseData, _ := MarshalOwnership(base)
	if err := inner.Put(ctx, SessionKey("s1"), baseData); err != nil {
		t.Fatalf("Put: %v", err)
	}

	store := &interloperCASStore{MemStore: inner}
	s := NewOwnershipService(store)

	candidate := base.NextEpoch("sg") // Epoch 1
	applied, err := s.SetIfNewer(ctx, candidate)
	if err != nil {
		t.Fatalf("SetIfNewer: %v", err)
	}
	if applied {
		t.Fatal("SetIfNewer applied despite an equal-or-newer interloper write, want it to give up")
	}
}

type interloperCASStore struct {
	*MemStore
	calls int
}

func (f *interloperCASStore) CompareAndSwap(ctx context.Context, key string, expectedRevision int64, value []byte) (int64, bool, error) {
	f.calls++
	if f.calls == 1 {
		interloper := OwnershipRecord{Session: "s1", Access: "a1", Egress: "jp", Epoch: 1}
		data, _ := MarshalOwnership(interloper)
		_ = f.MemStore.Put(ctx, key, data)
	}
	return f.MemStore.CompareAndSwap(ctx, key, expectedRevision, value)
}
