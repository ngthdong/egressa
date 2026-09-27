package control

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestMemStore_PutGet(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	if _, found, err := m.Get(ctx, "k1"); err != nil || found {
		t.Fatalf("Get on empty store = (_, %v, %v), want not found", found, err)
	}
	if err := m.Put(ctx, "k1", []byte("v1")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	v, found, err := m.Get(ctx, "k1")
	if err != nil || !found || string(v) != "v1" {
		t.Fatalf("Get = (%q, %v, %v), want (v1, true, nil)", v, found, err)
	}
}

func TestMemStore_Get_ReturnsACopy(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	original := []byte("v1")
	if err := m.Put(ctx, "k1", original); err != nil {
		t.Fatalf("Put: %v", err)
	}
	original[0] = 'X' // mutate the caller's own slice after Put
	v, _, _ := m.Get(ctx, "k1")
	if string(v) != "v1" {
		t.Fatalf("Get returned %q, want the store's copy unaffected by the caller mutating its original slice", v)
	}
}

func TestMemStore_List_FiltersByPrefix(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	if err := m.Put(ctx, "/a/1", []byte("1")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := m.Put(ctx, "/a/2", []byte("2")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := m.Put(ctx, "/b/1", []byte("3")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := m.List(ctx, "/a/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("List(\"/a/\") returned %d entries, want 2", len(got))
	}
	if string(got["/a/1"]) != "1" || string(got["/a/2"]) != "2" {
		t.Fatalf("List(\"/a/\") = %v, want {/a/1:1, /a/2:2}", got)
	}
}

func TestMemStore_Watch_ReceivesSubsequentWrites(t *testing.T) {
	m := NewMemStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, err := m.Watch(ctx, "/a/")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if err := m.Put(context.Background(), "/a/1", []byte("v1")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := m.Put(context.Background(), "/b/1", []byte("v2")); err != nil { // different prefix, must not arrive
		t.Fatalf("Put: %v", err)
	}

	select {
	case ev := <-events:
		if ev.Key != "/a/1" || string(ev.Value) != "v1" {
			t.Fatalf("first event = %+v, want Key=/a/1 Value=v1", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the watched write")
	}

	select {
	case ev := <-events:
		t.Fatalf("received an unexpected second event %+v, a write to a different prefix must not be delivered", ev)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestMemStore_Watch_ClosesOnContextCancel(t *testing.T) {
	m := NewMemStore()
	ctx, cancel := context.WithCancel(context.Background())
	events, err := m.Watch(ctx, "/a/")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	cancel()

	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("received a value on the watch channel instead of it closing")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the watch channel to close after cancel")
	}
}

func TestMemStore_CompareAndSwap_SucceedsOnMatchingRevision(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()

	rev, ok, err := m.CompareAndSwap(ctx, "k1", 0, []byte("v1"))
	if err != nil || !ok {
		t.Fatalf("CompareAndSwap on a nonexistent key with expected=0 = (_, %v, %v), want ok=true", ok, err)
	}

	rev2, ok, err := m.CompareAndSwap(ctx, "k1", rev, []byte("v2"))
	if err != nil || !ok {
		t.Fatalf("CompareAndSwap with the correct current revision = (_, %v, %v), want ok=true", ok, err)
	}
	if rev2 <= rev {
		t.Fatalf("revision did not advance: %d -> %d", rev, rev2)
	}
}

func TestMemStore_CompareAndSwap_FailsOnStaleRevision(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	if err := m.Put(ctx, "k1", []byte("v1")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	rev, _, _ := m.Revision(ctx, "k1")

	// A stale caller believes the revision is one less than it actually is.
	_, ok, err := m.CompareAndSwap(ctx, "k1", rev-1, []byte("v2"))
	if err != nil {
		t.Fatalf("CompareAndSwap: %v", err)
	}
	if ok {
		t.Fatal("CompareAndSwap succeeded against a stale expected revision")
	}
	v, _, _ := m.Get(ctx, "k1")
	if string(v) != "v1" {
		t.Fatalf("value changed to %q despite the failed CompareAndSwap", v)
	}
}

func TestMemStore_CompareAndSwap_ExactlyOneWinnerUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()

	const n = 10
	var wg sync.WaitGroup
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, ok, err := m.CompareAndSwap(ctx, "contested", 0, []byte("mine"))
			if err != nil {
				t.Errorf("CompareAndSwap: %v", err)
			}
			results[i] = ok
		}(i)
	}
	wg.Wait()

	winners := 0
	for _, ok := range results {
		if ok {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("winners = %d, want exactly 1", winners)
	}
}
