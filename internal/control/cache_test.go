package control

import (
	"testing"
	"time"
)

func TestLocalEpoch_Less(t *testing.T) {
	cases := []struct {
		name string
		a, b LocalEpoch
		want bool
	}{
		{"lower global is less regardless of local", LocalEpoch{Global: 1, Local: 99}, LocalEpoch{Global: 2, Local: 0}, true},
		{"higher global is never less", LocalEpoch{Global: 2, Local: 0}, LocalEpoch{Global: 1, Local: 99}, false},
		{"equal global compares by local", LocalEpoch{Global: 1, Local: 0}, LocalEpoch{Global: 1, Local: 1}, true},
		{"equal in every field is not less", LocalEpoch{Global: 1, Local: 1}, LocalEpoch{Global: 1, Local: 1}, false},
	}
	for _, c := range cases {
		if got := c.a.Less(c.b); got != c.want {
			t.Errorf("%s: (%+v).Less(%+v) = %v, want %v", c.name, c.a, c.b, got, c.want)
		}
	}
}

func TestConfigCache_StoreOwnership_Get(t *testing.T) {
	c := NewConfigCache()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rec := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 3}
	c.StoreOwnership(rec, now)

	gotRec, gotEpoch, age, ok := c.Ownership("s1", now)
	if !ok {
		t.Fatal("Ownership() ok = false right after StoreOwnership")
	}
	if gotRec != rec {
		t.Fatalf("Ownership() record = %+v, want %+v", gotRec, rec)
	}
	if gotEpoch != (LocalEpoch{Global: 3, Local: 0}) {
		t.Fatalf("Ownership() epoch = %+v, want {Global:3 Local:0}", gotEpoch)
	}
	if age != 0 {
		t.Fatalf("Ownership() age = %v, want 0 right after storing", age)
	}
}

func TestConfigCache_Ownership_UnknownSession(t *testing.T) {
	c := NewConfigCache()
	_, _, _, ok := c.Ownership("nope", time.Now())
	if ok {
		t.Fatal("Ownership() ok = true for a session never stored")
	}
}

func TestConfigCache_Ownership_AgeReflectsElapsedTime(t *testing.T) {
	c := NewConfigCache()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.StoreOwnership(OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 0}, t0)

	later := t0.Add(90 * time.Second)
	_, _, age, ok := c.Ownership("s1", later)
	if !ok {
		t.Fatal("Ownership() ok = false")
	}
	if age != 90*time.Second {
		t.Fatalf("age = %v, want 90s", age)
	}
}

func TestConfigCache_StoreOwnership_ResetsLocalEpoch(t *testing.T) {
	c := NewConfigCache()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	base := OwnershipRecord{Session: "s1", Access: "a1", Egress: "hk", Epoch: 3}
	c.StoreOwnership(base, t0)
	c.bumpLocal("s1", OwnershipRecord{Session: "s1", Access: "a1", Egress: "sg", Epoch: 3}, t0)

	if _, epoch, _, _ := c.Ownership("s1", t0); epoch.Local == 0 {
		t.Fatal("bumpLocal did not advance Local")
	}

	// A fresh control-plane confirmation must reset Local back to 0,
	// even though the new record's Epoch happens to be higher.
	c.StoreOwnership(OwnershipRecord{Session: "s1", Access: "a1", Egress: "jp", Epoch: 4}, t0)
	_, epoch, _, _ := c.Ownership("s1", t0)
	if epoch != (LocalEpoch{Global: 4, Local: 0}) {
		t.Fatalf("Ownership() epoch after a fresh StoreOwnership = %+v, want {Global:4 Local:0}", epoch)
	}
}

func TestConfigCache_Policy_DefaultsWhenUnset(t *testing.T) {
	c := NewConfigCache()
	if got := c.Policy(); got != DefaultPolicyDocument {
		t.Fatalf("Policy() before StorePolicy = %+v, want DefaultPolicyDocument", got)
	}
}

func TestConfigCache_StorePolicy_Get(t *testing.T) {
	c := NewConfigCache()
	doc := DefaultPolicyDocument.NextVersion()
	c.StorePolicy(doc)
	if got := c.Policy(); got != doc {
		t.Fatalf("Policy() = %+v, want %+v", got, doc)
	}
}
