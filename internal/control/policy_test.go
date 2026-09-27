package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ngthdong/egressa/internal/measurement"
)

func TestPolicyService_Get_DefaultsWhenUnset(t *testing.T) {
	s := NewPolicyService(NewMemStore())
	got, err := s.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != DefaultPolicyDocument {
		t.Fatalf("Get() before any Set = %+v, want DefaultPolicyDocument", got)
	}
}

func TestPolicyService_SetGet_RoundTrip(t *testing.T) {
	ctx := context.Background()
	s := NewPolicyService(NewMemStore())
	doc := DefaultPolicyDocument.NextVersion()
	doc.Decision.MigrationCost = 12345

	if err := s.Set(ctx, doc); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := s.Get(ctx)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != doc {
		t.Fatalf("Get() = %+v, want %+v", got, doc)
	}
	if got.Version != 1 {
		t.Fatalf("Version = %d, want 1", got.Version)
	}
}

func TestPolicyDocument_RoundTripsThroughJSON(t *testing.T) {
	doc := PolicyDocument{
		Version:   3,
		Cost:      measurement.CostWeights{TailWeight: 1, LossWeight: 1000, LossGate: 0.5, MaxCapacityFraction: 0.9},
		Decision:  measurement.DecisionWeights{Z: 1.645, MigrationCost: 500, SafetyMargin: 100},
		FlapGuard: measurement.FlapGuardConfig{ConfirmationWindow: 5 * time.Second, MinResidence: 30 * time.Second, Cooldown: 10 * time.Second},
	}
	data, err := MarshalPolicy(doc)
	if err != nil {
		t.Fatalf("MarshalPolicy: %v", err)
	}
	got, err := UnmarshalPolicy(data)
	if err != nil {
		t.Fatalf("UnmarshalPolicy: %v", err)
	}
	if got != doc {
		t.Fatalf("round-trip = %+v, want %+v", got, doc)
	}
}

func TestPolicyService_Watch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewPolicyService(NewMemStore())

	events, err := s.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	doc := DefaultPolicyDocument.NextVersion()
	if err := s.Set(context.Background(), doc); err != nil {
		t.Fatalf("Set: %v", err)
	}

	select {
	case got := <-events:
		if got != doc {
			t.Fatalf("Watch delivered %+v, want %+v", got, doc)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Watch to deliver the Set")
	}
}

func TestPolicyDocument_NextVersion(t *testing.T) {
	v0 := DefaultPolicyDocument
	v1 := v0.NextVersion()
	if v1.Version != v0.Version+1 {
		t.Fatalf("NextVersion().Version = %d, want %d", v1.Version, v0.Version+1)
	}
	if v0.Version != 0 {
		t.Fatalf("NextVersion mutated the receiver: v0.Version = %d", v0.Version)
	}
}

func TestUnmarshalPolicy_RejectsMalformedJSON(t *testing.T) {
	if _, err := UnmarshalPolicy([]byte("not json")); err == nil {
		t.Fatal("UnmarshalPolicy accepted malformed JSON")
	}
}

func TestPolicyService_Get_PropagatesStoreError(t *testing.T) {
	s := NewPolicyService(&errStore{getErr: errBoom})
	if _, err := s.Get(context.Background()); !errors.Is(err, errBoom) {
		t.Fatalf("Get error = %v, want %v", err, errBoom)
	}
}

func TestPolicyService_Get_PropagatesUnmarshalError(t *testing.T) {
	m := NewMemStore()
	if err := m.Put(context.Background(), policyKey, []byte("not json")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s := NewPolicyService(m)
	if _, err := s.Get(context.Background()); err == nil {
		t.Fatal("Get with a corrupted stored policy returned no error")
	}
}

func TestPolicyService_Set_PropagatesStoreError(t *testing.T) {
	s := NewPolicyService(&errStore{putErr: errBoom})
	if err := s.Set(context.Background(), DefaultPolicyDocument); !errors.Is(err, errBoom) {
		t.Fatalf("Set error = %v, want %v", err, errBoom)
	}
}

func TestPolicyService_Watch_PropagatesStoreError(t *testing.T) {
	s := NewPolicyService(&errStore{watchErr: errBoom})
	if _, err := s.Watch(context.Background()); !errors.Is(err, errBoom) {
		t.Fatalf("Watch error = %v, want %v", err, errBoom)
	}
}

func TestPolicyService_Watch_SkipsMalformedEntries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewMemStore()
	s := NewPolicyService(m)

	events, err := s.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if err := m.Put(context.Background(), policyKey, []byte("not json")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	good := DefaultPolicyDocument.NextVersion()
	if err := s.Set(context.Background(), good); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got := <-events
	if got != good {
		t.Fatalf("Watch delivered %+v, want the malformed entry skipped and %+v delivered instead", got, good)
	}
}
