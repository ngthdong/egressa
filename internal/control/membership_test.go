package control

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestGatewayRole_String(t *testing.T) {
	cases := []struct {
		role GatewayRole
		want string
	}{
		{RoleAccess, "access"},
		{RoleEgress, "egress"},
		{RoleAccess | RoleEgress, "access+egress"},
		{0, "none"},
	}
	for _, c := range cases {
		if got := c.role.String(); got != c.want {
			t.Errorf("GatewayRole(%d).String() = %q, want %q", c.role, got, c.want)
		}
	}
}

func TestGatewayMember_Validate(t *testing.T) {
	valid := GatewayMember{ID: "gw1", Roles: RoleAccess, Address: "10.0.0.1:51820"}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate() on a well-formed member: %v", err)
	}
	cases := []GatewayMember{
		{Roles: RoleAccess, Address: "10.0.0.1:51820"},
		{ID: "gw1", Address: "10.0.0.1:51820"},
		{ID: "gw1", Roles: RoleAccess},
	}
	for _, c := range cases {
		if err := c.Validate(); err == nil {
			t.Errorf("Validate(%+v) = nil, want an error", c)
		}
	}
}

func TestMembershipService_PutList(t *testing.T) {
	ctx := context.Background()
	s := NewMembershipService(NewMemStore())
	m1 := GatewayMember{ID: "gw1", Roles: RoleAccess | RoleEgress, Address: "10.0.0.1:51820"}
	m2 := GatewayMember{ID: "gw2", Roles: RoleEgress, Address: "10.0.0.2:51820"}

	if err := s.Put(ctx, m1); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Put(ctx, m2); err != nil {
		t.Fatalf("Put: %v", err)
	}

	members, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("List returned %d members, want 2", len(members))
	}
}

func TestMembershipService_Watch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := NewMembershipService(NewMemStore())

	events, err := s.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	m := GatewayMember{ID: "gw1", Roles: RoleAccess, Address: "10.0.0.1:51820"}
	if err := s.Put(context.Background(), m); err != nil {
		t.Fatalf("Put: %v", err)
	}

	select {
	case got := <-events:
		if got != m {
			t.Fatalf("Watch delivered %+v, want %+v", got, m)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for Watch to deliver the Put")
	}
}

func TestMarshalMembership_RejectsInvalid(t *testing.T) {
	if _, err := MarshalMembership(GatewayMember{ID: "gw1"}); err == nil {
		t.Fatal("MarshalMembership accepted a member missing Address/Roles")
	}
}

func TestUnmarshalMembership_RejectsInvalid(t *testing.T) {
	if _, err := UnmarshalMembership([]byte("not json")); err == nil {
		t.Fatal("UnmarshalMembership accepted malformed JSON")
	}
	if _, err := UnmarshalMembership([]byte(`{"id":"","address":"a","roles":1}`)); err == nil {
		t.Fatal("UnmarshalMembership accepted a member with an empty ID")
	}
}

func TestMembershipService_Put_PropagatesMarshalError(t *testing.T) {
	s := NewMembershipService(NewMemStore())
	if err := s.Put(context.Background(), GatewayMember{ID: "gw1"}); err == nil {
		t.Fatal("Put accepted an invalid GatewayMember")
	}
}

func TestMembershipService_Put_PropagatesStoreError(t *testing.T) {
	s := NewMembershipService(&errStore{putErr: errBoom})
	m := GatewayMember{ID: "gw1", Roles: RoleAccess, Address: "10.0.0.1:1"}
	if err := s.Put(context.Background(), m); !errors.Is(err, errBoom) {
		t.Fatalf("Put error = %v, want %v", err, errBoom)
	}
}

func TestMembershipService_List_PropagatesStoreError(t *testing.T) {
	s := NewMembershipService(&errStore{listErr: errBoom})
	if _, err := s.List(context.Background()); !errors.Is(err, errBoom) {
		t.Fatalf("List error = %v, want %v", err, errBoom)
	}
}

func TestMembershipService_List_PropagatesUnmarshalError(t *testing.T) {
	m := NewMemStore()
	if err := m.Put(context.Background(), GatewayKey("bad"), []byte("not json")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	s := NewMembershipService(m)
	if _, err := s.List(context.Background()); err == nil {
		t.Fatal("List with a corrupted stored entry returned no error")
	}
}

func TestMembershipService_Watch_PropagatesStoreError(t *testing.T) {
	s := NewMembershipService(&errStore{watchErr: errBoom})
	if _, err := s.Watch(context.Background()); !errors.Is(err, errBoom) {
		t.Fatalf("Watch error = %v, want %v", err, errBoom)
	}
}

func TestMembershipService_Watch_SkipsMalformedEntries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewMemStore()
	s := NewMembershipService(m)

	events, err := s.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	if err := m.Put(context.Background(), GatewayKey("bad"), []byte("not json")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	good := GatewayMember{ID: "gw1", Roles: RoleAccess, Address: "10.0.0.1:1"}
	if err := s.Put(context.Background(), good); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got := <-events
	if got != good {
		t.Fatalf("Watch delivered %+v, want the malformed entry skipped and %+v delivered instead", got, good)
	}
}
