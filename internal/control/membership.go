package control

import (
	"context"
	"encoding/json"
	"fmt"
)

type GatewayRole int

const (
	RoleAccess GatewayRole = 1 << 0
	RoleEgress GatewayRole = 1 << 1
)

func (r GatewayRole) Has(role GatewayRole) bool { return r&role != 0 }

func (r GatewayRole) String() string {
	switch {
	case r.Has(RoleAccess) && r.Has(RoleEgress):
		return "access+egress"
	case r.Has(RoleAccess):
		return "access"
	case r.Has(RoleEgress):
		return "egress"
	default:
		return "none"
	}
}

type GatewayMember struct {
	ID      string      `json:"id"`
	Roles   GatewayRole `json:"roles"`
	Address string      `json:"address"`
}

func (m GatewayMember) Validate() error {
	if m.ID == "" {
		return fmt.Errorf("control: GatewayMember.ID must not be empty")
	}
	if m.Address == "" {
		return fmt.Errorf("control: GatewayMember.Address must not be empty")
	}
	if m.Roles == 0 {
		return fmt.Errorf("control: GatewayMember.Roles must specify at least one role")
	}
	return nil
}

const membershipKeyPrefix = "/egressa/gateway/"

func GatewayKey(id string) string { return membershipKeyPrefix + id }

func MarshalMembership(m GatewayMember) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

func UnmarshalMembership(data []byte) (GatewayMember, error) {
	var m GatewayMember
	if err := json.Unmarshal(data, &m); err != nil {
		return GatewayMember{}, fmt.Errorf("control: decoding GatewayMember: %w", err)
	}
	if err := m.Validate(); err != nil {
		return GatewayMember{}, err
	}
	return m, nil
}

type MembershipService struct {
	store KVStore
}

func NewMembershipService(store KVStore) *MembershipService {
	return &MembershipService{store: store}
}

func (s *MembershipService) Put(ctx context.Context, m GatewayMember) error {
	data, err := MarshalMembership(m)
	if err != nil {
		return err
	}
	return s.store.Put(ctx, GatewayKey(m.ID), data)
}

func (s *MembershipService) List(ctx context.Context) ([]GatewayMember, error) {
	raw, err := s.store.List(ctx, membershipKeyPrefix)
	if err != nil {
		return nil, err
	}
	members := make([]GatewayMember, 0, len(raw))
	for _, data := range raw {
		m, err := UnmarshalMembership(data)
		if err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, nil
}

func (s *MembershipService) Watch(ctx context.Context) (<-chan GatewayMember, error) {
	events, err := s.store.Watch(ctx, membershipKeyPrefix)
	if err != nil {
		return nil, err
	}
	out := make(chan GatewayMember)
	go func() {
		defer close(out)
		for ev := range events {
			if ev.Deleted {
				continue
			}
			m, err := UnmarshalMembership(ev.Value)
			if err != nil {
				continue
			}
			select {
			case out <- m:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}
