package tunnel

import (
	"fmt"
	"net/netip"
	"time"
)

type standbyPeerManager interface {
	AddPeer(publicKey [KeySize]byte, allowedIPs []netip.Prefix, endpoint string, keepaliveInterval time.Duration) error
	RemovePeer(publicKey [KeySize]byte) error
	LastHandshake(publicKey [KeySize]byte) (time.Time, error)
}

// StandbyCandidate identifies a not-yet-active gateway path this device
// keeps a warm WireGuard session with.
type StandbyCandidate struct {
	ID        string
	PublicKey [KeySize]byte
	Endpoint  string
}

// StandbyManager keeps one or more candidate gateway paths handshaked and
// ready, without ever carrying real traffic through them.
type StandbyManager struct {
	dev       standbyPeerManager
	keepalive time.Duration
	byID      map[string]StandbyCandidate
}

func NewStandbyManager(dev standbyPeerManager, keepalive time.Duration) (*StandbyManager, error) {
	if keepalive <= 0 {
		return nil, fmt.Errorf("tunnel: standby manager requires a positive keepalive interval, got %s", keepalive)
	}
	return &StandbyManager{dev: dev, keepalive: keepalive, byID: make(map[string]StandbyCandidate)}, nil
}

func (m *StandbyManager) Add(candidate StandbyCandidate) error {
	if existing, ok := m.byID[candidate.ID]; ok && existing.PublicKey != candidate.PublicKey {
		if err := m.dev.RemovePeer(existing.PublicKey); err != nil {
			return fmt.Errorf("tunnel: replace standby candidate %s: remove old peer: %w", candidate.ID, err)
		}
	}
	if err := m.dev.AddPeer(candidate.PublicKey, nil, candidate.Endpoint, m.keepalive); err != nil {
		return fmt.Errorf("tunnel: add standby candidate %s: %w", candidate.ID, err)
	}
	m.byID[candidate.ID] = candidate
	return nil
}

func (m *StandbyManager) Remove(id string) error {
	candidate, ok := m.byID[id]
	if !ok {
		return nil
	}
	if err := m.dev.RemovePeer(candidate.PublicKey); err != nil {
		return fmt.Errorf("tunnel: remove standby candidate %s: %w", id, err)
	}
	delete(m.byID, id)
	return nil
}

// IsWarm reports whether the candidate identified by id has completed a
// handshake within the last maxAge. A candidate that has never
// handshaked at all (unreachable endpoint, wrong key, not yet due for its
// first keepalive, ...) is never warm.
func (m *StandbyManager) IsWarm(id string, maxAge time.Duration) (bool, error) {
	candidate, ok := m.byID[id]
	if !ok {
		return false, fmt.Errorf("tunnel: unknown standby candidate %s", id)
	}
	last, err := m.dev.LastHandshake(candidate.PublicKey)
	if err != nil {
		return false, fmt.Errorf("tunnel: standby candidate %s: %w", id, err)
	}
	if last.IsZero() {
		return false, nil
	}
	return time.Since(last) <= maxAge, nil
}

func (m *StandbyManager) Candidates() []string {
	ids := make([]string, 0, len(m.byID))
	for id := range m.byID {
		ids = append(ids, id)
	}
	return ids
}
