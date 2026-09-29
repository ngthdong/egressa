package handoff

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

type ArmPhase int

const (
	PhaseIdle ArmPhase = iota
	PhasePrepare
	PhaseReady
)

func (p ArmPhase) String() string {
	switch p {
	case PhaseIdle:
		return "idle"
	case PhasePrepare:
		return "prepare"
	case PhaseReady:
		return "ready"
	default:
		return fmt.Sprintf("ArmPhase(%d)", int(p))
	}
}

var (
	ErrSessionMismatch = errors.New("handoff: access state session does not match armed session")
	ErrStaleEpoch      = errors.New("handoff: prepare targets an epoch older than the one already armed")
	ErrNoArmInProgress = errors.New("handoff: mark-ready called with no arm in progress")
	ErrEpochMismatch   = errors.New("handoff: mark-ready epoch does not match the armed target epoch")
)

type AccessState struct {
	SessionID    string
	VirtualIP    string
	SeqHighWater uint64
}

func (s AccessState) Validate() error {
	if s.SessionID == "" {
		return errors.New("handoff: access state has empty SessionID")
	}
	if s.VirtualIP == "" {
		return errors.New("handoff: access state has empty VirtualIP")
	}
	return nil
}

type armEntry struct {
	phase       ArmPhase
	targetEpoch uint64
	state       AccessState
	armedAt     time.Time
}

type StandbyArmer struct {
	mu   sync.Mutex
	arms map[string]armEntry
}

func NewStandbyArmer() *StandbyArmer {
	return &StandbyArmer{arms: make(map[string]armEntry)}
}

func (a *StandbyArmer) Prepare(session string, currentEpoch uint64, state AccessState, now time.Time) error {
	if state.SessionID != session {
		return ErrSessionMismatch
	}
	if err := state.Validate(); err != nil {
		return err
	}
	target := currentEpoch + 1

	a.mu.Lock()
	defer a.mu.Unlock()

	existing, found := a.arms[session]
	if found && target < existing.targetEpoch {
		return ErrStaleEpoch
	}

	phase := PhasePrepare
	if found && target == existing.targetEpoch && existing.phase == PhaseReady {
		phase = PhaseReady
	}
	a.arms[session] = armEntry{
		phase:       phase,
		targetEpoch: target,
		state:       state,
		armedAt:     now,
	}
	return nil
}

func (a *StandbyArmer) MarkReady(session string, epoch uint64) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	existing, found := a.arms[session]
	if !found || existing.phase == PhaseIdle {
		return ErrNoArmInProgress
	}
	if existing.targetEpoch != epoch {
		return ErrEpochMismatch
	}
	existing.phase = PhaseReady
	a.arms[session] = existing
	return nil
}

func (a *StandbyArmer) ConsumeReady(session string, epoch uint64) (AccessState, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, found := a.arms[session]
	if !found || e.phase != PhaseReady || e.targetEpoch != epoch {
		return AccessState{}, false
	}
	delete(a.arms, session)
	return e.state, true
}

func (a *StandbyArmer) Reset(session string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.arms, session)
}

func (a *StandbyArmer) Phase(session string) ArmPhase {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.arms[session].phase
}

func (a *StandbyArmer) Snapshot(session string) (targetEpoch uint64, state AccessState, phase ArmPhase, armedAt time.Time, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, found := a.arms[session]
	if !found {
		return 0, AccessState{}, PhaseIdle, time.Time{}, false
	}
	return e.targetEpoch, e.state, e.phase, e.armedAt, true
}
