package handoff

import (
	"context"
	"errors"
	"time"

	"github.com/ngthdong/egressa/internal/control"
)

var ErrNotReady = errors.New(
	"handoff: standby is not ready for the epoch this cutover would commit",
)

type CutoverResult struct {
	Session     string
	OldAccess   string
	NewAccess   string
	Egress      string
	Epoch       uint64
	State       AccessState
	CommittedAt time.Time
}

type CutoverController struct {
	armer     *StandbyArmer
	ownership *control.OwnershipService
}

func NewCutoverController(
	armer *StandbyArmer,
	ownership *control.OwnershipService,
) *CutoverController {
	return &CutoverController{armer: armer, ownership: ownership}
}

func (c *CutoverController) Cutover(
	ctx context.Context,
	session, newAccess string,
	current control.OwnershipRecord,
	now time.Time,
) (result CutoverResult, ok bool, err error) {
	wantEpoch := current.Epoch + 1

	state, consumed := c.armer.ConsumeReady(session, wantEpoch)
	if !consumed {
		return CutoverResult{}, false, ErrNotReady
	}

	candidate := current.NextAccessEpoch(newAccess)
	applied, err := c.ownership.SetIfNewer(ctx, candidate)
	if err != nil {
		return CutoverResult{}, false, err
	}
	if !applied {
		return CutoverResult{}, false, nil
	}

	return CutoverResult{
		Session:     session,
		OldAccess:   current.Access,
		NewAccess:   newAccess,
		Egress:      candidate.Egress,
		Epoch:       candidate.Epoch,
		State:       state,
		CommittedAt: now,
	}, true, nil
}
