package control

import (
	"context"
	"errors"
	"time"
)

var ErrSessionNotCached = errors.New("control: session has no cached ownership record")

type FailoverController struct {
	cache     *ConfigCache
	ownership *OwnershipService
}

func NewFailoverController(cache *ConfigCache, ownership *OwnershipService) *FailoverController {
	return &FailoverController{cache: cache, ownership: ownership}
}

func (f *FailoverController) Refresh(ctx context.Context, session string, now time.Time) error {
	rec, found, err := f.ownership.Get(ctx, session)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	f.cache.StoreOwnership(rec, now)
	return nil
}

func (f *FailoverController) Forward(session string, now time.Time) (egress string, epoch LocalEpoch, ok bool) {
	rec, epoch, _, found := f.cache.Ownership(session, now)
	if !found {
		return "", LocalEpoch{}, false
	}
	return rec.Egress, epoch, true
}

func (f *FailoverController) AttemptPlannedMigration(ctx context.Context, session string, newEgress string, now time.Time) (applied, deferred bool, err error) {
	rec, _, _, found := f.cache.Ownership(session, now)
	if !found {
		return false, false, ErrSessionNotCached
	}
	candidate := rec.NextEpoch(newEgress)
	ok, setErr := f.ownership.SetIfNewer(ctx, candidate)
	if setErr != nil {
		return false, true, nil
	}
	if !ok {
		_ = f.Refresh(ctx, session, now)
		return false, false, nil
	}
	f.cache.StoreOwnership(candidate, now)
	return true, false, nil
}

// EmergencyFailover switches the session to newEgress using only the
// local cache.
func (f *FailoverController) EmergencyFailover(session, newEgress string, now time.Time) (LocalEpoch, error) {
	rec, _, _, found := f.cache.Ownership(session, now)
	if !found {
		return LocalEpoch{}, ErrSessionNotCached
	}
	rec.Egress = newEgress
	epoch := f.cache.bumpLocal(session, rec, now)
	return epoch, nil
}

// Reconcile is called once the control plane is reachable again after a
// possible emergency failover.
func (f *FailoverController) Reconcile(ctx context.Context, session string, now time.Time) (applied bool, err error) {
	cached, localEpoch, _, found := f.cache.Ownership(session, now)
	if !found {
		return false, ErrSessionNotCached
	}

	current, foundRemote, err := f.ownership.Get(ctx, session)
	if err != nil {
		return false, err
	}
	if foundRemote && current.Epoch > localEpoch.Global {
		f.cache.StoreOwnership(current, now)
		return false, nil
	}

	if localEpoch.Local == 0 {
		return false, nil
	}

	candidate := cached.NextEpoch(cached.Egress)
	ok, err := f.ownership.SetIfNewer(ctx, candidate)
	if err != nil {
		return false, err
	}
	if !ok {
		_ = f.Refresh(ctx, session, now)
		return false, nil
	}
	f.cache.StoreOwnership(candidate, now)
	return true, nil
}
