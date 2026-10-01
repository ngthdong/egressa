package ipsec

import (
	"context"
	"fmt"
	"time"
)

// DefaultPollInterval is the fallback re-query period while waiting on an
// SA. Waiting is driven by ike-updown/child-updown events; the poll only
// catches events that were lost, so it is deliberately long.
const DefaultPollInterval = 30 * time.Second

// IsWarm reports whether connection conn currently has a warm SA: an
// established IKE_SA with an installed CHILD_SA. No route needs to point
// at it, which is exactly what a warm standby is.
func IsWarm(ctx context.Context, ike IKE, conn string) (bool, error) {
	sas, err := ike.ListSAs(ctx, conn)
	if err != nil {
		return false, err
	}
	sa, ok := FindIKE(sas, conn)
	return ok && sa.Warm(), nil
}

// WaitWarm blocks until connection conn has a warm SA, and returns it.
func WaitWarm(ctx context.Context, ike IKE, conn string, poll time.Duration) (IKESA, error) {
	var warm IKESA
	err := waitSAs(ctx, ike, conn, poll, func(sas []IKESA) bool {
		sa, ok := FindIKE(sas, conn)
		if ok && sa.Warm() {
			warm = sa
			return true
		}
		return false
	})
	if err != nil {
		return IKESA{}, fmt.Errorf("ipsec: waiting for %s to become warm: %w", conn, err)
	}
	return warm, nil
}

// WaitDown blocks until connection conn has no established IKE_SA, for
// example after dead peer detection (dpd_action=clear) gave up on it.
func WaitDown(ctx context.Context, ike IKE, conn string, poll time.Duration) error {
	err := waitSAs(ctx, ike, conn, poll, func(sas []IKESA) bool {
		for _, sa := range sas {
			if sa.Name == conn && sa.State == IKEStateEstablished {
				return false
			}
		}
		return true
	})
	if err != nil {
		return fmt.Errorf("ipsec: waiting for %s to go down: %w", conn, err)
	}
	return nil
}

// waitSAs re-evaluates done against conn's SAs whenever an event mentions
// conn, whenever events may have been lost (EventResync), and every poll
// interval as a fallback, until done is satisfied or ctx ends.
//
// It subscribes before the first query, so a transition that happens
// between the query and the subscription cannot be missed. A query that
// fails after the first one is retried at the next trigger rather than
// aborting the wait: a daemon restart should not end a wait that its
// context still allows.
func waitSAs(ctx context.Context, ike IKE, conn string, poll time.Duration, done func([]IKESA) bool) error {
	if poll <= 0 {
		poll = DefaultPollInterval
	}
	events, cancel := ike.Subscribe()
	defer cancel()

	sas, err := ike.ListSAs(ctx, conn)
	if err != nil {
		return err
	}
	if done(sas) {
		return nil
	}

	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("%w (last query error: %v)", ctx.Err(), lastErr)
			}
			return ctx.Err()
		case ev, ok := <-events:
			if !ok {
				events = nil // the IKE is closing; keep polling until ctx ends
				continue
			}
			if ev.Kind != EventResync && ev.IKE.Name != conn {
				continue
			}
		case <-ticker.C:
		}
		sas, err := ike.ListSAs(ctx, conn)
		if err != nil {
			lastErr = err
			continue
		}
		lastErr = nil
		if done(sas) {
			return nil
		}
	}
}
