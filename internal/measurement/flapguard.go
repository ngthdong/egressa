package measurement

import "time"

// FlapGuardConfig configures the temporal conditions required before
// approving a migration.
type FlapGuardConfig struct {
	// ConfirmationWindow is the minimum duration a candidate must
	// continuously qualify before migration is approved.
	ConfirmationWindow time.Duration

	// MinResidence is the minimum time the current path must remain active
	// before another migration can be approved.
	MinResidence time.Duration

	// Cooldown is the minimum time between approved migrations.
	Cooldown time.Duration
}

var DefaultFlapGuardConfig = FlapGuardConfig{
	ConfirmationWindow: 5 * time.Second,
	MinResidence:       30 * time.Second,
	Cooldown:           10 * time.Second,
}

// FlapGuard prevents migrations caused by short-lived or rapidly changing
// qualification signals.
//
// Evaluate must be called once per sampling tick. The caller is responsible
// for serializing access when a FlapGuard is shared across goroutines.
type FlapGuard struct {
	cfg FlapGuardConfig

	activeSince     time.Time
	lastMigrationAt time.Time
	haveMigrated    bool

	pendingCandidate string
	pendingSince     time.Time
	havePending      bool
}

func NewFlapGuard(cfg FlapGuardConfig, now time.Time) *FlapGuard {
	return &FlapGuard{cfg: cfg, activeSince: now}
}

// Evaluate records the current qualification state of candidateID and
// returns true when all migration guards are satisfied.
//
// A candidate must qualify continuously for ConfirmationWindow. The current
// path must have remained active for at least MinResidence, and the previous
// migration must be at least Cooldown old.
//
// When this returns true, the migration is considered committed and the
// guard starts tracking the new path. Callers should perform the migration
// immediately and must not evaluate the same migration again for the tick.
func (f *FlapGuard) Evaluate(now time.Time, qualifies bool, candidateID string) bool {
	if !qualifies {
		// A failed tick breaks continuous confirmation.
		f.havePending = false
		return false
	}

	if !f.havePending || f.pendingCandidate != candidateID {
		// A new candidate or a broken confirmation window starts from this tick.
		f.havePending = true
		f.pendingCandidate = candidateID
		f.pendingSince = now
	}

	if now.Sub(f.pendingSince) < f.cfg.ConfirmationWindow {
		return false
	}
	if now.Sub(f.activeSince) < f.cfg.MinResidence {
		return false
	}
	if f.haveMigrated && now.Sub(f.lastMigrationAt) < f.cfg.Cooldown {
		return false
	}

	f.activeSince = now
	f.lastMigrationAt = now
	f.haveMigrated = true
	f.havePending = false
	return true
}

func (f *FlapGuard) Pending(now time.Time) (candidateID string, confirming time.Duration, ok bool) {
	if !f.havePending {
		return "", 0, false
	}
	return f.pendingCandidate, now.Sub(f.pendingSince), true
}

func (f *FlapGuard) Residence(now time.Time) time.Duration {
	return now.Sub(f.activeSince)
}
