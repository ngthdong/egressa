package client

import (
	"fmt"
	"math"
	"time"

	"github.com/ngthdong/egressa/internal/control"
	"github.com/ngthdong/egressa/internal/handoff"
	"github.com/ngthdong/egressa/internal/measurement"
)

// Path is one way to carry the session: in through Access, out through
// Egress. Segments are client->Access, then Access->Egress over the
// backbone when they differ. Egress->Internet is not measured: two paths
// to the same egress share it, so it cancels out of their comparison.
type Path struct {
	Access string
	Egress string
	// Segments are as measurement.PathCandidate wants them.
	Segments []measurement.SegmentStats
	// Reachable is false when the client has heard nothing back through
	// Access recently, or a segment has never been measured.
	Reachable bool
}

func (p Path) candidate() measurement.PathCandidate {
	return measurement.PathCandidate{EgressID: p.Egress, Segments: p.Segments}
}

// Decision is what Decider.Decide concluded.
type Decision struct {
	Migrate bool
	Access  string
	Egress  string
	Reason  string
}

// Decider chooses when to move the session to another path. Between
// paths to the same egress it moves only when measurement.DecideMigration
// is confident the candidate is better by more than the migration cost,
// and measurement.FlapGuard (through handoff.ShouldCutover) has seen that
// hold for long enough. When the current path is dead it moves at once.
// It changes egress, which breaks the session's open TCP connections,
// only when no path to the current egress works.
type Decider struct {
	policy control.PolicyDocument
	flap   *measurement.FlapGuard
}

// NewDecider returns a Decider for policy.
func NewDecider(policy control.PolicyDocument, now time.Time) *Decider {
	return &Decider{policy: policy, flap: measurement.NewFlapGuard(policy.FlapGuard, now)}
}

// Policy returns the decider's policy.
func (d *Decider) Policy() control.PolicyDocument { return d.policy }

// Reset restarts the flap guard's clock, after the path changed.
func (d *Decider) Reset(now time.Time) { d.flap = measurement.NewFlapGuard(d.policy.FlapGuard, now) }

func (d *Decider) cost(p Path) float64 {
	return measurement.ScorePath(p.candidate(), d.policy.Cost).Cost
}

// cheapest returns the reachable, ungated path with the lowest cost among
// those keep accepts.
func (d *Decider) cheapest(paths []Path, keep func(Path) bool) (Path, bool) {
	best, found := Path{}, false
	bestCost := math.Inf(1)
	for _, p := range paths {
		if !p.Reachable || !keep(p) {
			continue
		}
		if c := d.cost(p); c < bestCost {
			best, bestCost, found = p, c, true
		}
	}
	return best, found
}

// Decide looks at every known path once. currentDead says the current
// path has stopped answering.
func (d *Decider) Decide(now time.Time, access, egress string, paths []Path, currentDead bool) Decision {
	other := func(p Path) bool { return p.Egress == egress && p.Access != access }
	if currentDead {
		if p, ok := d.cheapest(paths, other); ok && handoff.ShouldCutover(d.flap, true, now, true, p.Access) {
			return Decision{Migrate: true, Access: p.Access, Egress: p.Egress,
				Reason: fmt.Sprintf("access %s stopped answering", access)}
		}
		if p, ok := d.cheapest(paths, func(p Path) bool { return p.Egress != egress }); ok {
			return Decision{Migrate: true, Access: p.Access, Egress: p.Egress,
				Reason: fmt.Sprintf("no path to egress %s works; changing egress (open connections will break)", egress)}
		}
		return Decision{Reason: "the current path is dead and no other path answers"}
	}

	var current Path
	haveCurrent := false
	for _, p := range paths {
		if p.Access == access && p.Egress == egress {
			current, haveCurrent = p, true
			break
		}
	}
	if !haveCurrent {
		d.flap.Evaluate(now, false, "")
		return Decision{Reason: "the current path is not measured yet"}
	}

	// Of the candidates that clear the bar, the one surest to be better:
	// the highest lower confidence bound on the improvement.
	var best Path
	var bestDec measurement.MigrationDecision
	found := false
	for _, p := range paths {
		if !p.Reachable || !other(p) {
			continue
		}
		dec, err := measurement.DecideMigration(current.candidate(), p.candidate(), 0, d.policy.Cost, d.policy.Decision)
		if err != nil {
			continue
		}
		if !found || dec.Delta.Lower > bestDec.Delta.Lower {
			best, bestDec, found = p, dec, true
		}
	}
	if !found || !bestDec.Migrate {
		d.flap.Evaluate(now, false, "")
		return Decision{}
	}
	if !handoff.ShouldCutover(d.flap, false, now, true, best.Access) {
		return Decision{Reason: fmt.Sprintf("%s looks better; confirming", best.Access)}
	}
	return Decision{
		Migrate: true, Access: best.Access, Egress: best.Egress,
		Reason: fmt.Sprintf("path via %s is better by at least %.1f ms (95%% bound)", best.Access, bestDec.Delta.Lower/1000),
	}
}
