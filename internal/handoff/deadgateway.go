package handoff

import (
	"time"

	"github.com/ngthdong/egressa/internal/measurement"
)

// ShouldCutover returns whether a migration should proceed.
// Dead gateways bypass FlapGuard and cut over immediately;
// normal migrations are evaluated by FlapGuard.
func ShouldCutover(flap *measurement.FlapGuard, deadGateway bool, now time.Time, qualifies bool, candidateID string) bool {
	if deadGateway {
		return true
	}
	return flap.Evaluate(now, qualifies, candidateID)
}
