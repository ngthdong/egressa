package ipsec

import (
	"context"
	"errors"
	"fmt"
)

// IKE is the control surface of the IKE daemon (strongSwan's charon) that
// the IPsec backend needs. egressa never speaks IKE or does crypto itself:
// it loads configuration into charon, asks it to start or tear down SAs,
// and listens to what charon reports. Client and Gateway depend only on
// this interface, so their logic is unit-tested with a fake; ViciIKE is
// the real implementation, over charon's vici socket.
type IKE interface {
	// LoadConn loads (or replaces) one connection. Already established
	// SAs keep running on the configuration they were created with.
	LoadConn(ctx context.Context, c Connection) error
	// UnloadConn removes a connection's configuration. It does not tear
	// down SAs created from it; terminate them first.
	UnloadConn(ctx context.Context, name string) error
	// LoadShared loads a pre-shared key straight into charon's memory, so
	// no secret is ever written to disk.
	LoadShared(ctx context.Context, s SharedSecret) error
	UnloadShared(ctx context.Context, id string) error

	// Initiate establishes the CHILD_SA child of connection ike, creating
	// the IKE_SA first if needed, and returns once charon reports the
	// result. A rejected pre-shared key fails with ErrAuthFailed.
	Initiate(ctx context.Context, ike, child string) error
	// TerminateIKE tears down every IKE_SA of connection ike.
	TerminateIKE(ctx context.Context, ike string) error
	// TerminateIKEByID tears down exactly one IKE_SA.
	TerminateIKEByID(ctx context.Context, uniqueID uint64) error
	// TerminateChild tears down exactly one CHILD_SA.
	TerminateChild(ctx context.Context, uniqueID uint64) error

	// ListSAs reports the SAs of connection ike, or of every connection
	// when ike is empty.
	ListSAs(ctx context.Context, ike string) ([]IKESA, error)

	// Subscribe delivers ike-updown and child-updown events until cancel
	// is called. Events can be lost (a slow reader, a daemon restart);
	// when that may have happened, an EventResync is delivered so the
	// reader re-queries with ListSAs instead of trusting stale state.
	Subscribe() (events <-chan Event, cancel func())
}

// SharedSecret is one IKE pre-shared key. Owners are the identities it
// applies to; AnyID among them matches any peer identity, but less
// specifically than a concrete identity does, so a key naming both peers
// always wins over one naming a single side and AnyID.
type SharedSecret struct {
	ID     string
	PSK    string
	Owners []string
}

// Validate checks s the same way Connection.Validate checks a PSK.
func (s SharedSecret) Validate() error {
	if !idRE.MatchString(s.ID) {
		return fmt.Errorf("ipsec: shared secret id %q must match %s", s.ID, idRE)
	}
	if err := validatePSK("shared secret "+s.ID, s.PSK); err != nil {
		return err
	}
	if len(s.Owners) == 0 {
		return fmt.Errorf("ipsec: shared secret %s: no owners", s.ID)
	}
	for _, o := range s.Owners {
		if o != AnyID && !idRE.MatchString(o) {
			return fmt.Errorf("ipsec: shared secret %s: owner %q must be %s or match %s", s.ID, o, AnyID, idRE)
		}
	}
	return nil
}

// EventKind says what an Event reports.
type EventKind int

const (
	// EventIKEUpDown reports an IKE_SA going up or down.
	EventIKEUpDown EventKind = iota + 1
	// EventChildUpDown reports a CHILD_SA going up or down.
	EventChildUpDown
	// EventResync means events may have been missed; re-query.
	EventResync
)

func (k EventKind) String() string {
	switch k {
	case EventIKEUpDown:
		return "ike-updown"
	case EventChildUpDown:
		return "child-updown"
	case EventResync:
		return "resync"
	default:
		return fmt.Sprintf("EventKind(%d)", int(k))
	}
}

// Event is one notification from the IKE daemon. IKE is the IKE_SA the
// event is about; for EventChildUpDown its Children hold the affected
// CHILD_SA. IKE is zero for EventResync.
type Event struct {
	Kind EventKind
	Up   bool
	IKE  IKESA
}

var (
	ErrAuthFailed = errors.New("ipsec: IKE authentication failed")
	ErrNotFound   = errors.New("ipsec: not found in the IKE daemon")
)
