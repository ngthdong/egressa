package encryption

import (
	"fmt"
	"strings"
)

type Backend string

const (
	BackendWireGuard Backend = "wireguard"
	BackendIPsec     Backend = "ipsec"
)

const DefaultBackend = BackendWireGuard

func Backends() []Backend {
	return []Backend{BackendWireGuard, BackendIPsec}
}

func ParseBackend(s string) (Backend, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return DefaultBackend, nil
	case string(BackendWireGuard), "wg", "wireguard-go":
		return BackendWireGuard, nil
	case string(BackendIPsec), "strongswan":
		return BackendIPsec, nil
	default:
		return "", fmt.Errorf("encryption: unknown backend %q (want one of: wireguard, ipsec)", s)
	}
}

func (b Backend) String() string { return string(b) }

type Fencing string

const (
	FencingEpochHeader Fencing = "epoch-header"
	FencingSATeardown  Fencing = "sa-teardown"
)

type Capabilities struct {
	KernelDataPath               bool
	InBandSessionHeader          bool
	AuthenticatedSessionMetadata bool
	PassiveLoss                  bool
	PassiveJitter                bool
	CrossPathDedup               bool
	Fencing                      Fencing
}

func (b Backend) Capabilities() Capabilities {
	switch b {
	case BackendWireGuard:
		return Capabilities{
			KernelDataPath:      false,
			InBandSessionHeader: true,
			// The session header rides OUTSIDE WireGuard's encryption
			// (moved to the conn.Bind layer in Stage 3 because
			// wireguard-go drops decrypted non-IP payloads), so nothing
			// authenticates it today. Recorded here so the gap stays
			// visible instead of implied.
			AuthenticatedSessionMetadata: false,
			PassiveLoss:                  true,
			PassiveJitter:                true,
			CrossPathDedup:               true,
			Fencing:                      FencingEpochHeader,
		}
	case BackendIPsec:
		return Capabilities{
			KernelDataPath:               true,
			InBandSessionHeader:          false,
			AuthenticatedSessionMetadata: true, // ESP's ICV covers SPI and sequence number
			PassiveLoss:                  true,
			PassiveJitter:                false,
			CrossPathDedup:               false,
			Fencing:                      FencingSATeardown,
		}
	default:
		panic(fmt.Sprintf("encryption: Capabilities of unknown backend %q", string(b)))
	}
}
