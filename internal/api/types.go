package api

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/ngthdong/egressa/internal/control"
	"github.com/ngthdong/egressa/internal/measurement"
)

type Roles = control.GatewayRole

func ParseRoles(s string) (Roles, error) {
	var r Roles
	for _, part := range strings.Split(s, ",") {
		switch strings.TrimSpace(part) {
		case "access":
			r |= control.RoleAccess
		case "egress":
			r |= control.RoleEgress
		case "":
		default:
			return 0, fmt.Errorf("api: unknown gateway role %q (want access and/or egress)", part)
		}
	}
	if r == 0 {
		return 0, fmt.Errorf("api: no gateway role in %q", s)
	}
	return r, nil
}

const (
	BackendWireGuard = "wireguard"
	BackendIPsec     = "ipsec"
)

func ValidBackend(b string) bool {
	return b == "" || b == BackendWireGuard || b == BackendIPsec
}

func IPsecGatewayID(id string) string { return "gw-" + id }

func IPsecClientID(session string) string { return "s" + session }

type Gateway struct {
	ID            string            `json:"id"`
	Roles         Roles             `json:"roles"`
	Endpoint      string            `json:"endpoint"`
	PublicKey     string            `json:"public_key"`
	NodeIP        netip.Addr        `json:"node_ip"`
	BackbonePorts map[string]uint16 `json:"backbone_ports,omitempty"`
	IPsec         bool              `json:"ipsec,omitempty"`
	Alive         bool              `json:"alive"`
}

func (g Gateway) Host() (netip.Addr, error) {
	ap, err := netip.ParseAddrPort(g.Endpoint)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("api: gateway %s endpoint %q: %w", g.ID, g.Endpoint, err)
	}
	return ap.Addr(), nil
}

type RegisterGatewayRequest struct {
	Roles         Roles             `json:"roles"`
	Endpoint      string            `json:"endpoint"`
	PublicKey     string            `json:"public_key"`
	BackbonePorts map[string]uint16 `json:"backbone_ports,omitempty"`
	IPsec         bool              `json:"ipsec,omitempty"`
}

type Network struct {
	ClientSubnet netip.Prefix `json:"client_subnet"`
	NodeSubnet   netip.Prefix `json:"node_subnet"`
	ProbePort    uint16       `json:"probe_port"`
}

type RegisterGatewayResponse struct {
	NodeIP  netip.Addr `json:"node_ip"`
	Network Network    `json:"network"`
}

// Session records a client's identity, data plane, and current path.
// Access, Egress, and Epoch define the session's ownership and migration state.
type Session struct {
	ID        string     `json:"id"`
	PublicKey string     `json:"public_key"`
	VirtualIP netip.Addr `json:"virtual_ip"`
	Access    string     `json:"access"`
	Egress    string     `json:"egress"`
	Epoch     uint64     `json:"epoch"`
	Backend   string     `json:"backend,omitempty"`
	// IPsecPSK is a session-specific key shared with the client and gateways.
	IPsecPSK string `json:"ipsec_psk,omitempty"`
}

type GatewayState struct {
	Version  uint64    `json:"version"`
	Network  Network   `json:"network"`
	Gateways []Gateway `json:"gateways"`
	Sessions []Session `json:"sessions"`
}

type Link struct {
	From  string                   `json:"from"`
	To    string                   `json:"to"`
	Stats measurement.SegmentStats `json:"stats"`
	// Staleness measures time since the controller received the report.
	Staleness time.Duration `json:"staleness"`
}

// LinkReport also serves as a gateway heartbeat.
type LinkReport struct {
	Links []Link `json:"links"`
}

// CreateSessionRequest opens a session or reopens the one owned by PublicKey.
type CreateSessionRequest struct {
	PublicKey string `json:"public_key"`
	Egress    string `json:"egress,omitempty"`
	// Secret is required to reopen an existing session.
	Secret  string `json:"secret,omitempty"`
	Backend string `json:"backend,omitempty"`
}

type CreateSessionResponse struct {
	Session Session `json:"session"`
	Secret  string  `json:"secret"`
	Network Network `json:"network"`
}

type ClientState struct {
	Version  uint64                 `json:"version"`
	Network  Network                `json:"network"`
	Session  Session                `json:"session"`
	Gateways []Gateway              `json:"gateways"`
	Links    []Link                 `json:"links"`
	Policy   control.PolicyDocument `json:"policy"`
}

// MigrateRequest uses Epoch to prevent a stale migration from overwriting
// a newer path assignment.
type MigrateRequest struct {
	Epoch  uint64 `json:"epoch"`
	Access string `json:"access"`
	Egress string `json:"egress"`
}

type Error struct {
	Error string `json:"error"`
	// Session contains the current state when a migration conflicts.
	Session *Session `json:"session,omitempty"`
}

func FindGateway(gws []Gateway, id string) (Gateway, bool) {
	i := slices.IndexFunc(gws, func(g Gateway) bool { return g.ID == id })
	if i < 0 {
		return Gateway{}, false
	}
	return gws[i], true
}
