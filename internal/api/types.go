// Package api is the HTTP contract between the controller and the two
// kinds of agents that talk to it: gateways and clients. Every request
// and response body is one of the JSON types below.
//
// Gateways and clients never talk to the store (etcd) directly: the
// controller is the only writer, so it alone enforces who may change
// what. A client can only read and migrate its own session.
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

// Roles is a gateway's set of roles, written as "access", "egress" or
// "access,egress".
type Roles = control.GatewayRole

// ParseRoles parses a comma-separated role list.
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

// Gateway is one gateway as the controller knows it.
type Gateway struct {
	ID    string `json:"id"`
	Roles Roles  `json:"roles"`
	// Endpoint is the public host:port clients reach its WireGuard on.
	Endpoint string `json:"endpoint"`
	// PublicKey is its WireGuard public key, base64.
	PublicKey string `json:"public_key"`
	// NodeIP is its address inside the overlay: probes are sent to it,
	// and backbone tunnels use it as their local address.
	NodeIP netip.Addr `json:"node_ip"`
	// BackbonePorts maps a peer gateway's ID to the UDP port this
	// gateway's backbone tunnel to that peer listens on.
	BackbonePorts map[string]uint16 `json:"backbone_ports,omitempty"`
	// Alive is false once the gateway has not reported in for a while.
	Alive bool `json:"alive"`
}

// Host returns the host part of Endpoint.
func (g Gateway) Host() (netip.Addr, error) {
	ap, err := netip.ParseAddrPort(g.Endpoint)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("api: gateway %s endpoint %q: %w", g.ID, g.Endpoint, err)
	}
	return ap.Addr(), nil
}

// RegisterGatewayRequest is sent by a gateway on start and whenever its
// backbone ports change.
type RegisterGatewayRequest struct {
	Roles         Roles             `json:"roles"`
	Endpoint      string            `json:"endpoint"`
	PublicKey     string            `json:"public_key"`
	BackbonePorts map[string]uint16 `json:"backbone_ports,omitempty"`
}

// Network is the overlay addressing the controller hands out.
type Network struct {
	// ClientSubnet holds every client's virtual IP.
	ClientSubnet netip.Prefix `json:"client_subnet"`
	// NodeSubnet holds every gateway's NodeIP.
	NodeSubnet netip.Prefix `json:"node_subnet"`
	// ProbePort is the UDP port every gateway answers probes on.
	ProbePort uint16 `json:"probe_port"`
}

// RegisterGatewayResponse tells a gateway its overlay address.
type RegisterGatewayResponse struct {
	NodeIP  netip.Addr `json:"node_ip"`
	Network Network    `json:"network"`
}

// Session is one client's session: who it is, and which path carries it.
// Access, Egress and Epoch are the session's ownership record.
type Session struct {
	ID        string     `json:"id"`
	PublicKey string     `json:"public_key"`
	VirtualIP netip.Addr `json:"virtual_ip"`
	Access    string     `json:"access"`
	Egress    string     `json:"egress"`
	Epoch     uint64     `json:"epoch"`
}

// GatewayState is everything a gateway needs to configure itself.
type GatewayState struct {
	Version  uint64    `json:"version"`
	Network  Network   `json:"network"`
	Gateways []Gateway `json:"gateways"`
	Sessions []Session `json:"sessions"`
}

// Link is one gateway's measurement of its backbone tunnel to another.
type Link struct {
	From  string                   `json:"from"`
	To    string                   `json:"to"`
	Stats measurement.SegmentStats `json:"stats"`
	// Staleness is how long ago, by the controller's clock, the report
	// was received. Stats.Age does not include it.
	Staleness time.Duration `json:"staleness"`
}

// LinkReport is a gateway's periodic report; it doubles as a heartbeat.
type LinkReport struct {
	Links []Link `json:"links"`
}

// CreateSessionRequest opens a session, or reopens the one already held
// by PublicKey.
type CreateSessionRequest struct {
	PublicKey string `json:"public_key"`
	// Egress, if set, is the gateway the client wants its traffic to
	// leave from. Empty lets the controller choose.
	Egress string `json:"egress,omitempty"`
	// Secret reopens the session PublicKey already holds; a key that
	// holds one cannot get it back without it.
	Secret string `json:"secret,omitempty"`
}

// CreateSessionResponse carries the secret that authorizes every later
// request about this session.
type CreateSessionResponse struct {
	Session Session `json:"session"`
	Secret  string  `json:"secret"`
	Network Network `json:"network"`
}

// ClientState is everything a client needs to choose its path.
type ClientState struct {
	Version  uint64                 `json:"version"`
	Network  Network                `json:"network"`
	Session  Session                `json:"session"`
	Gateways []Gateway              `json:"gateways"`
	Links    []Link                 `json:"links"`
	Policy   control.PolicyDocument `json:"policy"`
}

// MigrateRequest asks to move a session from the path it has at Epoch to
// Access and Egress. It fails with a conflict if the session has already
// moved past Epoch.
type MigrateRequest struct {
	Epoch  uint64 `json:"epoch"`
	Access string `json:"access"`
	Egress string `json:"egress"`
}

// Error is the body of every non-2xx response.
type Error struct {
	Error string `json:"error"`
	// Session is set on a migration conflict: the session as it is now.
	Session *Session `json:"session,omitempty"`
}

// FindGateway returns the gateway with id.
func FindGateway(gws []Gateway, id string) (Gateway, bool) {
	i := slices.IndexFunc(gws, func(g Gateway) bool { return g.ID == id })
	if i < 0 {
		return Gateway{}, false
	}
	return gws[i], true
}
