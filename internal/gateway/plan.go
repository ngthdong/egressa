// Package gateway is the gateway agent: it registers with the controller,
// then keeps this host's tunnels, routes and NAT matching the sessions the
// controller reports.
//
// One gateway can be an access gateway (clients connect to it), an egress
// gateway (traffic leaves to the Internet from it), or both. A session
// whose access and egress differ crosses the backbone:
//
//	client --egc0--> access --egb<n>--> egress --uplink (NAT)--> Internet
//
// Data plane, per gateway:
//
//   - egc0, the client-facing WireGuard device. Every client is a peer
//     with its virtual IP as allowed IP. Addressed with the gateway's
//     NodeIP/32, with a route for the whole client subnet.
//   - egb<n>, one WireGuard device per other gateway (wireguard-go routes
//     by destination, so per-egress choice needs a device per egress).
//     Its one peer allows 0.0.0.0/0; the kernel decides what goes in.
//   - on an access gateway, for each session leaving elsewhere:
//     ip rule from <virtual IP> lookup <table of its egress>, whose
//     default route is that egress's egb<n> (and a blackhole behind it,
//     so traffic never leaks out of the access gateway's own uplink).
//     These rules exist for every session, not only those whose access
//     this gateway is, so a client switching access is forwarded right
//     away, before anything else changes.
//   - on an egress gateway, for each session whose access is elsewhere:
//     a /32 route for its virtual IP via that access's egb<n>. This is
//     the one thing a migration changes.
//   - MASQUERADE for the client subnet, only out of the uplink, only on
//     an egress gateway.
//   - probe replies (from the NodeIP) always go straight back on egc0,
//     so a client measures this gateway directly even when its traffic
//     currently comes in through another.
package gateway

import (
	"net/netip"
	"slices"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/control"
)

// Backbone is the desired tunnel to one other gateway.
type Backbone struct {
	PublicKey string
	// Endpoint is where the peer's tunnel to this gateway listens;
	// empty until the peer has reported its port.
	Endpoint string
	NodeIP   netip.Addr
}

// Plan is the configuration a gateway should have for one state.
type Plan struct {
	// Peers maps a client's public key to its virtual IP.
	Peers map[string]netip.Addr
	// Backbones maps another gateway's ID to the tunnel to it.
	Backbones map[string]Backbone
	// Forward maps a virtual IP to the egress gateway its traffic must
	// be forwarded to over the backbone.
	Forward map[netip.Addr]string
	// Return maps a virtual IP to the access gateway its return traffic
	// must be sent back through.
	Return map[netip.Addr]string
	// Epochs maps a session ID to its current epoch.
	Epochs map[string]uint64
}

// MakePlan computes gateway me's configuration for st.
func MakePlan(me string, roles api.Roles, st api.GatewayState) Plan {
	p := Plan{
		Peers:     make(map[string]netip.Addr),
		Backbones: make(map[string]Backbone),
		Forward:   make(map[netip.Addr]string),
		Return:    make(map[netip.Addr]string),
		Epochs:    make(map[string]uint64),
	}
	known := make(map[string]bool, len(st.Gateways))
	for _, g := range st.Gateways {
		known[g.ID] = true
		if g.ID == me {
			continue
		}
		b := Backbone{PublicKey: g.PublicKey, NodeIP: g.NodeIP}
		if port, ok := g.BackbonePorts[me]; ok {
			if host, err := g.Host(); err == nil {
				b.Endpoint = netip.AddrPortFrom(host, port).String()
			}
		}
		p.Backbones[g.ID] = b
	}
	isAccess := roles.Has(control.RoleAccess)
	isEgress := roles.Has(control.RoleEgress)
	for _, s := range st.Sessions {
		p.Epochs[s.ID] = s.Epoch
		if isAccess {
			p.Peers[s.PublicKey] = s.VirtualIP
			if s.Egress != me && known[s.Egress] {
				p.Forward[s.VirtualIP] = s.Egress
			}
		}
		if isEgress && s.Egress == me && s.Access != me && known[s.Access] {
			p.Return[s.VirtualIP] = s.Access
		}
	}
	return p
}

// BackboneIDs returns the plan's backbone peers, sorted.
func (p Plan) BackboneIDs() []string {
	ids := make([]string, 0, len(p.Backbones))
	for id := range p.Backbones {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}
