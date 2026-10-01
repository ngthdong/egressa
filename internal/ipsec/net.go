package ipsec

import (
	"errors"
	"fmt"
	"net/netip"
)

// Net is the kernel networking surface the IPsec backend needs: XFRM
// interfaces, addresses, routes, policy rules, and a read of the kernel's
// XFRM states for passive loss. Client and Gateway depend only on this
// interface, so their logic is unit-tested with a fake; NetlinkNet is the
// real implementation.
type Net interface {
	// AddXfrmInterface creates an XFRM interface name bound to ifID. An
	// empty underlay creates it without a lower device, which is all a
	// route-based setup needs.
	AddXfrmInterface(name string, ifID uint32, underlay string) error
	DeleteLink(name string) error
	AddAddr(link string, addr netip.Prefix) error
	SetLinkUp(name string) error

	// RouteAdd creates r and fails with ErrExist if a route with the same
	// destination already exists in that table. It never overwrites, which
	// is what lets a caller tell a route it created apart from one that was
	// already there.
	RouteAdd(r Route) error
	RouteReplace(r Route) error
	RouteDel(r Route) error
	// RouteGet resolves the route the kernel would use for dst.
	RouteGet(dst netip.Addr) (Route, error)
	// DefaultRoute reads the main table's default route for family. It is
	// a read only: nothing here ever modifies the default route.
	DefaultRoute(family Family) (Route, error)

	RuleAdd(r Rule) error
	RuleDel(r Rule) error

	XfrmStates() ([]XfrmState, error)
}

// Family is an IP address family.
type Family int

const (
	FamilyV4 Family = 4
	FamilyV6 Family = 6
)

func familyOf(a netip.Addr) Family {
	if a.Is4() {
		return FamilyV4
	}
	return FamilyV6
}

// MainTable is the kernel's main routing table. A Route or Rule Table of 0
// also means the main table.
const MainTable = 254

// Route is one kernel route. Dev is an interface name rather than an
// index so callers and fakes never need to know about ifindexes.
type Route struct {
	Dst   netip.Prefix
	Gw    netip.Addr // optional next hop
	Dev   string
	Src   netip.Addr // optional preferred source
	Table int        // 0 means MainTable
}

func (r Route) table() int {
	if r.Table == 0 {
		return MainTable
	}
	return r.Table
}

func (r Route) String() string {
	s := r.Dst.String()
	if r.Gw.IsValid() {
		s += " via " + r.Gw.String()
	}
	if r.Dev != "" {
		s += " dev " + r.Dev
	}
	if r.Src.IsValid() {
		s += " src " + r.Src.String()
	}
	return fmt.Sprintf("%s table %d", s, r.table())
}

// Rule is one policy routing rule: traffic matching Src (if valid) and
// arriving on Iif (if set) looks up Table at Priority. Family is used only
// when Src is not set.
type Rule struct {
	Src      netip.Prefix
	Iif      string
	Table    int
	Priority int
	Family   Family
}

func (r Rule) family() Family {
	if r.Src.IsValid() {
		return familyOf(r.Src.Addr())
	}
	if r.Family == 0 {
		return FamilyV4
	}
	return r.Family
}

// XfrmState is the part of a kernel XFRM state passive loss needs.
type XfrmState struct {
	Src, Dst netip.Addr
	SPI      uint32
	IfID     uint32
	Packets  uint64
	Bytes    uint64
	// ReplaySeq is the highest sequence number accepted on this inbound
	// state. HasReplay is false when the kernel reported the state's
	// anti-replay data in a form the netlink library does not decode (the
	// ESN replay attribute); see Loss.
	ReplaySeq uint32
	HasReplay bool
}

var (
	// ErrExist reports that the object being created already exists.
	ErrExist = errors.New("ipsec: already exists")
	// ErrNotExist reports that the object being read or removed does not
	// exist.
	ErrNotExist = errors.New("ipsec: does not exist")
)
