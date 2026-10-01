//go:build linux

package ipsec

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// nlHandle is the subset of *netlink.Handle that NetlinkNet calls. It is
// the seam that lets the conversion logic below be tested without root.
type nlHandle interface {
	LinkAdd(link netlink.Link) error
	LinkDel(link netlink.Link) error
	LinkByName(name string) (netlink.Link, error)
	LinkByIndex(index int) (netlink.Link, error)
	LinkSetUp(link netlink.Link) error
	AddrAdd(link netlink.Link, addr *netlink.Addr) error
	RouteAdd(route *netlink.Route) error
	RouteReplace(route *netlink.Route) error
	RouteDel(route *netlink.Route) error
	RouteGet(destination net.IP) ([]netlink.Route, error)
	RouteListFiltered(family int, filter *netlink.Route, filterMask uint64) ([]netlink.Route, error)
	RuleAdd(rule *netlink.Rule) error
	RuleDel(rule *netlink.Rule) error
	XfrmStateList(family int) ([]netlink.XfrmState, error)
	Close()
}

var _ nlHandle = (*netlink.Handle)(nil)

// NetlinkNet implements Net with netlink sockets bound to one network
// namespace.
type NetlinkNet struct {
	h nlHandle
}

var _ Net = (*NetlinkNet)(nil)

// NewNetlinkNet returns a NetlinkNet for the calling process's network
// namespace.
func NewNetlinkNet() (*NetlinkNet, error) {
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE, unix.NETLINK_XFRM)
	if err != nil {
		return nil, fmt.Errorf("ipsec: netlink handle: %w", err)
	}
	return &NetlinkNet{h: h}, nil
}

// NewNetlinkNetAt returns a NetlinkNet for network namespace ns, without
// switching the calling thread into it.
func NewNetlinkNetAt(ns netns.NsHandle) (*NetlinkNet, error) {
	h, err := netlink.NewHandleAt(ns, unix.NETLINK_ROUTE, unix.NETLINK_XFRM)
	if err != nil {
		return nil, fmt.Errorf("ipsec: netlink handle in namespace: %w", err)
	}
	return &NetlinkNet{h: h}, nil
}

// Close releases the netlink sockets.
func (n *NetlinkNet) Close() { n.h.Close() }

func (n *NetlinkNet) AddXfrmInterface(name string, ifID uint32, underlay string) error {
	if ifID == 0 {
		return fmt.Errorf("ipsec: xfrm interface %s: if_id must be non-zero", name)
	}
	link := &netlink.Xfrmi{LinkAttrs: netlink.LinkAttrs{Name: name}, Ifid: ifID}
	if underlay != "" {
		lower, err := n.linkByName(underlay)
		if err != nil {
			return err
		}
		link.ParentIndex = lower.Attrs().Index
	}
	if err := n.h.LinkAdd(link); err != nil {
		return fmt.Errorf("ipsec: add xfrm interface %s (if_id %d): %w", name, ifID, mapErr(err))
	}
	return nil
}

func (n *NetlinkNet) DeleteLink(name string) error {
	link, err := n.linkByName(name)
	if err != nil {
		return err
	}
	if err := n.h.LinkDel(link); err != nil {
		return fmt.Errorf("ipsec: delete link %s: %w", name, mapErr(err))
	}
	return nil
}

func (n *NetlinkNet) AddAddr(name string, addr netip.Prefix) error {
	link, err := n.linkByName(name)
	if err != nil {
		return err
	}
	if err := n.h.AddrAdd(link, &netlink.Addr{IPNet: prefixToIPNet(addr)}); err != nil {
		return fmt.Errorf("ipsec: add address %s to %s: %w", addr, name, mapErr(err))
	}
	return nil
}

func (n *NetlinkNet) SetLinkUp(name string) error {
	link, err := n.linkByName(name)
	if err != nil {
		return err
	}
	if err := n.h.LinkSetUp(link); err != nil {
		return fmt.Errorf("ipsec: set %s up: %w", name, mapErr(err))
	}
	return nil
}

func (n *NetlinkNet) RouteAdd(r Route) error {
	nr, err := n.toNetlinkRoute(r)
	if err != nil {
		return err
	}
	if err := n.h.RouteAdd(nr); err != nil {
		return fmt.Errorf("ipsec: add route %s: %w", r, mapErr(err))
	}
	return nil
}

func (n *NetlinkNet) RouteReplace(r Route) error {
	nr, err := n.toNetlinkRoute(r)
	if err != nil {
		return err
	}
	if err := n.h.RouteReplace(nr); err != nil {
		return fmt.Errorf("ipsec: replace route %s: %w", r, mapErr(err))
	}
	return nil
}

func (n *NetlinkNet) RouteDel(r Route) error {
	nr, err := n.toNetlinkRoute(r)
	if err != nil {
		return err
	}
	if err := n.h.RouteDel(nr); err != nil {
		return fmt.Errorf("ipsec: delete route %s: %w", r, mapErr(err))
	}
	return nil
}

func (n *NetlinkNet) RouteGet(dst netip.Addr) (Route, error) {
	if !dst.IsValid() || dst.Zone() != "" {
		return Route{}, fmt.Errorf("ipsec: route get: invalid destination %v", dst)
	}
	routes, err := n.h.RouteGet(dst.AsSlice())
	if err != nil {
		return Route{}, fmt.Errorf("ipsec: route get %s: %w", dst, mapErr(err))
	}
	if len(routes) == 0 {
		return Route{}, fmt.Errorf("ipsec: route get %s: %w", dst, ErrNotExist)
	}
	r, err := n.fromNetlinkRoute(routes[0])
	if err != nil {
		return Route{}, err
	}
	// RouteGet answers for one address, so the result's destination is
	// that address as a host route, whatever prefix matched.
	r.Dst = netip.PrefixFrom(dst, dst.BitLen())
	return r, nil
}

func (n *NetlinkNet) DefaultRoute(family Family) (Route, error) {
	routes, err := n.h.RouteListFiltered(
		nlFamily(family), &netlink.Route{Table: MainTable}, netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return Route{}, fmt.Errorf("ipsec: list main table: %w", mapErr(err))
	}
	var best *netlink.Route
	for i := range routes {
		rt := &routes[i]
		if rt.Dst != nil {
			if ones, _ := rt.Dst.Mask.Size(); ones != 0 {
				continue
			}
		}
		if best == nil || rt.Priority < best.Priority {
			best = rt
		}
	}
	if best == nil {
		return Route{}, fmt.Errorf("ipsec: no IPv%d default route in the main table: %w", family, ErrNotExist)
	}
	r, err := n.fromNetlinkRoute(*best)
	if err != nil {
		return Route{}, err
	}
	if family == FamilyV4 {
		r.Dst = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	} else {
		r.Dst = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	return r, nil
}

func (n *NetlinkNet) RuleAdd(r Rule) error {
	if err := n.h.RuleAdd(toNetlinkRule(r)); err != nil {
		return fmt.Errorf("ipsec: add rule %+v: %w", r, mapErr(err))
	}
	return nil
}

func (n *NetlinkNet) RuleDel(r Rule) error {
	if err := n.h.RuleDel(toNetlinkRule(r)); err != nil {
		return fmt.Errorf("ipsec: delete rule %+v: %w", r, mapErr(err))
	}
	return nil
}

func (n *NetlinkNet) XfrmStates() ([]XfrmState, error) {
	states, err := n.h.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("ipsec: list xfrm states: %w", mapErr(err))
	}
	out := make([]XfrmState, 0, len(states))
	for _, s := range states {
		out = append(out, fromNetlinkState(s))
	}
	return out, nil
}

func fromNetlinkState(s netlink.XfrmState) XfrmState {
	st := XfrmState{
		Src:     ipToAddr(s.Src),
		Dst:     ipToAddr(s.Dst),
		SPI:     uint32(s.Spi),
		IfID:    uint32(s.Ifid),
		Packets: s.Statistics.Packets,
		Bytes:   s.Statistics.Bytes,
	}
	// netlink decodes only the legacy XFRMA_REPLAY_VAL attribute. A state
	// using the ESN replay attribute (ESN enabled, or a replay window above
	// 32) comes back with Replay == nil, and passive loss is then unknown
	// rather than silently zero.
	if s.Replay != nil {
		st.ReplaySeq = s.Replay.Seq
		st.HasReplay = true
	}
	return st
}

func (n *NetlinkNet) linkByName(name string) (netlink.Link, error) {
	link, err := n.h.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("ipsec: link %s: %w", name, mapErr(err))
	}
	return link, nil
}

func (n *NetlinkNet) toNetlinkRoute(r Route) (*netlink.Route, error) {
	if !r.Dst.IsValid() {
		return nil, fmt.Errorf("ipsec: route without a destination")
	}
	nr := &netlink.Route{
		Dst:   prefixToIPNet(r.Dst),
		Table: r.table(),
	}
	if r.Gw.IsValid() {
		nr.Gw = r.Gw.AsSlice()
	}
	if r.Src.IsValid() {
		nr.Src = r.Src.AsSlice()
	}
	if r.Dev != "" {
		link, err := n.linkByName(r.Dev)
		if err != nil {
			return nil, err
		}
		nr.LinkIndex = link.Attrs().Index
	}
	return nr, nil
}

func (n *NetlinkNet) fromNetlinkRoute(nr netlink.Route) (Route, error) {
	r := Route{
		Gw:    ipToAddr(nr.Gw),
		Src:   ipToAddr(nr.Src),
		Table: nr.Table,
	}
	if nr.Dst != nil {
		if p, ok := ipNetToPrefix(nr.Dst); ok {
			r.Dst = p
		}
	}
	if nr.LinkIndex != 0 {
		link, err := n.h.LinkByIndex(nr.LinkIndex)
		if err != nil {
			return Route{}, fmt.Errorf("ipsec: link index %d: %w", nr.LinkIndex, mapErr(err))
		}
		r.Dev = link.Attrs().Name
	}
	return r, nil
}

func toNetlinkRule(r Rule) *netlink.Rule {
	nr := netlink.NewRule()
	nr.Family = nlFamily(r.family())
	nr.Table = r.Table
	if nr.Table == 0 {
		nr.Table = MainTable
	}
	nr.Priority = r.Priority
	if r.Src.IsValid() {
		nr.Src = prefixToIPNet(r.Src)
	}
	nr.IifName = r.Iif
	return nr
}

func nlFamily(f Family) int {
	if f == FamilyV6 {
		return netlink.FAMILY_V6
	}
	return netlink.FAMILY_V4
}

func prefixToIPNet(p netip.Prefix) *net.IPNet {
	p = p.Masked()
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func ipNetToPrefix(n *net.IPNet) (netip.Prefix, bool) {
	a := ipToAddr(n.IP)
	if !a.IsValid() {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	if bits != a.BitLen() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, ones), true
}

// ipToAddr converts a net.IP, unmapping 4-in-6 forms so an IPv4 address
// always comes back as a 4-byte netip.Addr.
func ipToAddr(ip net.IP) netip.Addr {
	if len(ip) == 0 {
		return netip.Addr{}
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return a.Unmap()
}

// mapErr translates the errno values netlink returns into ErrExist and
// ErrNotExist, keeping the original error in the chain.
func mapErr(err error) error {
	var lnf netlink.LinkNotFoundError
	switch {
	case errors.As(err, &lnf):
		return fmt.Errorf("%w: %v", ErrNotExist, err)
	case errors.Is(err, syscall.EEXIST):
		return fmt.Errorf("%w: %w", ErrExist, err)
	case errors.Is(err, syscall.ESRCH), errors.Is(err, syscall.ENOENT):
		return fmt.Errorf("%w: %w", ErrNotExist, err)
	default:
		return err
	}
}
