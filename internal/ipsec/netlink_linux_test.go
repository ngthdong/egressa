//go:build linux

package ipsec

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
)

// fakeHandle is an in-memory nlHandle. It records what NetlinkNet asked
// for, so the conversion logic is tested without touching the kernel.
type fakeHandle struct {
	links  map[string]netlink.Link
	nextIx int

	added, replaced, deleted []*netlink.Route
	rulesAdded, rulesDeleted []*netlink.Rule
	addrs                    []*netlink.Addr
	up                       []string

	getRoutes  []netlink.Route
	listRoutes []netlink.Route
	states     []netlink.XfrmState

	err    error // returned by every mutating/reading call when set
	closed bool
}

func newFakeHandle() *fakeHandle {
	return &fakeHandle{links: map[string]netlink.Link{}, nextIx: 10}
}

func (f *fakeHandle) addLink(name string) netlink.Link {
	f.nextIx++
	l := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, Index: f.nextIx}}
	f.links[name] = l
	return l
}

func (f *fakeHandle) LinkAdd(l netlink.Link) error {
	if f.err != nil {
		return f.err
	}
	if _, ok := f.links[l.Attrs().Name]; ok {
		return syscall.EEXIST
	}
	f.nextIx++
	l.Attrs().Index = f.nextIx
	f.links[l.Attrs().Name] = l
	return nil
}

func (f *fakeHandle) LinkDel(l netlink.Link) error {
	if f.err != nil {
		return f.err
	}
	delete(f.links, l.Attrs().Name)
	return nil
}

func (f *fakeHandle) LinkByName(name string) (netlink.Link, error) {
	l, ok := f.links[name]
	if !ok {
		return nil, netlink.LinkNotFoundError{}
	}
	return l, nil
}

func (f *fakeHandle) LinkByIndex(ix int) (netlink.Link, error) {
	for _, l := range f.links {
		if l.Attrs().Index == ix {
			return l, nil
		}
	}
	return nil, netlink.LinkNotFoundError{}
}

func (f *fakeHandle) LinkSetUp(l netlink.Link) error {
	if f.err != nil {
		return f.err
	}
	f.up = append(f.up, l.Attrs().Name)
	return nil
}

func (f *fakeHandle) AddrAdd(_ netlink.Link, a *netlink.Addr) error {
	if f.err != nil {
		return f.err
	}
	f.addrs = append(f.addrs, a)
	return nil
}

func (f *fakeHandle) RouteAdd(r *netlink.Route) error {
	if f.err != nil {
		return f.err
	}
	f.added = append(f.added, r)
	return nil
}

func (f *fakeHandle) RouteReplace(r *netlink.Route) error {
	if f.err != nil {
		return f.err
	}
	f.replaced = append(f.replaced, r)
	return nil
}

func (f *fakeHandle) RouteDel(r *netlink.Route) error {
	if f.err != nil {
		return f.err
	}
	f.deleted = append(f.deleted, r)
	return nil
}

func (f *fakeHandle) RouteGet(net.IP) ([]netlink.Route, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.getRoutes, nil
}

func (f *fakeHandle) RouteListFiltered(int, *netlink.Route, uint64) ([]netlink.Route, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.listRoutes, nil
}

func (f *fakeHandle) RuleAdd(r *netlink.Rule) error {
	if f.err != nil {
		return f.err
	}
	f.rulesAdded = append(f.rulesAdded, r)
	return nil
}

func (f *fakeHandle) RuleDel(r *netlink.Rule) error {
	if f.err != nil {
		return f.err
	}
	f.rulesDeleted = append(f.rulesDeleted, r)
	return nil
}

func (f *fakeHandle) XfrmStateList(int) ([]netlink.XfrmState, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.states, nil
}

func (f *fakeHandle) Close() { f.closed = true }

func TestNetlinkNet_XfrmInterfaceLifecycle(t *testing.T) {
	h := newFakeHandle()
	h.addLink("eth0")
	n := &NetlinkNet{h: h}

	if err := n.AddXfrmInterface("egx7", 7, "eth0"); err != nil {
		t.Fatalf("AddXfrmInterface: %v", err)
	}
	x, ok := h.links["egx7"].(*netlink.Xfrmi)
	if !ok {
		t.Fatalf("created link is %T, want *netlink.Xfrmi", h.links["egx7"])
	}
	if x.Ifid != 7 || x.ParentIndex != h.links["eth0"].Attrs().Index {
		t.Fatalf("xfrm interface = if_id %d parent %d, want 7 and eth0's index", x.Ifid, x.ParentIndex)
	}
	if err := n.AddXfrmInterface("egx8", 8, ""); err != nil {
		t.Fatalf("AddXfrmInterface without underlay: %v", err)
	}
	if h.links["egx8"].(*netlink.Xfrmi).ParentIndex != 0 {
		t.Fatal("xfrm interface without underlay got a parent")
	}
	if err := n.AddXfrmInterface("egx7", 9, ""); !errors.Is(err, ErrExist) {
		t.Fatalf("duplicate AddXfrmInterface error = %v, want ErrExist", err)
	}
	if err := n.AddXfrmInterface("egx9", 0, ""); err == nil {
		t.Fatal("AddXfrmInterface accepted if_id 0")
	}
	if err := n.AddXfrmInterface("egx9", 9, "nope"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("AddXfrmInterface with missing underlay error = %v, want ErrNotExist", err)
	}

	if err := n.AddAddr("egx7", netip.MustParsePrefix("10.0.0.2/32")); err != nil {
		t.Fatalf("AddAddr: %v", err)
	}
	if got := h.addrs[0].IPNet.String(); got != "10.0.0.2/32" {
		t.Fatalf("address = %s, want 10.0.0.2/32", got)
	}
	if err := n.SetLinkUp("egx7"); err != nil || h.up[0] != "egx7" {
		t.Fatalf("SetLinkUp: err=%v up=%v", err, h.up)
	}
	if err := n.DeleteLink("egx7"); err != nil {
		t.Fatalf("DeleteLink: %v", err)
	}
	if _, ok := h.links["egx7"]; ok {
		t.Fatal("link still present after DeleteLink")
	}
	for name, err := range map[string]error{
		"DeleteLink": n.DeleteLink("egx7"),
		"AddAddr":    n.AddAddr("egx7", netip.MustParsePrefix("10.0.0.2/32")),
		"SetLinkUp":  n.SetLinkUp("egx7"),
	} {
		if !errors.Is(err, ErrNotExist) {
			t.Errorf("%s on a missing link = %v, want ErrNotExist", name, err)
		}
	}
}

func TestNetlinkNet_HandleErrorsAreWrapped(t *testing.T) {
	h := newFakeHandle()
	h.addLink("egx1")
	n := &NetlinkNet{h: h}
	h.err = syscall.EPERM

	r := Route{Dst: netip.MustParsePrefix("10.0.0.0/8"), Dev: "egx1"}
	calls := map[string]error{
		"AddXfrmInterface": n.AddXfrmInterface("egx2", 2, ""),
		"DeleteLink":       n.DeleteLink("egx1"),
		"AddAddr":          n.AddAddr("egx1", netip.MustParsePrefix("10.0.0.1/32")),
		"SetLinkUp":        n.SetLinkUp("egx1"),
		"RouteAdd":         n.RouteAdd(r),
		"RouteReplace":     n.RouteReplace(r),
		"RouteDel":         n.RouteDel(r),
		"RuleAdd":          n.RuleAdd(Rule{Table: 100, Priority: 10}),
		"RuleDel":          n.RuleDel(Rule{Table: 100, Priority: 10}),
	}
	_, calls["RouteGet"] = n.RouteGet(netip.MustParseAddr("10.0.0.1"))
	_, calls["DefaultRoute"] = n.DefaultRoute(FamilyV4)
	_, calls["XfrmStates"] = n.XfrmStates()
	for name, err := range calls {
		if !errors.Is(err, syscall.EPERM) {
			t.Errorf("%s error = %v, want it to wrap EPERM", name, err)
		}
	}
}

func TestNetlinkNet_Routes(t *testing.T) {
	h := newFakeHandle()
	h.addLink("egx1")
	n := &NetlinkNet{h: h}

	r := Route{
		Dst:   netip.MustParsePrefix("10.1.2.3/8"), // unmasked on purpose
		Gw:    netip.MustParseAddr("192.0.2.1"),
		Dev:   "egx1",
		Src:   netip.MustParseAddr("10.0.0.2"),
		Table: 100,
	}
	if err := n.RouteAdd(r); err != nil {
		t.Fatalf("RouteAdd: %v", err)
	}
	got := h.added[0]
	if got.Dst.String() != "10.0.0.0/8" || got.Gw.String() != "192.0.2.1" ||
		got.Src.String() != "10.0.0.2" || got.Table != 100 ||
		got.LinkIndex != h.links["egx1"].Attrs().Index {
		t.Fatalf("netlink route = %+v", got)
	}
	if err := n.RouteReplace(Route{Dst: netip.MustParsePrefix("0.0.0.0/1"), Dev: "egx1"}); err != nil {
		t.Fatalf("RouteReplace: %v", err)
	}
	if h.replaced[0].Table != MainTable || h.replaced[0].Gw != nil || h.replaced[0].Src != nil {
		t.Fatalf("replace route = %+v, want main table and no gw/src", h.replaced[0])
	}
	if err := n.RouteDel(Route{Dst: netip.MustParsePrefix("2001:db8::/32")}); err != nil {
		t.Fatalf("RouteDel: %v", err)
	}
	if h.deleted[0].Dst.String() != "2001:db8::/32" || h.deleted[0].LinkIndex != 0 {
		t.Fatalf("delete route = %+v", h.deleted[0])
	}

	for name, err := range map[string]error{
		"RouteAdd no dst":      n.RouteAdd(Route{Dev: "egx1"}),
		"RouteReplace no dst":  n.RouteReplace(Route{}),
		"RouteDel no dst":      n.RouteDel(Route{}),
		"RouteAdd missing dev": n.RouteAdd(Route{Dst: netip.MustParsePrefix("10.0.0.0/8"), Dev: "nope"}),
	} {
		if err == nil {
			t.Errorf("%s: no error", name)
		}
	}

	h.err = syscall.EEXIST
	if err := n.RouteAdd(r); !errors.Is(err, ErrExist) {
		t.Fatalf("RouteAdd over an existing route = %v, want ErrExist", err)
	}
	h.err = syscall.ESRCH
	if err := n.RouteDel(r); !errors.Is(err, ErrNotExist) {
		t.Fatalf("RouteDel of a missing route = %v, want ErrNotExist", err)
	}
	h.err = syscall.ENOENT
	if err := n.RuleDel(Rule{Table: 1}); !errors.Is(err, ErrNotExist) {
		t.Fatalf("RuleDel of a missing rule = %v, want ErrNotExist", err)
	}
}

func TestNetlinkNet_RouteGet(t *testing.T) {
	h := newFakeHandle()
	eth := h.addLink("eth0")
	n := &NetlinkNet{h: h}

	h.getRoutes = []netlink.Route{{
		Dst:       &net.IPNet{IP: net.ParseIP("203.0.113.0").To4(), Mask: net.CIDRMask(24, 32)},
		Gw:        net.ParseIP("192.0.2.1"), // 16-byte form must be unmapped
		Src:       net.ParseIP("192.0.2.10").To4(),
		LinkIndex: eth.Attrs().Index,
		Table:     MainTable,
	}}
	got, err := n.RouteGet(netip.MustParseAddr("203.0.113.9"))
	if err != nil {
		t.Fatalf("RouteGet: %v", err)
	}
	want := Route{
		Dst:   netip.MustParsePrefix("203.0.113.9/32"),
		Gw:    netip.MustParseAddr("192.0.2.1"),
		Dev:   "eth0",
		Src:   netip.MustParseAddr("192.0.2.10"),
		Table: MainTable,
	}
	if got != want {
		t.Fatalf("RouteGet = %+v, want %+v", got, want)
	}

	h.getRoutes = []netlink.Route{{LinkIndex: 999}}
	if _, err := n.RouteGet(netip.MustParseAddr("203.0.113.9")); !errors.Is(err, ErrNotExist) {
		t.Fatalf("RouteGet with an unknown link index = %v, want ErrNotExist", err)
	}
	h.getRoutes = nil
	if _, err := n.RouteGet(netip.MustParseAddr("203.0.113.9")); !errors.Is(err, ErrNotExist) {
		t.Fatalf("RouteGet with no answer = %v, want ErrNotExist", err)
	}
	for _, bad := range []netip.Addr{{}, netip.MustParseAddr("fe80::1%eth0")} {
		if _, err := n.RouteGet(bad); err == nil {
			t.Errorf("RouteGet(%v) accepted an invalid destination", bad)
		}
	}
}

func TestNetlinkNet_DefaultRoute(t *testing.T) {
	h := newFakeHandle()
	eth := h.addLink("eth0")
	wlan := h.addLink("wlan0")
	n := &NetlinkNet{h: h}

	h.listRoutes = []netlink.Route{
		{Dst: &net.IPNet{IP: net.IPv4(10, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 32)}, LinkIndex: eth.Attrs().Index},
		{Gw: net.IPv4(192, 0, 2, 1), LinkIndex: wlan.Attrs().Index, Priority: 600},
		{Dst: &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}, Gw: net.IPv4(192, 0, 2, 254), LinkIndex: eth.Attrs().Index, Priority: 100},
	}
	got, err := n.DefaultRoute(FamilyV4)
	if err != nil {
		t.Fatalf("DefaultRoute: %v", err)
	}
	if got.Dev != "eth0" || got.Gw != netip.MustParseAddr("192.0.2.254") || got.Dst != netip.MustParsePrefix("0.0.0.0/0") {
		t.Fatalf("DefaultRoute = %+v, want the lowest-metric default via eth0", got)
	}

	h.listRoutes = []netlink.Route{{Gw: net.ParseIP("fe80::1"), LinkIndex: eth.Attrs().Index}}
	got, err = n.DefaultRoute(FamilyV6)
	if err != nil || got.Dst != netip.MustParsePrefix("::/0") {
		t.Fatalf("DefaultRoute(v6) = %+v, %v", got, err)
	}

	h.listRoutes = h.listRoutes[:0]
	if _, err := n.DefaultRoute(FamilyV4); !errors.Is(err, ErrNotExist) {
		t.Fatalf("DefaultRoute with no default = %v, want ErrNotExist", err)
	}
	h.listRoutes = []netlink.Route{{LinkIndex: 999}}
	if _, err := n.DefaultRoute(FamilyV4); !errors.Is(err, ErrNotExist) {
		t.Fatalf("DefaultRoute via an unknown link = %v, want ErrNotExist", err)
	}
}

func TestNetlinkNet_Rules(t *testing.T) {
	h := newFakeHandle()
	n := &NetlinkNet{h: h}

	if err := n.RuleAdd(Rule{Src: netip.MustParsePrefix("10.0.0.2/32"), Table: 100, Priority: 50}); err != nil {
		t.Fatalf("RuleAdd: %v", err)
	}
	r := h.rulesAdded[0]
	if r.Src.String() != "10.0.0.2/32" || r.Table != 100 || r.Priority != 50 || r.Family != netlink.FAMILY_V4 {
		t.Fatalf("src rule = %+v", r)
	}
	if err := n.RuleDel(Rule{Iif: "egx1", Family: FamilyV6}); err != nil {
		t.Fatalf("RuleDel: %v", err)
	}
	r = h.rulesDeleted[0]
	if r.IifName != "egx1" || r.Table != MainTable || r.Family != netlink.FAMILY_V6 || r.Src != nil {
		t.Fatalf("iif rule = %+v", r)
	}
	if err := n.RuleAdd(Rule{Table: 7}); err != nil || h.rulesAdded[1].Family != netlink.FAMILY_V4 {
		t.Fatalf("rule without src or family should default to IPv4: err=%v rule=%+v", err, h.rulesAdded[1])
	}
}

func TestNetlinkNet_XfrmStates(t *testing.T) {
	h := newFakeHandle()
	n := &NetlinkNet{h: h}
	h.states = []netlink.XfrmState{
		{
			Src: net.ParseIP("192.0.2.2"), Dst: net.ParseIP("192.0.2.1"),
			Spi: int(0xc0ffee01), Ifid: 7,
			Statistics: netlink.XfrmStateStats{Packets: 40, Bytes: 4000},
			Replay:     &netlink.XfrmReplayState{Seq: 42},
		},
		{Spi: 1, Ifid: 9, ESN: true}, // ESN replay data: netlink leaves Replay nil
	}
	got, err := n.XfrmStates()
	if err != nil {
		t.Fatalf("XfrmStates: %v", err)
	}
	want0 := XfrmState{
		Src: netip.MustParseAddr("192.0.2.2"), Dst: netip.MustParseAddr("192.0.2.1"),
		SPI: 0xc0ffee01, IfID: 7, Packets: 40, Bytes: 4000, ReplaySeq: 42, HasReplay: true,
	}
	if len(got) != 2 || got[0] != want0 {
		t.Fatalf("XfrmStates[0] = %+v, want %+v", got[0], want0)
	}
	if got[1].HasReplay || got[1].Src.IsValid() {
		t.Fatalf("XfrmStates[1] = %+v, want HasReplay=false and no addresses", got[1])
	}
}

func TestNetlinkNet_Close(t *testing.T) {
	h := newFakeHandle()
	(&NetlinkNet{h: h}).Close()
	if !h.closed {
		t.Fatal("Close did not close the handle")
	}
}

func TestNetlinkHelpers(t *testing.T) {
	if _, ok := ipNetToPrefix(&net.IPNet{IP: net.IP{1, 2, 3}, Mask: net.CIDRMask(8, 32)}); ok {
		t.Error("ipNetToPrefix accepted a malformed IP")
	}
	if _, ok := ipNetToPrefix(&net.IPNet{IP: net.IPv4(10, 0, 0, 0).To4(), Mask: net.CIDRMask(8, 128)}); ok {
		t.Error("ipNetToPrefix accepted a mask of the wrong family")
	}
	if a := ipToAddr(net.IP{1, 2, 3}); a.IsValid() {
		t.Errorf("ipToAddr(3 bytes) = %v, want invalid", a)
	}
	if err := mapErr(syscall.EPERM); errors.Is(err, ErrExist) || errors.Is(err, ErrNotExist) {
		t.Errorf("mapErr(EPERM) = %v, want it left alone", err)
	}
}
