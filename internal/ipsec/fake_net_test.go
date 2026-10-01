package ipsec

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
)

// fakeNet is an in-memory kernel: links, addresses, routes per table,
// rules and XFRM states. RouteGet does a longest-prefix match over every
// installed route and then the default route, the way the kernel answers
// with no policy rules, so a full-tunnel /1 captures lookups exactly as it
// would for real.
type fakeNet struct {
	mu     sync.Mutex
	links  map[string]*fakeLink
	routes map[routeKey]Route
	rules  []Rule
	defs   map[Family]Route
	states []XfrmState
	log    []string

	errs map[string]error // by operation: "add-xfrm", "route-replace 10.0.0.0/8", ...
}

type fakeLink struct {
	ifID     uint32
	underlay string
	up       bool
	addrs    []netip.Prefix
}

type routeKey struct {
	table int
	dst   netip.Prefix
}

var _ Net = (*fakeNet)(nil)

func newFakeNet() *fakeNet {
	n := &fakeNet{
		links:  map[string]*fakeLink{"eth0": {up: true}},
		routes: map[routeKey]Route{},
		defs: map[Family]Route{
			FamilyV4: {Dst: netip.MustParsePrefix("0.0.0.0/0"), Gw: netip.MustParseAddr("198.51.100.1"), Dev: "eth0", Table: MainTable},
			FamilyV6: {Dst: netip.MustParsePrefix("::/0"), Gw: netip.MustParseAddr("2001:db8::1"), Dev: "eth0", Table: MainTable},
		},
		errs: map[string]error{},
	}
	return n
}

func (n *fakeNet) fail(op string) error {
	n.log = append(n.log, op)
	return n.errs[op]
}

func (n *fakeNet) setErr(op string, err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.errs[op] = err
}

func (n *fakeNet) AddXfrmInterface(name string, ifID uint32, underlay string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.fail("add-xfrm " + name); err != nil {
		return err
	}
	if _, ok := n.links[name]; ok {
		return fmt.Errorf("link %s: %w", name, ErrExist)
	}
	if underlay != "" && n.links[underlay] == nil {
		return fmt.Errorf("underlay %s: %w", underlay, ErrNotExist)
	}
	n.links[name] = &fakeLink{ifID: ifID, underlay: underlay}
	return nil
}

func (n *fakeNet) DeleteLink(name string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.fail("delete-link " + name); err != nil {
		return err
	}
	if _, ok := n.links[name]; !ok {
		return fmt.Errorf("link %s: %w", name, ErrNotExist)
	}
	delete(n.links, name)
	// The kernel drops every route through a deleted interface.
	for k, r := range n.routes {
		if r.Dev == name {
			delete(n.routes, k)
		}
	}
	return nil
}

func (n *fakeNet) AddAddr(name string, p netip.Prefix) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.fail("add-addr " + name); err != nil {
		return err
	}
	l := n.links[name]
	if l == nil {
		return fmt.Errorf("link %s: %w", name, ErrNotExist)
	}
	l.addrs = append(l.addrs, p)
	return nil
}

func (n *fakeNet) SetLinkUp(name string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.fail("link-up " + name); err != nil {
		return err
	}
	l := n.links[name]
	if l == nil {
		return fmt.Errorf("link %s: %w", name, ErrNotExist)
	}
	l.up = true
	return nil
}

func (n *fakeNet) checkDev(r Route) error {
	if r.Dev != "" && n.links[r.Dev] == nil {
		return fmt.Errorf("dev %s: %w", r.Dev, ErrNotExist)
	}
	return nil
}

func (n *fakeNet) RouteAdd(r Route) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.fail("route-add " + r.Dst.String()); err != nil {
		return err
	}
	if err := n.checkDev(r); err != nil {
		return err
	}
	k := routeKey{r.table(), r.Dst}
	if _, ok := n.routes[k]; ok {
		return fmt.Errorf("route %s: %w", r.Dst, ErrExist)
	}
	n.routes[k] = r
	return nil
}

func (n *fakeNet) RouteReplace(r Route) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.fail("route-replace " + r.Dst.String()); err != nil {
		return err
	}
	if err := n.checkDev(r); err != nil {
		return err
	}
	n.routes[routeKey{r.table(), r.Dst}] = r
	return nil
}

func (n *fakeNet) RouteDel(r Route) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.fail("route-del " + r.Dst.String()); err != nil {
		return err
	}
	k := routeKey{r.table(), r.Dst}
	if _, ok := n.routes[k]; !ok {
		return fmt.Errorf("route %s: %w", r.Dst, ErrNotExist)
	}
	delete(n.routes, k)
	return nil
}

func (n *fakeNet) RouteGet(dst netip.Addr) (Route, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.fail("route-get " + dst.String()); err != nil {
		return Route{}, err
	}
	var best Route
	found := false
	for _, r := range n.routes {
		if r.Dst.Contains(dst) && (!found || r.Dst.Bits() > best.Dst.Bits()) {
			best, found = r, true
		}
	}
	if !found {
		def, ok := n.defs[familyOf(dst)]
		if !ok {
			return Route{}, fmt.Errorf("no route to %s: %w", dst, ErrNotExist)
		}
		best = def
	}
	best.Dst = hostPrefix(dst)
	return best, nil
}

func (n *fakeNet) DefaultRoute(f Family) (Route, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.fail("default-route"); err != nil {
		return Route{}, err
	}
	def, ok := n.defs[f]
	if !ok {
		return Route{}, fmt.Errorf("no default route: %w", ErrNotExist)
	}
	return def, nil
}

func (n *fakeNet) RuleAdd(r Rule) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.fail("rule-add"); err != nil {
		return err
	}
	if slices.Contains(n.rules, r) {
		return fmt.Errorf("rule: %w", ErrExist)
	}
	n.rules = append(n.rules, r)
	return nil
}

func (n *fakeNet) RuleDel(r Rule) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.fail("rule-del"); err != nil {
		return err
	}
	i := slices.Index(n.rules, r)
	if i < 0 {
		return fmt.Errorf("rule: %w", ErrNotExist)
	}
	n.rules = slices.Delete(n.rules, i, i+1)
	return nil
}

func (n *fakeNet) XfrmStates() ([]XfrmState, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.fail("xfrm-states"); err != nil {
		return nil, err
	}
	return append([]XfrmState(nil), n.states...), nil
}

// route returns the route installed for dst in table (0 = main).
func (n *fakeNet) route(table int, dst string) (Route, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if table == 0 {
		table = MainTable
	}
	r, ok := n.routes[routeKey{table, netip.MustParsePrefix(dst)}]
	return r, ok
}

func (n *fakeNet) routeCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.routes)
}

func (n *fakeNet) link(name string) (*fakeLink, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	l, ok := n.links[name]
	if !ok {
		return nil, false
	}
	cp := *l
	return &cp, true
}
