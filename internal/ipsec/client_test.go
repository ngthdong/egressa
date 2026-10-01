package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const testClientPSK = "client-psk-0123456789"

func testClientConfig() ClientConfig {
	return ClientConfig{
		LocalID:   "client-1",
		PSK:       testClientPSK,
		VirtualIP: netip.MustParseAddr("10.201.0.2"),
		LocalAddr: netip.MustParseAddr("198.51.100.10"),
		DPDDelay:  10 * time.Second,
	}
}

func testPeer(name string, ifID uint32, addr string) Peer {
	return Peer{Name: name, Addr: netip.MustParseAddr(addr), ID: "gw-" + name, IfID: ifID, Epoch: 1}
}

func newTestClient(t *testing.T, mutate func(*ClientConfig)) (*Client, *fakeIKE, *fakeNet) {
	t.Helper()
	cfg := testClientConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	ike, n := newFakeIKE(), newFakeNet()
	c, err := NewClient(cfg, ike, n)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c, ike, n
}

// assertClean checks that nothing the client created is left behind.
func assertClean(t *testing.T, ike *fakeIKE, n *fakeNet) {
	t.Helper()
	ike.mu.Lock()
	conns, secrets, sas := len(ike.conns), len(ike.secrets), len(ike.sas)
	ike.mu.Unlock()
	n.mu.Lock()
	links, routes := len(n.links), len(n.routes)
	n.mu.Unlock()
	if conns+secrets+sas != 0 || links != 1 || routes != 0 {
		t.Fatalf("left behind: %d conns, %d secrets, %d SAs, %d links (want only eth0), %d routes",
			conns, secrets, sas, links, routes)
	}
}

func TestNewClient_Validation(t *testing.T) {
	cases := map[string]func(*ClientConfig){
		"bad name":            func(c *ClientConfig) { c.Name = "bad name" },
		"bad local id":        func(c *ClientConfig) { c.LocalID = "" },
		"short psk":           func(c *ClientConfig) { c.PSK = "short" },
		"psk with space":      func(c *ClientConfig) { c.PSK = "aaaaaaaa aaaaaaaaaaa" },
		"no virtual ip":       func(c *ClientConfig) { c.VirtualIP = netip.Addr{} },
		"zoned virtual ip":    func(c *ClientConfig) { c.VirtualIP = netip.MustParseAddr("fe80::2%eth0") },
		"zoned local addr":    func(c *ClientConfig) { c.LocalAddr = netip.MustParseAddr("fe80::1%eth0") },
		"invalid controller":  func(c *ClientConfig) { c.Controllers = []netip.Addr{{}} },
		"zoned controller":    func(c *ClientConfig) { c.Controllers = []netip.Addr{netip.MustParseAddr("fe80::9%eth0")} },
		"controller v6 vs v4": func(c *ClientConfig) { c.Controllers = []netip.Addr{netip.MustParseAddr("2001:db8::9")} },
		"negative table":      func(c *ClientConfig) { c.Table = -1 },
		"long iface prefix":   func(c *ClientConfig) { c.InterfacePrefix = "egressax" },
		"iface prefix chars":  func(c *ClientConfig) { c.InterfacePrefix = "eg-x" },
		"negative dpd":        func(c *ClientConfig) { c.DPDDelay = -time.Second },
	}
	for name, mutate := range cases {
		cfg := testClientConfig()
		mutate(&cfg)
		c, err := NewClient(cfg, newFakeIKE(), newFakeNet())
		if err == nil {
			t.Errorf("%s: NewClient accepted an invalid config", name)
		}
		if c != nil {
			t.Errorf("%s: NewClient returned %#v with an error, want nil", name, c)
		}
	}
}

func TestClient_AddIsWarmStandby(t *testing.T) {
	c, ike, n := newTestClient(t, nil)
	ctx := context.Background()
	p := testPeer("hk", 7, "203.0.113.1")
	p.Epoch = 3
	if err := c.Add(ctx, p); err != nil {
		t.Fatalf("Add: %v", err)
	}

	l, ok := n.link("egx7")
	if !ok || l.ifID != 7 || !l.up || !slices.Equal(l.addrs, []netip.Prefix{netip.MustParsePrefix("10.201.0.2/32")}) {
		t.Fatalf("xfrm interface = %+v (exists %v), want egx7 if_id 7, up, with the virtual IP", l, ok)
	}
	sec, ok := ike.secrets["egressa-hk"]
	if !ok || sec.PSK != testClientPSK || !slices.Equal(sec.Owners, []string{"client-1", "gw-hk"}) {
		t.Fatalf("shared secret = %+v (loaded %v)", sec, ok)
	}
	conn, ok := ike.conns["egressa-hk"]
	if !ok {
		t.Fatal("connection not loaded")
	}
	want := Connection{
		Name: "egressa-hk", Epoch: 3,
		LocalAddr: netip.MustParseAddr("198.51.100.10"), RemoteAddr: p.Addr,
		LocalID: "client-1", RemoteID: "gw-hk", Auth: AuthPSK, PSK: testClientPSK,
		LocalTS:  []netip.Prefix{netip.MustParsePrefix("10.201.0.2/32")},
		RemoteTS: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		IfID:     7, DPDDelay: 10 * time.Second, Start: StartNone,
	}
	if !reflect.DeepEqual(conn, want) {
		t.Fatalf("connection =\n%+v\nwant\n%+v", conn, want)
	}
	if warm, err := c.Warm(ctx, "hk"); err != nil || !warm {
		t.Fatalf("Warm after Add = %v, %v", warm, err)
	}
	if n.routeCount() != 0 || len(c.Routes()) != 0 || c.Active() != "" {
		t.Fatal("Add routed traffic: a standby must have no route pointing at it")
	}
	if !slices.Equal(c.Peers(), []string{"hk"}) {
		t.Fatalf("Peers = %v", c.Peers())
	}
}

func TestClient_AddRejects(t *testing.T) {
	c, _, _ := newTestClient(t, nil)
	ctx := context.Background()
	if err := c.Add(ctx, testPeer("hk", 7, "203.0.113.1")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	cases := map[string]Peer{
		"same name":          testPeer("hk", 8, "203.0.113.2"),
		"same if_id":         testPeer("sg", 7, "203.0.113.2"),
		"zoned address":      {Name: "x", Addr: netip.MustParseAddr("fe80::1%eth0"), ID: "gw", IfID: 9},
		"other family":       {Name: "x", Addr: netip.MustParseAddr("2001:db8::1"), ID: "gw", IfID: 9},
		"no address":         {Name: "x", ID: "gw", IfID: 9},
		"prefix family":      {Name: "x", Addr: netip.MustParseAddr("203.0.113.3"), ID: "gw", IfID: 9, Prefixes: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}},
		"invalid prefix":     {Name: "x", Addr: netip.MustParseAddr("203.0.113.3"), ID: "gw", IfID: 9, Prefixes: []netip.Prefix{{}}},
		"bad gateway id":     {Name: "x", Addr: netip.MustParseAddr("203.0.113.3"), ID: "g w", IfID: 9},
		"zero if_id":         {Name: "x", Addr: netip.MustParseAddr("203.0.113.3"), ID: "gw", IfID: 0},
		"name not a conn id": {Name: "x y", Addr: netip.MustParseAddr("203.0.113.3"), ID: "gw", IfID: 9},
	}
	for name, p := range cases {
		if err := c.Add(ctx, p); err == nil {
			t.Errorf("%s: Add accepted it", name)
		}
	}
	if err := c.Add(ctx, testPeer("hk", 8, "203.0.113.2")); !errors.Is(err, ErrExist) {
		t.Errorf("duplicate name = %v, want ErrExist", err)
	}
}

func TestClient_PendingAddDetectedAndLockNotHeldDuringIKE(t *testing.T) {
	c, ike, _ := newTestClient(t, nil)
	ctx := context.Background()
	if err := c.Add(ctx, testPeer("sg", 8, "203.0.113.2")); err != nil {
		t.Fatalf("Add sg: %v", err)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	ike.onInitiate = func(_ context.Context, ike, _ string) error {
		if ike == "egressa-hk" {
			close(entered)
			<-release
		}
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- c.Add(ctx, testPeer("hk", 7, "203.0.113.1")) }()
	<-entered

	// hk is mid-negotiation. A second Add of the same name or if_id must
	// fail at once instead of racing it...
	if err := c.Add(ctx, testPeer("hk", 9, "203.0.113.9")); !errors.Is(err, ErrExist) {
		t.Fatalf("Add while the same name is being added = %v, want ErrExist", err)
	}
	if err := c.Add(ctx, testPeer("jp", 7, "203.0.113.9")); !errors.Is(err, ErrExist) {
		t.Fatalf("Add with an if_id being added = %v, want ErrExist", err)
	}
	// ...while the client stays fully usable: no lock is held across IKE.
	if err := c.Add(ctx, testPeer("us", 10, "203.0.113.10")); err != nil {
		t.Fatalf("Add of another gateway during a negotiation: %v", err)
	}
	if err := c.Promote(ctx, "sg", netip.MustParsePrefix("10.0.0.0/8")); err != nil {
		t.Fatalf("Promote during a negotiation: %v", err)
	}
	if _, err := c.Warm(ctx, "sg"); err != nil {
		t.Fatalf("Warm during a negotiation: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("blocked Add: %v", err)
	}
	if len(c.Peers()) != 3 {
		t.Fatalf("Peers = %v, want sg, hk, us", c.Peers())
	}
}

func TestClient_AddRollsBackEveryStep(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*fakeIKE, *fakeNet)
	}{
		{"xfrm interface", func(_ *fakeIKE, n *fakeNet) { n.setErr("add-xfrm egx7", errors.New("boom")) }},
		{"address", func(_ *fakeIKE, n *fakeNet) { n.setErr("add-addr egx7", errors.New("boom")) }},
		{"link up", func(_ *fakeIKE, n *fakeNet) { n.setErr("link-up egx7", errors.New("boom")) }},
		{"bypass route", func(_ *fakeIKE, n *fakeNet) { n.setErr("route-add 203.0.113.1/32", errors.New("boom")) }},
		{"bypass lookup", func(_ *fakeIKE, n *fakeNet) { n.setErr("route-get 203.0.113.1", errors.New("boom")) }},
		{"secret", func(ike *fakeIKE, _ *fakeNet) { ike.setErr("load-shared", errors.New("boom")) }},
		{"connection", func(ike *fakeIKE, _ *fakeNet) { ike.setErr("load-conn", errors.New("boom")) }},
		{"initiate", func(ike *fakeIKE, _ *fakeNet) { ike.setErr("initiate", ErrAuthFailed) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ike, n := newTestClient(t, func(cfg *ClientConfig) { cfg.FullTunnel = true })
			tc.setup(ike, n)
			err := c.Add(context.Background(), testPeer("hk", 7, "203.0.113.1"))
			if err == nil {
				t.Fatal("Add succeeded despite the injected failure")
			}
			assertClean(t, ike, n)
			// The name and if_id are free again.
			ike.setErr("load-shared", nil)
			ike.setErr("load-conn", nil)
			ike.setErr("initiate", nil)
			for op := range n.errs {
				n.setErr(op, nil)
			}
			if err := c.Add(context.Background(), testPeer("hk", 7, "203.0.113.1")); err != nil {
				t.Fatalf("Add after a rolled-back Add: %v", err)
			}
		})
	}
}

func TestClient_AddRollbackSurvivesCancellationAndTerminatesIKE(t *testing.T) {
	c, ike, n := newTestClient(t, nil)
	ike.honorCtx = true
	ctx, cancel := context.WithCancel(context.Background())
	ike.onInitiate = func(ictx context.Context, name, _ string) error {
		// The exchange got far enough to leave an IKE_SA behind, then the
		// caller gave up.
		ike.addSA(IKESA{Name: name, State: "CONNECTING"})
		cancel()
		<-ictx.Done()
		return ictx.Err()
	}
	err := c.Add(ctx, testPeer("hk", 7, "203.0.113.1"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Add = %v, want the cancellation", err)
	}
	// Cleanup ran on a live context although ctx is cancelled, and it
	// terminated the IKE_SA the cancelled initiate left behind.
	if !slices.Contains(ike.calls(), "terminate-ike egressa-hk") {
		t.Fatalf("rollback did not terminate the IKE_SA: %v", ike.calls())
	}
	assertClean(t, ike, n)
}

func TestClient_AddCancelledBeforeInitiate(t *testing.T) {
	c, ike, n := newTestClient(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Add(ctx, testPeer("hk", 7, "203.0.113.1")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Add with a cancelled context = %v", err)
	}
	if slices.Contains(ike.calls(), "initiate egressa-hk-e1") {
		t.Fatal("Add initiated although its context was already cancelled")
	}
	assertClean(t, ike, n)
}

func TestClient_AddReportsIncompleteRollback(t *testing.T) {
	c, ike, n := newTestClient(t, nil)
	ike.setErr("initiate", errors.New("timeout"))
	n.setErr("delete-link egx7", errors.New("device busy"))
	err := c.Add(context.Background(), testPeer("hk", 7, "203.0.113.1"))
	if err == nil || !strings.Contains(err.Error(), "rollback incomplete") || !strings.Contains(err.Error(), "device busy") {
		t.Fatalf("Add = %v, want the original error plus the rollback failure", err)
	}
}

func TestClient_CloseDuringAddRollsBackTheAdd(t *testing.T) {
	c, ike, n := newTestClient(t, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	ike.onInitiate = func(context.Context, string, string) error {
		close(entered)
		<-release
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- c.Add(context.Background(), testPeer("hk", 7, "203.0.113.1")) }()
	<-entered
	if err := c.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	close(release)
	if err := <-done; !errors.Is(err, errClientClosed) {
		t.Fatalf("Add finishing after Close = %v, want errClientClosed", err)
	}
	assertClean(t, ike, n)
	if err := c.Add(context.Background(), testPeer("sg", 8, "203.0.113.2")); !errors.Is(err, errClientClosed) {
		t.Fatalf("Add after Close = %v", err)
	}
}

func TestClient_PromoteSplitTunnel(t *testing.T) {
	c, _, n := newTestClient(t, func(cfg *ClientConfig) { cfg.Table = 100 })
	ctx := context.Background()
	for _, p := range []Peer{testPeer("hk", 7, "203.0.113.1"), testPeer("sg", 8, "203.0.113.2")} {
		if err := c.Add(ctx, p); err != nil {
			t.Fatalf("Add %s: %v", p.Name, err)
		}
	}
	a, b := netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12")
	if err := c.Promote(ctx, "hk", a, netip.MustParsePrefix("172.16.5.0/12"), a); err != nil {
		t.Fatalf("Promote hk: %v", err)
	}
	for _, dst := range []string{"10.0.0.0/8", "172.16.0.0/12"} {
		r, ok := n.route(100, dst)
		if !ok || r.Dev != "egx7" || r.Src != netip.MustParseAddr("10.201.0.2") {
			t.Fatalf("route %s = %+v (present %v), want dev egx7 src 10.201.0.2 in table 100", dst, r, ok)
		}
	}
	if n.routeCount() != 2 || c.Active() != "hk" {
		t.Fatalf("routes = %d, active = %q; want 2 deduplicated, masked routes and hk active", n.routeCount(), c.Active())
	}

	// Move to sg with a different prefix set: a moves, b is withdrawn,
	// c is new.
	cpf := netip.MustParsePrefix("192.168.0.0/16")
	if err := c.Promote(ctx, "sg", a, cpf); err != nil {
		t.Fatalf("Promote sg: %v", err)
	}
	if r, _ := n.route(100, "10.0.0.0/8"); r.Dev != "egx8" {
		t.Fatalf("10.0.0.0/8 now via %s, want egx8", r.Dev)
	}
	if _, ok := n.route(100, b.String()); ok {
		t.Fatal("172.16.0.0/12 was not withdrawn")
	}
	if got := c.Routes(); len(got) != 2 || got[0].Dst != a || got[1].Dst != cpf {
		t.Fatalf("Routes = %+v", got)
	}
	if c.Active() != "sg" {
		t.Fatalf("Active = %q", c.Active())
	}
}

func TestClient_PromoteRejects(t *testing.T) {
	c, _, _ := newTestClient(t, nil)
	ctx := context.Background()
	if err := c.Add(ctx, testPeer("hk", 7, "203.0.113.1")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	cases := map[string]error{
		"no prefixes":     c.Promote(ctx, "hk"),
		"default route":   c.Promote(ctx, "hk", netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("0.0.0.0/0")),
		"other family":    c.Promote(ctx, "hk", netip.MustParsePrefix("2001:db8::/32")),
		"invalid prefix":  c.Promote(ctx, "hk", netip.Prefix{}),
		"unknown gateway": c.Promote(ctx, "nope", netip.MustParsePrefix("10.0.0.0/8")),
		"cancelled ctx":   c.Promote(cancelled, "hk", netip.MustParsePrefix("10.0.0.0/8")),
	}
	for name, err := range cases {
		if err == nil {
			t.Errorf("%s: Promote accepted it", name)
		}
	}
	if !errors.Is(cases["unknown gateway"], ErrNotFound) {
		t.Errorf("unknown gateway = %v, want ErrNotFound", cases["unknown gateway"])
	}
	if len(c.Routes()) != 0 {
		t.Fatal("a rejected Promote installed routes")
	}
}

func TestClient_PromoteUndoesPartialChange(t *testing.T) {
	c, _, n := newTestClient(t, nil)
	ctx := context.Background()
	for _, p := range []Peer{testPeer("hk", 7, "203.0.113.1"), testPeer("sg", 8, "203.0.113.2")} {
		if err := c.Add(ctx, p); err != nil {
			t.Fatalf("Add %s: %v", p.Name, err)
		}
	}
	a, b, d := netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16")
	if err := c.Promote(ctx, "hk", a); err != nil {
		t.Fatalf("Promote hk: %v", err)
	}
	// Moving a (already routed) and adding b both work; d fails.
	n.setErr("route-replace "+d.String(), errors.New("no buffer space"))
	err := c.Promote(ctx, "sg", a, b, d)
	if err == nil || !strings.Contains(err.Error(), "no buffer space") {
		t.Fatalf("Promote = %v, want the replace failure", err)
	}
	if r, _ := n.route(0, a.String()); r.Dev != "egx7" {
		t.Fatalf("a now via %s; the partial move must be undone back to egx7", r.Dev)
	}
	if _, ok := n.route(0, b.String()); ok {
		t.Fatal("b was left installed after the failed Promote")
	}
	if c.Active() != "hk" || len(c.Routes()) != 1 {
		t.Fatalf("after a failed Promote: active %q routes %v; want hk and only a", c.Active(), c.Routes())
	}

	// When undoing itself fails, the error says so.
	n.setErr("route-replace "+a.String(), nil)
	n.setErr("route-del "+b.String(), errors.New("busy"))
	if err := c.Promote(ctx, "sg", b, d); err == nil || !strings.Contains(err.Error(), "undoing the partial change failed") {
		t.Fatalf("Promote with a failing undo = %v", err)
	}
}

func TestClient_PromoteKeepsTrackOfRoutesItFailedToWithdraw(t *testing.T) {
	c, _, n := newTestClient(t, nil)
	ctx := context.Background()
	if err := c.Add(ctx, testPeer("hk", 7, "203.0.113.1")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	a, b := netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12")
	if err := c.Promote(ctx, "hk", a, b); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	n.setErr("route-del "+b.String(), errors.New("busy"))
	if err := c.Promote(ctx, "hk", a); err == nil {
		t.Fatal("Promote hid a failed withdrawal")
	}
	if got := c.Routes(); len(got) != 2 {
		t.Fatalf("Routes = %v; a route that could not be withdrawn must stay tracked for a retry", got)
	}
	n.setErr("route-del "+b.String(), nil)
	if err := c.Promote(ctx, "hk", a); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if _, ok := n.route(0, b.String()); ok || len(c.Routes()) != 1 {
		t.Fatal("the retried withdrawal did not happen")
	}
	// A route someone else already removed is not an error.
	n.mu.Lock()
	delete(n.routes, routeKey{MainTable, a})
	n.mu.Unlock()
	if err := c.Promote(ctx, "hk", b); err != nil {
		t.Fatalf("withdrawing an already-gone route: %v", err)
	}
}

func TestClient_FullTunnel(t *testing.T) {
	controller := netip.MustParseAddr("198.51.100.50")
	c, _, n := newTestClient(t, func(cfg *ClientConfig) {
		cfg.FullTunnel = true
		cfg.Controllers = []netip.Addr{controller, controller} // listed twice: one route, two refs
	})
	ctx := context.Background()
	if r, ok := n.route(0, "198.51.100.50/32"); !ok || r.Dev != "eth0" || r.Gw != netip.MustParseAddr("198.51.100.1") {
		t.Fatalf("controller bypass = %+v (present %v), want via 198.51.100.1 dev eth0", r, ok)
	}
	if err := c.Add(ctx, testPeer("hk", 7, "203.0.113.1")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if r, ok := n.route(0, "203.0.113.1/32"); !ok || r.Dev != "eth0" {
		t.Fatalf("gateway bypass = %+v (present %v)", r, ok)
	}
	if err := c.Promote(ctx, "hk", netip.MustParsePrefix("10.0.0.0/8")); err == nil {
		t.Fatal("full-tunnel Promote accepted explicit prefixes")
	}
	if err := c.Promote(ctx, "hk"); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if r, ok := n.route(0, half); !ok || r.Dev != "egx7" {
			t.Fatalf("full-tunnel half %s = %+v (present %v)", half, r, ok)
		}
	}
	if _, ok := n.route(0, "0.0.0.0/0"); ok {
		t.Fatal("full tunnel installed a default route")
	}
	if n.defs[FamilyV4].Dev != "eth0" {
		t.Fatal("full tunnel modified the default route")
	}

	// A standby added now: the lookup for it lands on our /1, so its
	// bypass must come from the default route, not from egx7.
	if r, _ := n.RouteGet(netip.MustParseAddr("203.0.113.2")); r.Dev != "egx7" {
		t.Fatalf("precondition: lookup for a new gateway should hit the tunnel, got %+v", r)
	}
	if err := c.Add(ctx, testPeer("sg", 8, "203.0.113.2")); err != nil {
		t.Fatalf("Add standby under full tunnel: %v", err)
	}
	if r, ok := n.route(0, "203.0.113.2/32"); !ok || r.Dev != "eth0" || r.Gw != netip.MustParseAddr("198.51.100.1") {
		t.Fatalf("late standby bypass = %+v (present %v), want via the underlay", r, ok)
	}
	if err := c.Remove(ctx, "sg"); err != nil {
		t.Fatalf("Remove standby: %v", err)
	}
	if _, ok := n.route(0, "203.0.113.2/32"); ok {
		t.Fatal("removing a gateway left its bypass route")
	}

	if err := c.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if n.routeCount() != 0 {
		t.Fatalf("Close left %d routes", n.routeCount())
	}
}

func TestClient_FullTunnelIPv6(t *testing.T) {
	c, ike, n := newTestClient(t, func(cfg *ClientConfig) {
		cfg.FullTunnel = true
		cfg.VirtualIP = netip.MustParseAddr("fd00::2")
		cfg.LocalAddr = netip.MustParseAddr("2001:db8:1::10")
	})
	ctx := context.Background()
	if err := c.Add(ctx, Peer{Name: "hk", Addr: netip.MustParseAddr("2001:db8:2::1"), ID: "gw-hk", IfID: 7}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if got := ike.conns["egressa-hk"].RemoteTS; !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("::/0")}) {
		t.Fatalf("v6 remote TS = %v, want ::/0", got)
	}
	if err := c.Promote(ctx, "hk"); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	for _, half := range []string{"::/1", "8000::/1"} {
		if r, ok := n.route(0, half); !ok || r.Src != netip.MustParseAddr("fd00::2") {
			t.Fatalf("v6 half %s = %+v (present %v)", half, r, ok)
		}
	}
}

func TestClient_BypassOwnership(t *testing.T) {
	gwAddr := netip.MustParseAddr("203.0.113.1")
	ctx := context.Background()
	ike, n := newFakeIKE(), newFakeNet()
	// Someone else already routes this gateway: the client must use that
	// route but never delete it.
	foreign := Route{Dst: hostPrefix(gwAddr), Gw: netip.MustParseAddr("198.51.100.254"), Dev: "eth0"}
	if err := n.RouteAdd(foreign); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cfg := testClientConfig()
	cfg.FullTunnel = true
	cfg.Controllers = []netip.Addr{gwAddr} // the controller shares the gateway's address
	c, err := NewClient(cfg, ike, n)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c.Add(ctx, testPeer("hk", 7, gwAddr.String())); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := c.Remove(ctx, "hk"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if r, ok := n.route(0, hostPrefix(gwAddr).String()); !ok || r != foreign {
		t.Fatalf("pre-existing route = %+v (present %v); a client must only delete bypass routes it created", r, ok)
	}

	// Shared ownership: the route the client created for a controller that
	// is also a gateway lives until both are released.
	n2 := newFakeNet()
	c2, err := NewClient(cfg, newFakeIKE(), n2)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if err := c2.Add(ctx, testPeer("hk", 7, gwAddr.String())); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := c2.Remove(ctx, "hk"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, ok := n2.route(0, hostPrefix(gwAddr).String()); !ok {
		t.Fatal("bypass removed while the controller still needs it")
	}
	if err := c2.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, ok := n2.route(0, hostPrefix(gwAddr).String()); ok {
		t.Fatal("bypass the client created outlived the client")
	}
}

func TestClient_BypassErrors(t *testing.T) {
	cfg := testClientConfig()
	cfg.FullTunnel = true
	cfg.Controllers = []netip.Addr{netip.MustParseAddr("198.51.100.50"), netip.MustParseAddr("198.51.100.51")}
	n := newFakeNet()
	n.setErr("route-add 198.51.100.51/32", errors.New("boom"))
	if c, err := NewClient(cfg, newFakeIKE(), n); err == nil || c != nil {
		t.Fatalf("NewClient with a failing controller bypass = %v, %v", c, err)
	}
	if n.routeCount() != 0 {
		t.Fatal("a failed NewClient left the first controller's bypass behind")
	}

	// Lookup lands in the tunnel and there is no default route to fall
	// back to.
	c, _, n2 := newTestClient(t, func(cfg *ClientConfig) { cfg.FullTunnel = true })
	ctx := context.Background()
	if err := c.Add(ctx, testPeer("hk", 7, "203.0.113.1")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := c.Promote(ctx, "hk"); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	n2.mu.Lock()
	delete(n2.defs, FamilyV4)
	n2.mu.Unlock()
	if err := c.Add(ctx, testPeer("sg", 8, "203.0.113.2")); err == nil || !strings.Contains(err.Error(), "no default route") {
		t.Fatalf("Add without an underlay path = %v", err)
	}
	if err := c.releaseBypass(netip.MustParseAddr("192.0.2.200")); err != nil {
		t.Fatalf("releasing an unknown bypass: %v", err)
	}
}

func TestClient_Remove(t *testing.T) {
	c, ike, n := newTestClient(t, nil)
	ctx := context.Background()
	for _, p := range []Peer{testPeer("hk", 7, "203.0.113.1"), testPeer("sg", 8, "203.0.113.2")} {
		if err := c.Add(ctx, p); err != nil {
			t.Fatalf("Add %s: %v", p.Name, err)
		}
	}
	if err := c.Promote(ctx, "hk", netip.MustParsePrefix("10.0.0.0/8")); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if err := c.Remove(ctx, "hk"); err == nil || !strings.Contains(err.Error(), "carries the routes") {
		t.Fatalf("Remove of the active gateway = %v, want a refusal", err)
	}
	if err := c.Remove(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Remove of an unknown gateway = %v", err)
	}
	if err := c.Remove(ctx, "sg"); err != nil {
		t.Fatalf("Remove sg: %v", err)
	}
	if _, ok := n.link("egx8"); ok {
		t.Fatal("Remove left the XFRM interface")
	}
	if _, ok := ike.conns["egressa-sg"]; ok {
		t.Fatal("Remove left the connection loaded")
	}
	if _, ok := ike.secrets["egressa-sg"]; ok {
		t.Fatal("Remove left the secret loaded")
	}
	// The name and if_id are free again.
	if err := c.Add(ctx, testPeer("sg", 8, "203.0.113.2")); err != nil {
		t.Fatalf("re-Add: %v", err)
	}

	// Teardown errors are reported, but the gateway is gone either way.
	n.setErr("delete-link egx8", errors.New("busy"))
	if err := c.Remove(ctx, "sg"); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("Remove with a failing step = %v", err)
	}
	if slices.Contains(c.Peers(), "sg") {
		t.Fatal("a gateway whose teardown failed is still listed")
	}
	if err := c.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.Remove(ctx, "hk"); !errors.Is(err, errClientClosed) {
		t.Fatalf("Remove after Close = %v", err)
	}
}

func TestClient_FenceBelowAndAdvance(t *testing.T) {
	c, ike, _ := newTestClient(t, nil)
	ctx := context.Background()
	p := testPeer("hk", 7, "203.0.113.1")
	p.Epoch = 4
	if err := c.Add(ctx, p); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := c.Advance(ctx, "hk", 4); err == nil {
		t.Fatal("Advance to the current epoch succeeded")
	}
	if err := c.Advance(ctx, "hk", 6); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	sas, _ := ike.ListSAs(ctx, "egressa-hk")
	if len(sas) != 1 || len(sas[0].Children) != 1 || sas[0].Children[0].Name != "egressa-hk-e6" {
		t.Fatalf("after Advance: %+v, want one IKE_SA carrying only the epoch-6 child", sas)
	}
	if got := ike.conns["egressa-hk"].Epoch; got != 6 {
		t.Fatalf("loaded connection epoch = %d, want 6", got)
	}
	// The client remembers the new epoch: advancing to it again fails.
	if err := c.Advance(ctx, "hk", 6); err == nil {
		t.Fatal("Advance to the same epoch twice succeeded")
	}

	// Foreign children (another connection's, unparseable names) are left
	// alone by FenceBelow.
	ike.mu.Lock()
	ike.sas[0].Children = append(ike.sas[0].Children,
		ChildSA{Name: "manual-child", UniqueID: 900, State: ChildStateInstalled},
		ChildSA{Name: "other-conn-e1", UniqueID: 901, State: ChildStateInstalled},
	)
	ike.mu.Unlock()
	if err := c.FenceBelow(ctx, "hk", 7); err != nil {
		t.Fatalf("FenceBelow: %v", err)
	}
	sas, _ = ike.ListSAs(ctx, "egressa-hk")
	var names []string
	for _, ch := range sas[0].Children {
		names = append(names, ch.Name)
	}
	if !slices.Equal(names, []string{"manual-child", "other-conn-e1"}) {
		t.Fatalf("children after FenceBelow(7) = %v, want only the foreign ones left", names)
	}
	if warm, _ := c.Warm(ctx, "hk"); !warm {
		t.Fatal("precondition: foreign installed children keep the SA warm in this fake")
	}

	if err := c.FenceBelow(ctx, "nope", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("FenceBelow of an unknown gateway = %v", err)
	}
	ike.setErr("list", errors.New("down"))
	if err := c.FenceBelow(ctx, "hk", 9); err == nil {
		t.Fatal("FenceBelow hid a query error")
	}
}

func TestClient_FenceBelowReportsTerminateErrors(t *testing.T) {
	c, ike, _ := newTestClient(t, nil)
	ctx := context.Background()
	if err := c.Add(ctx, testPeer("hk", 7, "203.0.113.1")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	ike.setErr("terminate-child", errors.New("busy"))
	if err := c.FenceBelow(ctx, "hk", 5); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("FenceBelow = %v, want the terminate failure", err)
	}
}

func TestClient_AdvanceFailures(t *testing.T) {
	c, ike, _ := newTestClient(t, nil)
	ctx := context.Background()
	if err := c.Add(ctx, testPeer("hk", 7, "203.0.113.1")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := c.Advance(ctx, "nope", 5); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Advance of an unknown gateway = %v", err)
	}

	ike.setErr("load-conn", errors.New("rejected"))
	if err := c.Advance(ctx, "hk", 5); err == nil {
		t.Fatal("Advance hid a load-conn failure")
	}
	ike.setErr("load-conn", nil)

	// The new child fails: the old configuration (epoch 1) comes back and
	// its child keeps running.
	ike.setErr("initiate", errors.New("no proposal chosen"))
	if err := c.Advance(ctx, "hk", 5); err == nil {
		t.Fatal("Advance hid an initiate failure")
	}
	if got := ike.conns["egressa-hk"].Epoch; got != 1 {
		t.Fatalf("connection epoch after a failed Advance = %d, want the old 1", got)
	}
	if warm, _ := c.Warm(ctx, "hk"); !warm {
		t.Fatal("the old child stopped after a failed Advance")
	}

	// Restoring fails too: both are reported.
	ike.onInitiate = func(context.Context, string, string) error {
		ike.setErr("load-conn", errors.New("daemon gone"))
		return errors.New("no proposal chosen")
	}
	ike.setErr("initiate", nil)
	if err := c.Advance(ctx, "hk", 5); err == nil || !strings.Contains(err.Error(), "restoring the old connection failed") {
		t.Fatalf("Advance with a failing restore = %v", err)
	}
}

func TestClient_WarmAndWaits(t *testing.T) {
	c, ike, _ := newTestClient(t, func(cfg *ClientConfig) { cfg.PollInterval = time.Hour })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for name, err := range map[string]error{
		"Warm": func() error { _, err := c.Warm(ctx, "nope"); return err }(),
		"WaitWarm": func() error {
			_, err := c.WaitWarm(ctx, "nope")
			return err
		}(),
		"WaitDown": c.WaitDown(ctx, "nope"),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("%s of an unknown gateway = %v", name, err)
		}
	}
	if err := c.Add(ctx, testPeer("hk", 7, "203.0.113.1")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if sa, err := c.WaitWarm(ctx, "hk"); err != nil || !sa.Warm() {
		t.Fatalf("WaitWarm = %+v, %v", sa, err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		waitForCond(func() bool { return ike.subscribers() == 1 })
		ike.dropIKE("egressa-hk", true) // DPD gave up on the gateway
	}()
	if err := c.WaitDown(ctx, "hk"); err != nil {
		t.Fatalf("WaitDown: %v", err)
	}
	wg.Wait()
}

func TestClient_CloseReportsErrorsAndIsIdempotent(t *testing.T) {
	c, ike, n := newTestClient(t, nil)
	ctx := context.Background()
	if err := c.Add(ctx, testPeer("hk", 7, "203.0.113.1")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := c.Promote(ctx, "hk", netip.MustParsePrefix("10.0.0.0/8")); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	ike.setErr("terminate", errors.New("daemon gone"))
	if err := c.Close(ctx); err == nil || !strings.Contains(err.Error(), "daemon gone") {
		t.Fatalf("Close = %v, want the teardown failure", err)
	}
	if n.routeCount() != 0 {
		t.Fatal("Close left tunnel routes although only IKE teardown failed")
	}
	if err := c.Close(ctx); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	if _, err := c.Warm(ctx, "hk"); !errors.Is(err, errClientClosed) {
		t.Fatalf("Warm after Close = %v", err)
	}
}

func TestRouteSetSortsRoutes(t *testing.T) {
	s := newRouteSet(newFakeNet())
	want := []Route{
		{Dst: netip.MustParsePrefix("10.0.0.0/8"), Dev: "eth0"},
		{Dst: netip.MustParsePrefix("10.0.0.0/16"), Dev: "eth0"},
		{Dst: netip.MustParsePrefix("192.168.0.0/16"), Dev: "eth0"},
	}
	if err := s.apply([]Route{want[2], want[1], want[0]}); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := s.routes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("routes() = %v, want sorted by address then length", got)
	}
}

func TestRouteString(t *testing.T) {
	r := Route{Dst: netip.MustParsePrefix("10.0.0.0/8"), Gw: netip.MustParseAddr("192.0.2.1"), Dev: "egx7", Src: netip.MustParseAddr("10.201.0.2"), Table: 100}
	if got, want := r.String(), "10.0.0.0/8 via 192.0.2.1 dev egx7 src 10.201.0.2 table 100"; got != want {
		t.Fatalf("String = %q, want %q", got, want)
	}
	if got := (Route{Dst: netip.MustParsePrefix("10.0.0.0/8")}).String(); got != "10.0.0.0/8 table 254" {
		t.Fatalf("String = %q", got)
	}
	if (Rule{}).family() != FamilyV4 || (Rule{Family: FamilyV6}).family() != FamilyV6 ||
		(Rule{Src: netip.MustParsePrefix("fd00::/64")}).family() != FamilyV6 {
		t.Fatal("Rule.family")
	}
}
