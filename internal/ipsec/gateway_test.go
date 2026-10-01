package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	testGatewayClientPSK   = "gw-client-psk-0123456789"
	testGatewayBackbonePSK = "gw-backbone-psk-9876543210"
)

func testGatewayConfig() GatewayConfig {
	return GatewayConfig{
		LocalID:      "gw-b",
		LocalAddr:    netip.MustParseAddr("203.0.113.2"),
		ClientPSK:    testGatewayClientPSK,
		BackbonePSK:  testGatewayBackbonePSK,
		ClientSubnet: netip.MustParsePrefix("10.201.0.0/24"),
		InnerAddr:    netip.MustParseAddr("10.201.0.1"),
		ClientIfID:   9,
		DPDDelay:     10 * time.Second,
	}
}

func newTestGateway(t *testing.T, mutate func(*GatewayConfig)) (*Gateway, *fakeIKE, *fakeNet) {
	t.Helper()
	cfg := testGatewayConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	ike, n := newFakeIKE(), newFakeNet()
	g, err := NewGateway(cfg, ike, n)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return g, ike, n
}

func startedGateway(t *testing.T, mutate func(*GatewayConfig)) (*Gateway, *fakeIKE, *fakeNet) {
	t.Helper()
	g, ike, n := newTestGateway(t, mutate)
	if err := g.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	return g, ike, n
}

func testBackbone(id string, ifID uint32, addr string) BackbonePeer {
	return BackbonePeer{ID: id, Addr: netip.MustParseAddr(addr), IfID: ifID, Epoch: 1}
}

func TestNewGateway_Validation(t *testing.T) {
	cases := map[string]func(*GatewayConfig){
		"bad name":              func(c *GatewayConfig) { c.Name = "a b" },
		"bad local id":          func(c *GatewayConfig) { c.LocalID = "" },
		"bad backbone id":       func(c *GatewayConfig) { c.BackboneID = "a b" },
		"same identities":       func(c *GatewayConfig) { c.BackboneID = c.LocalID },
		"no local addr":         func(c *GatewayConfig) { c.LocalAddr = netip.Addr{} },
		"zoned local addr":      func(c *GatewayConfig) { c.LocalAddr = netip.MustParseAddr("fe80::1%eth0") },
		"short client psk":      func(c *GatewayConfig) { c.ClientPSK = "short" },
		"short backbone psk":    func(c *GatewayConfig) { c.BackbonePSK = "short" },
		"same psks":             func(c *GatewayConfig) { c.BackbonePSK = c.ClientPSK },
		"no client subnet":      func(c *GatewayConfig) { c.ClientSubnet = netip.Prefix{} },
		"served wrong family":   func(c *GatewayConfig) { c.Served = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")} },
		"inner addr family":     func(c *GatewayConfig) { c.InnerAddr = netip.MustParseAddr("fd00::1") },
		"zoned inner addr":      func(c *GatewayConfig) { c.InnerAddr = netip.MustParseAddr("fe80::1%eth0") },
		"zero client if_id":     func(c *GatewayConfig) { c.ClientIfID = 0 },
		"negative table":        func(c *GatewayConfig) { c.Table = -1 },
		"negative priority":     func(c *GatewayConfig) { c.RulePriority = -1 },
		"bad interface prefix":  func(c *GatewayConfig) { c.InterfacePrefix = "Egw" },
		"negative dpd":          func(c *GatewayConfig) { c.DPDDelay = -time.Second },
		"zoned local addr only": func(c *GatewayConfig) { c.LocalAddr = netip.MustParseAddr("fe80::2%lo") },
	}
	for name, mutate := range cases {
		cfg := testGatewayConfig()
		mutate(&cfg)
		g, err := NewGateway(cfg, newFakeIKE(), newFakeNet())
		if err == nil {
			t.Errorf("%s: NewGateway accepted it", name)
		}
		if g != nil {
			t.Errorf("%s: NewGateway returned %#v with an error, want nil", name, g)
		}
	}
}

func TestGateway_Start(t *testing.T) {
	g, ike, n := startedGateway(t, func(c *GatewayConfig) { c.Table = 200 })
	l, ok := n.link("egw9")
	if !ok || l.ifID != 9 || !l.up || !slices.Equal(l.addrs, []netip.Prefix{netip.MustParsePrefix("10.201.0.1/32")}) {
		t.Fatalf("client interface = %+v (exists %v)", l, ok)
	}
	if r, ok := n.route(0, "10.201.0.0/24"); !ok || r.Dev != "egw9" {
		t.Fatalf("client subnet route = %+v (present %v), want via egw9 in the main table", r, ok)
	}
	wantRule := Rule{Iif: "egw9", Table: 200, Priority: DefaultRulePriority, Family: FamilyV4}
	if got := n.rules; !slices.Equal(got, []Rule{wantRule}) {
		t.Fatalf("rules = %+v, want the iif rule %+v", got, wantRule)
	}
	sec, ok := ike.secrets["egressa-clients"]
	if !ok || sec.PSK != testGatewayClientPSK || !slices.Equal(sec.Owners, []string{"gw-b"}) {
		t.Fatalf("client secret = %+v (loaded %v), want it owned by the client-facing identity only", sec, ok)
	}
	want := Connection{
		Name: "egressa-clients", LocalAddr: netip.MustParseAddr("203.0.113.2"),
		LocalID: "gw-b", RemoteID: AnyID, Auth: AuthPSK, PSK: testGatewayClientPSK,
		LocalTS:  []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		RemoteTS: []netip.Prefix{netip.MustParsePrefix("10.201.0.0/24")},
		IfID:     9, DPDDelay: 10 * time.Second, Start: StartNone,
	}
	if got := ike.conns["egressa-clients"]; !reflect.DeepEqual(got, want) {
		t.Fatalf("responder =\n%+v\nwant\n%+v", got, want)
	}
	if g.ResponderName() != "egressa-clients" {
		t.Fatalf("ResponderName = %q", g.ResponderName())
	}
	if err := g.Start(context.Background()); err == nil {
		t.Fatal("second Start succeeded")
	}
}

func TestGateway_StartMinimal(t *testing.T) {
	_, ike, n := startedGateway(t, func(c *GatewayConfig) {
		c.InnerAddr = netip.Addr{}
		c.Table = MainTable
		c.Served = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	})
	if l, _ := n.link("egw9"); len(l.addrs) != 0 {
		t.Fatalf("addresses without InnerAddr: %v", l.addrs)
	}
	if len(n.rules) != 0 {
		t.Fatalf("a rule was added for the main table: %v", n.rules)
	}
	if got := ike.conns["egressa-clients"].LocalTS; !slices.Equal(got, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}) {
		t.Fatalf("served = %v", got)
	}
}

func TestGateway_StartRollsBack(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*fakeIKE, *fakeNet)
	}{
		{"interface", func(_ *fakeIKE, n *fakeNet) { n.setErr("add-xfrm egw9", errors.New("boom")) }},
		{"address", func(_ *fakeIKE, n *fakeNet) { n.setErr("add-addr egw9", errors.New("boom")) }},
		{"link up", func(_ *fakeIKE, n *fakeNet) { n.setErr("link-up egw9", errors.New("boom")) }},
		{"client route", func(_ *fakeIKE, n *fakeNet) { n.setErr("route-replace 10.201.0.0/24", errors.New("boom")) }},
		{"rule", func(_ *fakeIKE, n *fakeNet) { n.setErr("rule-add", errors.New("boom")) }},
		{"secret", func(ike *fakeIKE, _ *fakeNet) { ike.setErr("load-shared", errors.New("boom")) }},
		{"responder", func(ike *fakeIKE, _ *fakeNet) { ike.setErr("load-conn", errors.New("boom")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, ike, n := newTestGateway(t, func(c *GatewayConfig) { c.Table = 200 })
			tc.setup(ike, n)
			if err := g.Start(context.Background()); err == nil {
				t.Fatal("Start succeeded despite the injected failure")
			}
			assertClean(t, ike, n)
			if len(n.rules) != 0 {
				t.Fatalf("rules left: %v", n.rules)
			}
			// A failed Start can be retried.
			ike.setErr("load-shared", nil)
			ike.setErr("load-conn", nil)
			for op := range n.errs {
				n.setErr(op, nil)
			}
			if err := g.Start(context.Background()); err != nil {
				t.Fatalf("Start after a failed Start: %v", err)
			}
		})
	}

	g, ike, n := newTestGateway(t, func(c *GatewayConfig) { c.Table = 200 })
	ike.setErr("load-conn", errors.New("boom"))
	n.setErr("rule-del", errors.New("busy"))
	if err := g.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "rollback incomplete") {
		t.Fatalf("Start with a failing rollback = %v", err)
	}
}

func TestGateway_FenceClient(t *testing.T) {
	g, ike, _ := startedGateway(t, nil)
	ctx := context.Background()
	resp := g.ResponderName()
	a1 := ike.addSA(IKESA{Name: resp, State: IKEStateEstablished, RemoteID: "client-1"})
	a2 := ike.addSA(IKESA{Name: resp, State: IKEStateEstablished, RemoteID: "client-1"})
	b := ike.addSA(IKESA{Name: resp, State: IKEStateEstablished, RemoteID: "client-2"})
	ike.addSA(IKESA{Name: "unrelated", State: IKEStateEstablished, RemoteID: "client-1"})

	n, err := g.FenceClient(ctx, "client-1")
	if err != nil || n != 2 {
		t.Fatalf("FenceClient = %d, %v; want 2 torn down", n, err)
	}
	if calls := ike.calls(); !slices.Contains(calls, "terminate-ike-id "+strconv.FormatUint(a1.UniqueID, 10)) ||
		!slices.Contains(calls, "terminate-ike-id "+strconv.FormatUint(a2.UniqueID, 10)) {
		t.Fatalf("FenceClient did not terminate by unique id: %v", calls)
	}
	clients, _ := g.Clients(ctx)
	if len(clients) != 1 || clients[0].UniqueID != b.UniqueID {
		t.Fatalf("clients left = %+v, want only client-2", clients)
	}
	if sas, _ := ike.ListSAs(ctx, "unrelated"); len(sas) != 1 {
		t.Fatal("FenceClient touched another connection's SA")
	}

	if n, err := g.FenceClient(ctx, "nobody"); n != 0 || err != nil {
		t.Fatalf("FenceClient of an absent client = %d, %v", n, err)
	}
	if _, err := g.FenceClient(ctx, "bad id"); err == nil {
		t.Fatal("FenceClient accepted an invalid identity")
	}
	ike.addSA(IKESA{Name: resp, State: IKEStateEstablished, RemoteID: "client-3"})
	ike.setErr("terminate", errors.New("busy"))
	if n, err := g.FenceClient(ctx, "client-3"); n != 0 || err == nil {
		t.Fatalf("FenceClient with a failing terminate = %d, %v", n, err)
	}
	ike.setErr("terminate", nil)
	ike.setErr("list", errors.New("down"))
	if _, err := g.FenceClient(ctx, "client-3"); err == nil {
		t.Fatal("FenceClient hid a query error")
	}

	unstarted, _, _ := newTestGateway(t, nil)
	if _, err := unstarted.FenceClient(ctx, "client-1"); err == nil {
		t.Fatal("FenceClient before Start succeeded")
	}
}

func TestGateway_AddBackbone(t *testing.T) {
	g, ike, n := startedGateway(t, nil)
	ctx := context.Background()

	// gw-b-bb < gw-c: this gateway initiates.
	if err := g.AddBackbone(ctx, testBackbone("gw-c", 11, "203.0.113.3")); err != nil {
		t.Fatalf("AddBackbone gw-c: %v", err)
	}
	// gw-a < gw-b-bb: the peer initiates, this gateway only responds.
	if err := g.AddBackbone(ctx, testBackbone("gw-a", 12, "203.0.113.1")); err != nil {
		t.Fatalf("AddBackbone gw-a: %v", err)
	}
	c := ike.conns["egressa-bb-gw-c"]
	if c.Start != StartStart || c.RemoteID != "gw-c" || c.PSK != testGatewayBackbonePSK || c.IfID != 11 ||
		!slices.Equal(c.LocalTS, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}) {
		t.Fatalf("backbone to gw-c = %+v, want start_action=start with the backbone PSK", c)
	}
	if a := ike.conns["egressa-bb-gw-a"]; a.Start != StartNone {
		t.Fatalf("backbone to gw-a start = %q, want none (the smaller identity initiates)", a.Start)
	}
	sec := ike.secrets["egressa-bb-gw-c"]
	if sec.PSK != testGatewayBackbonePSK || !slices.Equal(sec.Owners, []string{"gw-b-bb", "gw-c"}) {
		t.Fatalf("backbone secret = %+v, want the backbone PSK owned by both backbone identities", sec)
	}
	if c.LocalID != "gw-b-bb" {
		t.Fatalf("backbone local identity = %q, want the backbone identity gw-b-bb", c.LocalID)
	}
	if l, ok := n.link("egw11"); !ok || l.ifID != 11 || !l.up {
		t.Fatalf("backbone interface = %+v (exists %v)", l, ok)
	}

	for name, p := range map[string]BackbonePeer{
		"same id":         testBackbone("gw-c", 13, "203.0.113.4"),
		"same if_id":      testBackbone("gw-d", 11, "203.0.113.4"),
		"client if_id":    testBackbone("gw-d", 9, "203.0.113.4"),
		"itself":          testBackbone("gw-b-bb", 13, "203.0.113.4"),
		"itself (client)": testBackbone("gw-b", 13, "203.0.113.4"),
		"zoned":           {ID: "gw-d", Addr: netip.MustParseAddr("fe80::1%eth0"), IfID: 13},
		"other family":    {ID: "gw-d", Addr: netip.MustParseAddr("2001:db8::4"), IfID: 13},
		"ts family":       {ID: "gw-d", Addr: netip.MustParseAddr("203.0.113.4"), IfID: 13, RemoteTS: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}},
		"bad identity":    {ID: "gw d", Addr: netip.MustParseAddr("203.0.113.4"), IfID: 13},
		"zero if_id":      {ID: "gw-d", Addr: netip.MustParseAddr("203.0.113.4")},
		"missing address": {ID: "gw-d", IfID: 13},
	} {
		if err := g.AddBackbone(ctx, p); err == nil {
			t.Errorf("%s: AddBackbone accepted it", name)
		}
	}
	if err := g.AddBackbone(ctx, testBackbone("gw-c", 13, "203.0.113.4")); !errors.Is(err, ErrExist) {
		t.Errorf("duplicate peer = %v, want ErrExist", err)
	}

	custom := testBackbone("gw-e", 14, "203.0.113.5")
	custom.LocalTS = []netip.Prefix{netip.MustParsePrefix("10.201.0.0/24")}
	custom.RemoteTS = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	if err := g.AddBackbone(ctx, custom); err != nil {
		t.Fatalf("AddBackbone with explicit selectors: %v", err)
	}
	if got := ike.conns["egressa-bb-gw-e"]; !slices.Equal(got.RemoteTS, custom.RemoteTS) || !slices.Equal(got.LocalTS, custom.LocalTS) {
		t.Fatalf("explicit selectors not used: %+v", got)
	}

	unstarted, _, _ := newTestGateway(t, nil)
	if err := unstarted.AddBackbone(ctx, testBackbone("gw-c", 11, "203.0.113.3")); err == nil {
		t.Fatal("AddBackbone before Start succeeded")
	}
}

func TestGateway_AddBackboneRollsBack(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*fakeIKE, *fakeNet)
	}{
		{"interface", func(_ *fakeIKE, n *fakeNet) { n.setErr("add-xfrm egw11", errors.New("boom")) }},
		{"link up", func(_ *fakeIKE, n *fakeNet) { n.setErr("link-up egw11", errors.New("boom")) }},
		{"secret", func(ike *fakeIKE, _ *fakeNet) { ike.setErr("load-shared egressa-bb-gw-c", errors.New("boom")) }},
		{"connection", func(ike *fakeIKE, _ *fakeNet) { ike.setErr("load-conn egressa-bb-gw-c", errors.New("boom")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, ike, n := startedGateway(t, nil)
			tc.setup(ike, n)
			if err := g.AddBackbone(context.Background(), testBackbone("gw-c", 11, "203.0.113.3")); err == nil {
				t.Fatal("AddBackbone succeeded despite the injected failure")
			}
			if _, ok := n.link("egw11"); ok {
				t.Fatal("rollback left the backbone interface")
			}
			if _, ok := ike.conns["egressa-bb-gw-c"]; ok {
				t.Fatal("rollback left the backbone connection")
			}
			if _, ok := ike.secrets["egressa-bb-gw-c"]; ok {
				t.Fatal("rollback left the backbone secret")
			}
		})
	}

	// Cancelled after loading: the initiation start_action=start began is
	// terminated on a live context.
	g, ike, _ := startedGateway(t, nil)
	ike.honorCtx = true
	ctx, cancel := context.WithCancel(context.Background())
	cancelAfterLoad := &cancelOnLoad{fakeIKE: ike, cancel: cancel, conn: "egressa-bb-gw-c"}
	g.ike = cancelAfterLoad
	err := g.AddBackbone(ctx, testBackbone("gw-c", 11, "203.0.113.3"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("AddBackbone cancelled after loading = %v", err)
	}
	if !slices.Contains(ike.calls(), "terminate-ike egressa-bb-gw-c") {
		t.Fatalf("rollback did not terminate the backbone IKE_SA: %v", ike.calls())
	}
	if _, ok := ike.conns["egressa-bb-gw-c"]; ok {
		t.Fatal("rollback after cancellation left the connection loaded")
	}

	g2, ike2, n2 := startedGateway(t, nil)
	ike2.setErr("load-conn egressa-bb-gw-c", errors.New("boom"))
	n2.setErr("delete-link egw11", errors.New("busy"))
	if err := g2.AddBackbone(context.Background(), testBackbone("gw-c", 11, "203.0.113.3")); err == nil ||
		!strings.Contains(err.Error(), "rollback incomplete") {
		t.Fatalf("AddBackbone with a failing rollback = %v", err)
	}
}

// cancelOnLoad cancels the caller's context right after a given
// connection is loaded, the moment start_action=start begins initiating.
type cancelOnLoad struct {
	*fakeIKE
	cancel func()
	conn   string
}

func (c *cancelOnLoad) LoadConn(ctx context.Context, conn Connection) error {
	err := c.fakeIKE.LoadConn(ctx, conn)
	if conn.Name == c.conn {
		c.cancel()
	}
	return err
}

func TestGateway_CloseDuringAddBackbone(t *testing.T) {
	g, ike, n := startedGateway(t, nil)
	block := &blockOnLoad{fakeIKE: ike, entered: make(chan struct{}), release: make(chan struct{})}
	g.ike = block
	done := make(chan error, 1)
	go func() { done <- g.AddBackbone(context.Background(), testBackbone("gw-c", 11, "203.0.113.3")) }()
	<-block.entered
	if err := g.AddBackbone(context.Background(), testBackbone("gw-c", 12, "203.0.113.3")); !errors.Is(err, ErrExist) {
		t.Fatalf("AddBackbone while the same peer is being added = %v", err)
	}
	if err := g.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	close(block.release)
	if err := <-done; !errors.Is(err, errGatewayClosed) {
		t.Fatalf("AddBackbone finishing after Close = %v", err)
	}
	if _, ok := n.link("egw11"); ok {
		t.Fatal("the interrupted AddBackbone was not rolled back")
	}
}

type blockOnLoad struct {
	*fakeIKE
	entered, release chan struct{}
}

func (b *blockOnLoad) LoadShared(ctx context.Context, s SharedSecret) error {
	if strings.HasPrefix(s.ID, "egressa-bb-") {
		close(b.entered)
		<-b.release
	}
	return b.fakeIKE.LoadShared(ctx, s)
}

func TestGateway_WaitAndFenceBackbone(t *testing.T) {
	g, ike, _ := startedGateway(t, func(c *GatewayConfig) { c.PollInterval = time.Hour })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := g.WaitBackbone(ctx, "gw-c"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("WaitBackbone of an unknown peer = %v", err)
	}
	if err := g.FenceBackboneBelow(ctx, "gw-c", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("FenceBackboneBelow of an unknown peer = %v", err)
	}
	if err := g.AddBackbone(ctx, testBackbone("gw-c", 11, "203.0.113.3")); err != nil {
		t.Fatalf("AddBackbone: %v", err)
	}
	go func() {
		waitForCond(func() bool { return ike.subscribers() == 1 })
		// charon's start_action=start would do this on load.
		_ = ike.Initiate(ctx, "egressa-bb-gw-c", "egressa-bb-gw-c-e1")
	}()
	if sa, err := g.WaitBackbone(ctx, "gw-c"); err != nil || !sa.Warm() {
		t.Fatalf("WaitBackbone = %+v, %v", sa, err)
	}
	if err := g.FenceBackboneBelow(ctx, "gw-c", 2); err != nil {
		t.Fatalf("FenceBackboneBelow: %v", err)
	}
	if warm, _ := IsWarm(ctx, ike, "egressa-bb-gw-c"); warm {
		t.Fatal("the epoch-1 backbone child survived FenceBackboneBelow(2)")
	}
}

func TestGateway_Uplink(t *testing.T) {
	g, _, n := startedGateway(t, func(c *GatewayConfig) { c.Table = 200 })
	ctx := context.Background()
	for _, p := range []BackbonePeer{testBackbone("gw-c", 11, "203.0.113.3"), testBackbone("gw-d", 12, "203.0.113.4")} {
		if err := g.AddBackbone(ctx, p); err != nil {
			t.Fatalf("AddBackbone %s: %v", p.ID, err)
		}
	}
	all := netip.MustParsePrefix("0.0.0.0/0")
	if err := g.Uplink(ctx, "gw-c", all, all); err != nil {
		t.Fatalf("Uplink: %v", err)
	}
	if r, ok := n.route(200, "0.0.0.0/0"); !ok || r.Dev != "egw11" {
		t.Fatalf("uplink default = %+v (present %v), want via egw11 in table 200", r, ok)
	}
	if _, ok := n.route(0, "0.0.0.0/0"); ok {
		t.Fatal("Uplink touched the main table")
	}
	if err := g.RemoveBackbone(ctx, "gw-c"); err == nil || !strings.Contains(err.Error(), "carries the uplink") {
		t.Fatalf("RemoveBackbone of the uplink peer = %v", err)
	}
	if err := g.Uplink(ctx, "gw-d", all); err != nil {
		t.Fatalf("move Uplink: %v", err)
	}
	if r, _ := n.route(200, "0.0.0.0/0"); r.Dev != "egw12" {
		t.Fatalf("uplink now via %s, want egw12", r.Dev)
	}
	if got := g.UplinkRoutes(); len(got) != 1 || got[0].Dev != "egw12" {
		t.Fatalf("UplinkRoutes = %+v", got)
	}
	if err := g.RemoveBackbone(ctx, "gw-c"); err != nil {
		t.Fatalf("RemoveBackbone after moving the uplink away: %v", err)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	n.setErr("route-replace 10.0.0.0/8", errors.New("boom"))
	for name, err := range map[string]error{
		"no prefixes":   g.Uplink(ctx, "gw-d"),
		"other family":  g.Uplink(ctx, "gw-d", netip.MustParsePrefix("2001:db8::/32")),
		"unknown peer":  g.Uplink(ctx, "gw-x", all),
		"cancelled ctx": g.Uplink(cancelled, "gw-d", all),
		"replace fails": g.Uplink(ctx, "gw-d", netip.MustParsePrefix("10.0.0.0/8")),
	} {
		if err == nil {
			t.Errorf("%s: Uplink accepted it", name)
		}
	}
}

func TestGateway_UplinkRefusesDefaultInMainTable(t *testing.T) {
	g, _, _ := startedGateway(t, nil)
	ctx := context.Background()
	if err := g.AddBackbone(ctx, testBackbone("gw-c", 11, "203.0.113.3")); err != nil {
		t.Fatalf("AddBackbone: %v", err)
	}
	if err := g.Uplink(ctx, "gw-c", netip.MustParsePrefix("0.0.0.0/0")); err == nil {
		t.Fatal("Uplink of 0.0.0.0/0 into the main table succeeded")
	}
	if err := g.Uplink(ctx, "gw-c", netip.MustParsePrefix("198.51.100.0/24")); err != nil {
		t.Fatalf("Uplink of a specific prefix in the main table: %v", err)
	}
}

func TestGateway_RemoveBackbone(t *testing.T) {
	g, ike, n := startedGateway(t, nil)
	ctx := context.Background()
	if err := g.RemoveBackbone(ctx, "gw-c"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RemoveBackbone of an unknown peer = %v", err)
	}
	if err := g.AddBackbone(ctx, testBackbone("gw-c", 11, "203.0.113.3")); err != nil {
		t.Fatalf("AddBackbone: %v", err)
	}
	n.setErr("delete-link egw11", errors.New("busy"))
	if err := g.RemoveBackbone(ctx, "gw-c"); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("RemoveBackbone with a failing step = %v", err)
	}
	if _, ok := ike.conns["egressa-bb-gw-c"]; ok {
		t.Fatal("RemoveBackbone left the connection")
	}
	// The if_id is free again.
	n.setErr("delete-link egw11", nil)
	n.mu.Lock()
	delete(n.links, "egw11")
	n.mu.Unlock()
	if err := g.AddBackbone(ctx, testBackbone("gw-c", 11, "203.0.113.3")); err != nil {
		t.Fatalf("re-AddBackbone: %v", err)
	}
	if err := g.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := g.RemoveBackbone(ctx, "gw-c"); !errors.Is(err, errGatewayClosed) {
		t.Fatalf("RemoveBackbone after Close = %v", err)
	}
	if _, err := g.WaitBackbone(ctx, "gw-c"); !errors.Is(err, errGatewayClosed) {
		t.Fatalf("WaitBackbone after Close = %v", err)
	}
}

func TestGateway_Close(t *testing.T) {
	g, ike, n := startedGateway(t, func(c *GatewayConfig) { c.Table = 200 })
	ctx := context.Background()
	if err := g.AddBackbone(ctx, testBackbone("gw-c", 11, "203.0.113.3")); err != nil {
		t.Fatalf("AddBackbone: %v", err)
	}
	if err := g.Uplink(ctx, "gw-c", netip.MustParsePrefix("0.0.0.0/0")); err != nil {
		t.Fatalf("Uplink: %v", err)
	}
	ike.addSA(IKESA{Name: g.ResponderName(), State: IKEStateEstablished, RemoteID: "client-1"})
	if err := g.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertClean(t, ike, n)
	if len(n.rules) != 0 {
		t.Fatalf("Close left rules: %v", n.rules)
	}
	if err := g.Close(ctx); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	if err := g.Start(ctx); !errors.Is(err, errGatewayClosed) {
		t.Fatalf("Start after Close = %v", err)
	}
	if _, err := g.Clients(ctx); !errors.Is(err, errGatewayClosed) {
		t.Fatalf("Clients after Close = %v", err)
	}
	if err := g.AddBackbone(ctx, testBackbone("gw-d", 12, "203.0.113.4")); !errors.Is(err, errGatewayClosed) {
		t.Fatalf("AddBackbone after Close = %v", err)
	}

	// Close of a gateway that was never started touches nothing.
	never, ike2, n2 := newTestGateway(t, nil)
	if err := never.Close(ctx); err != nil {
		t.Fatalf("Close before Start: %v", err)
	}
	if len(ike2.calls())+len(n2.log) != 0 {
		t.Fatalf("Close before Start did something: %v %v", ike2.calls(), n2.log)
	}

	// Errors are reported.
	g3, ike3, _ := startedGateway(t, nil)
	ike3.setErr("unload-conn", errors.New("daemon gone"))
	if err := g3.Close(ctx); err == nil || !strings.Contains(err.Error(), "daemon gone") {
		t.Fatalf("Close with a failing step = %v", err)
	}
}

func TestGateway_BackboneIDDefaultsAndOverrides(t *testing.T) {
	g, _, _ := newTestGateway(t, nil)
	if g.cfg.BackboneID != "gw-b-bb" {
		t.Fatalf("default BackboneID = %q, want gw-b-bb", g.cfg.BackboneID)
	}
	g2, ike, _ := startedGateway(t, func(c *GatewayConfig) { c.BackboneID = "core.gw-b" })
	ctx := context.Background()
	// An identity that cannot be part of a connection name needs a Name.
	if err := g2.AddBackbone(ctx, testBackbone("core.gw-a", 11, "203.0.113.3")); err == nil {
		t.Fatal("AddBackbone derived an invalid connection name from the identity")
	}
	p := testBackbone("core.gw-a", 11, "203.0.113.3")
	p.Name = "core-a"
	if err := g2.AddBackbone(ctx, p); err != nil {
		t.Fatalf("AddBackbone: %v", err)
	}
	if c := ike.conns["egressa-bb-core-a"]; c.LocalID != "core.gw-b" || c.RemoteID != "core.gw-a" || c.Start != StartNone {
		t.Fatalf("backbone = %+v, want local identity core.gw-b responding to the smaller core.gw-a", c)
	}
	// One identity, one backbone: a second name for it is refused.
	dup := testBackbone("core.gw-a", 12, "203.0.113.3")
	dup.Name = "core-a2"
	if err := g2.AddBackbone(ctx, dup); !errors.Is(err, ErrExist) {
		t.Fatalf("second backbone to the same identity = %v, want ErrExist", err)
	}
	if _, err := g2.WaitBackbone(ctx, "core.gw-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("backbone methods take the Name, not the identity: %v", err)
	}
}
