package gateway

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/control"
)

const both = control.RoleAccess | control.RoleEgress

var (
	vip1 = netip.MustParseAddr("10.201.0.2")
	vip2 = netip.MustParseAddr("10.201.0.3")
	vip3 = netip.MustParseAddr("10.201.0.4")
)

func testState() api.GatewayState {
	return api.GatewayState{
		Gateways: []api.Gateway{
			{ID: "hk", Roles: both, Endpoint: "192.0.2.11:51820", PublicKey: "hk-key", NodeIP: netip.MustParseAddr("10.200.0.2"),
				BackbonePorts: map[string]uint16{"sg": 40001, "eu": 40002}},
			{ID: "sg", Roles: both, Endpoint: "192.0.2.12:51820", PublicKey: "sg-key", NodeIP: netip.MustParseAddr("10.200.0.3"),
				BackbonePorts: map[string]uint16{"hk": 40011}},
			{ID: "eu", Roles: control.RoleEgress, Endpoint: "192.0.2.13:51820", PublicKey: "eu-key", NodeIP: netip.MustParseAddr("10.200.0.4")},
		},
		Sessions: []api.Session{
			// Direct: in and out through hk.
			{ID: "1", PublicKey: "c1", VirtualIP: vip1, Access: "hk", Egress: "hk", Epoch: 3},
			// Detour: in through sg, out through hk.
			{ID: "2", PublicKey: "c2", VirtualIP: vip2, Access: "sg", Egress: "hk", Epoch: 5},
			// Out through an egress-only gateway.
			{ID: "3", PublicKey: "c3", VirtualIP: vip3, Access: "hk", Egress: "eu", Epoch: 1},
		},
	}
}

func TestMakePlan_AccessAndEgress(t *testing.T) {
	p := MakePlan("hk", both, testState())

	wantPeers := map[string]netip.Addr{"c1": vip1, "c2": vip2, "c3": vip3}
	if !reflect.DeepEqual(p.Peers, wantPeers) {
		t.Errorf("peers %v, want every client (any could switch to hk)", p.Peers)
	}
	// Forward over the backbone every session leaving elsewhere, whoever
	// its access is now.
	if want := map[netip.Addr]string{vip3: "eu"}; !reflect.DeepEqual(p.Forward, want) {
		t.Errorf("forward %v, want %v", p.Forward, want)
	}
	// Send back over the backbone what came in elsewhere.
	if want := map[netip.Addr]string{vip2: "sg"}; !reflect.DeepEqual(p.Return, want) {
		t.Errorf("return %v, want %v", p.Return, want)
	}
	if want := map[string]uint64{"1": 3, "2": 5, "3": 1}; !reflect.DeepEqual(p.Epochs, want) {
		t.Errorf("epochs %v", p.Epochs)
	}
	if got := p.BackboneIDs(); !reflect.DeepEqual(got, []string{"eu", "sg"}) {
		t.Errorf("backbones %v", got)
	}
	if b := p.Backbones["sg"]; b.Endpoint != "192.0.2.12:40011" || b.PublicKey != "sg-key" || b.NodeIP != netip.MustParseAddr("10.200.0.3") {
		t.Errorf("backbone to sg %+v", b)
	}
	if b := p.Backbones["eu"]; b.Endpoint != "" {
		t.Errorf("eu has reported no port for hk yet, but the endpoint is %q", b.Endpoint)
	}
}

func TestMakePlan_AccessOnlyForwardsEverythingNotItsOwn(t *testing.T) {
	p := MakePlan("sg", control.RoleAccess, testState())
	want := map[netip.Addr]string{vip1: "hk", vip2: "hk", vip3: "eu"}
	if !reflect.DeepEqual(p.Forward, want) {
		t.Errorf("forward %v, want %v", p.Forward, want)
	}
	if len(p.Return) != 0 {
		t.Errorf("an access-only gateway returned %v", p.Return)
	}
}

func TestMakePlan_EgressOnly(t *testing.T) {
	p := MakePlan("eu", control.RoleEgress, testState())
	if len(p.Peers) != 0 || len(p.Forward) != 0 {
		t.Errorf("an egress-only gateway got clients %v or forwarding %v", p.Peers, p.Forward)
	}
	if want := map[netip.Addr]string{vip3: "hk"}; !reflect.DeepEqual(p.Return, want) {
		t.Errorf("return %v, want %v", p.Return, want)
	}
}

func TestMakePlan_UnknownGatewaysAreSkipped(t *testing.T) {
	st := testState()
	st.Sessions = append(st.Sessions,
		api.Session{ID: "4", PublicKey: "c4", VirtualIP: netip.MustParseAddr("10.201.0.5"), Access: "gone", Egress: "hk"},
		api.Session{ID: "5", PublicKey: "c5", VirtualIP: netip.MustParseAddr("10.201.0.6"), Access: "hk", Egress: "gone"},
	)
	p := MakePlan("hk", both, st)
	if _, ok := p.Return[netip.MustParseAddr("10.201.0.5")]; ok {
		t.Error("return route through a gateway that is not registered")
	}
	if _, ok := p.Forward[netip.MustParseAddr("10.201.0.6")]; ok {
		t.Error("forwarding to a gateway that is not registered")
	}
}

func TestWithOp(t *testing.T) {
	r := natRule(netip.MustParsePrefix("10.201.0.0/16"), "eth0")
	got := withOp(r, "-C")
	want := []string{"-t", "nat", "-C", "POSTROUTING", "-s", "10.201.0.0/16", "-o", "eth0", "-j", "MASQUERADE"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
	if r[2] != "%s" {
		t.Error("withOp changed its input")
	}
	if got := ruleFrom(vip1, 1003); !reflect.DeepEqual(got, []string{"from", "10.201.0.2/32", "lookup", "1003", "pref", "1000"}) {
		t.Errorf("ruleFrom %v", got)
	}
}

func TestNew_Validates(t *testing.T) {
	ctl, _ := api.NewClient("http://127.0.0.1:1", "")
	ok := Config{ID: "hk", Controller: ctl, Endpoint: "192.0.2.1:51820", Roles: both, Uplink: "eth0"}
	if _, err := New(ok); err != nil {
		t.Fatalf("New: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"no id":             func(c *Config) { c.ID = "" },
		"bad ep":            func(c *Config) { c.Endpoint = "nope" },
		"egress, no uplink": func(c *Config) { c.Uplink = "" },
	} {
		c := ok
		mutate(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	accessOnly := ok
	accessOnly.Roles, accessOnly.Uplink = control.RoleAccess, ""
	if _, err := New(accessOnly); err != nil {
		t.Errorf("an access-only gateway needs no uplink: %v", err)
	}
}
