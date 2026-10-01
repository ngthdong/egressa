//go:build linux

package ipsec

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
)

// TestNetlinkNet_RealKernel drives NetlinkNet against a real kernel, in a
// throwaway user+network namespace, so the adapter is checked against what
// the kernel actually accepts and reports, not only against a fake.
func TestNetlinkNet_RealKernel(t *testing.T) {
	if !runUnprivilegedNetNS(t) {
		return
	}
	n, err := NewNetlinkNet()
	if err != nil {
		t.Fatalf("NewNetlinkNet: %v", err)
	}
	defer n.Close()

	if err := n.AddXfrmInterface("egt7", 7, ""); err != nil {
		t.Skipf("skipping: kernel cannot create XFRM interfaces here: %v", err)
	}
	if err := n.AddXfrmInterface("egt7", 8, ""); !errors.Is(err, ErrExist) {
		t.Fatalf("duplicate AddXfrmInterface = %v, want ErrExist", err)
	}
	if err := n.AddAddr("egt7", netip.MustParsePrefix("10.205.0.2/32")); err != nil {
		t.Fatalf("AddAddr: %v", err)
	}
	if err := n.SetLinkUp("egt7"); err != nil {
		t.Fatalf("SetLinkUp: %v", err)
	}
	// A subnet address must keep its host part (192.0.2.1, not .0).
	if err := n.AddAddr("egt7", netip.MustParsePrefix("192.0.2.1/24")); err != nil {
		t.Fatalf("AddAddr subnet: %v", err)
	}
	if got, err := n.RouteGet(netip.MustParseAddr("192.0.2.9")); err != nil || got.Src != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("RouteGet on the subnet = %+v, %v; want src 192.0.2.1", got, err)
	}

	host := Route{Dst: netip.MustParsePrefix("203.0.113.0/24"), Dev: "egt7", Src: netip.MustParseAddr("10.205.0.2")}
	if err := n.RouteAdd(host); err != nil {
		t.Fatalf("RouteAdd: %v", err)
	}
	if err := n.RouteAdd(host); !errors.Is(err, ErrExist) {
		t.Fatalf("second RouteAdd = %v, want ErrExist (RouteAdd must never overwrite)", err)
	}
	got, err := n.RouteGet(netip.MustParseAddr("203.0.113.9"))
	if err != nil {
		t.Fatalf("RouteGet: %v", err)
	}
	if got.Dev != "egt7" || got.Src != netip.MustParseAddr("10.205.0.2") || got.Dst != netip.MustParsePrefix("203.0.113.9/32") {
		t.Fatalf("RouteGet = %+v, want dev egt7 src 10.205.0.2", got)
	}

	if _, err := n.DefaultRoute(FamilyV4); !errors.Is(err, ErrNotExist) {
		t.Fatalf("DefaultRoute in an empty namespace = %v, want ErrNotExist", err)
	}
	def := Route{Dst: netip.MustParsePrefix("0.0.0.0/0"), Dev: "egt7"}
	if err := n.RouteAdd(def); err != nil {
		t.Fatalf("RouteAdd default: %v", err)
	}
	if d, err := n.DefaultRoute(FamilyV4); err != nil || d.Dev != "egt7" {
		t.Fatalf("DefaultRoute = %+v, %v; want dev egt7", d, err)
	}

	half := Route{Dst: netip.MustParsePrefix("0.0.0.0/1"), Dev: "egt7", Table: 100}
	if err := n.RouteReplace(half); err != nil {
		t.Fatalf("RouteReplace in table 100: %v", err)
	}
	if err := n.RouteReplace(half); err != nil {
		t.Fatalf("RouteReplace is not idempotent: %v", err)
	}
	if err := n.RouteDel(half); err != nil {
		t.Fatalf("RouteDel: %v", err)
	}
	if err := n.RouteDel(half); !errors.Is(err, ErrNotExist) {
		t.Fatalf("RouteDel of a deleted route = %v, want ErrNotExist", err)
	}

	for _, r := range []Rule{
		{Src: netip.MustParsePrefix("10.205.0.2/32"), Table: 100, Priority: 1000},
		{Iif: "egt7", Table: 100, Priority: 1001},
	} {
		if err := n.RuleAdd(r); err != nil {
			t.Fatalf("RuleAdd(%+v): %v", r, err)
		}
		if err := n.RuleDel(r); err != nil {
			t.Fatalf("RuleDel(%+v): %v", r, err)
		}
		if err := n.RuleDel(r); !errors.Is(err, ErrNotExist) {
			t.Fatalf("RuleDel of a deleted rule = %v, want ErrNotExist", err)
		}
	}

	t.Run("XfrmStates", func(t *testing.T) {
		h, err := netlink.NewHandle()
		if err != nil {
			t.Fatalf("netlink handle: %v", err)
		}
		defer h.Close()
		st := &netlink.XfrmState{
			Src: net.ParseIP("192.0.2.2"), Dst: net.ParseIP("192.0.2.1"),
			Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TUNNEL,
			Spi: 0x1234, Reqid: 1, Ifid: 7, ReplayWindow: 32,
			Aead: &netlink.XfrmStateAlgo{
				Name:   "rfc4106(gcm(aes))",
				Key:    make([]byte, 36),
				ICVLen: 128,
			},
		}
		if err := h.XfrmStateAdd(st); err != nil {
			t.Skipf("skipping: kernel refused an ESP/AES-GCM state here (esp4 cannot be "+
				"auto-loaded from a user namespace; run as real root to cover this): %v", err)
		}
		states, err := n.XfrmStates()
		if err != nil {
			t.Fatalf("XfrmStates: %v", err)
		}
		if len(states) != 1 || states[0].SPI != 0x1234 || states[0].IfID != 7 || !states[0].HasReplay {
			t.Fatalf("XfrmStates = %+v, want one state SPI 0x1234 if_id 7 with replay data", states)
		}
	})

	if err := n.DeleteLink("egt7"); err != nil {
		t.Fatalf("DeleteLink: %v", err)
	}
	if err := n.DeleteLink("egt7"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("DeleteLink of a deleted link = %v, want ErrNotExist", err)
	}
}
