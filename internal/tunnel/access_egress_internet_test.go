package tunnel

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// TestFullThreeHopInternet verifies end-to-end Internet access through
// client -> access gateway -> egress gateway -> Internet.
//
// Egress NAT must match the client subnet because the access gateway
// forwards the original client source IP without NAT.
func TestFullThreeHopInternet(t *testing.T) {
	const (
		clientSubnetCIDR = "10.205.0.0/24"
		clientAddrStr    = "10.205.0.2"
		accessAAddrStr   = "10.205.0.1"

		accessBAddrStr = "10.206.0.1"
		egressBAddrStr = "10.206.0.2"

		accessAIface = "eg-5c-aa"
		accessBIface = "eg-5c-ab"
		egressBIface = "eg-5c-eb"
	)

	clientSubnet := netip.MustParsePrefix(clientSubnetCIDR)
	clientAddr := netip.MustParseAddr(clientAddrStr)
	accessAAddr := netip.MustParseAddr(accessAAddrStr)
	accessBAddr := netip.MustParseAddr(accessBAddrStr)
	egressBAddr := netip.MustParseAddr(egressBAddrStr)

	clientKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (client): %v", err)
	}
	accessAKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (access TUN-A): %v", err)
	}
	accessBKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (access TUN-B): %v", err)
	}
	egressBKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (egress TUN-B): %v", err)
	}

	accessRoleA, accessRoleB := setupAccessGateway(t,
		accessAKP.Private, accessAIface, accessAAddr,
		accessBKP.Private, accessBIface, accessBAddr,
	)

	// Egress: backbone TUN, plus forwarding + NAT out to the real Internet.
	egressB, err := NewReal(RealConfig{PrivateKey: egressBKP.Private, InterfaceName: egressBIface})
	if err != nil {
		t.Fatalf("NewReal (egress TUN-B): %v", err)
	}
	t.Cleanup(egressB.Close)
	if err := ConfigureInterface(egressB.Name(), netip.PrefixFrom(egressBAddr, 24)); err != nil {
		t.Fatalf("ConfigureInterface (egress TUN-B): %v", err)
	}

	enableForwardingWithCleanup(t)

	// net.ipv4.ip_forward alone only lets the kernel consider forwarding;
	// it does not override the FORWARD chain's own policy, which hosts
	// with Docker installed commonly default to DROP for container
	// isolation. Without this, ip_forward+NAT alone produces silent
	// packet loss, not an error, on egress's TUN-B -> real Internet hop
	// (see e2e_internet_test.go, which needs the same rule for the same
	// reason on its own single combined gateway).
	egressForwardRule := ForwardRule{Interface: egressB.Name()}
	if err := AddForward(egressForwardRule); err != nil {
		skipIfPrivilegedCommandFailed(t, "iptables", err)
		t.Fatalf("AddForward (egress): %v", err)
	}
	t.Cleanup(func() {
		_ = RemoveForward(egressForwardRule)
	})

	egressRole := NewEgressGateway(egressB)

	// The client subnet, not the backbone subnet: see the doc comment
	// above for why.
	if err := egressRole.ConfigureNAT(clientSubnet); err != nil {
		skipIfPrivilegedCommandFailed(t, "iptables", err)
		t.Fatalf("ConfigureNAT: %v", err)
	}
	t.Cleanup(func() {
		_ = egressRole.RemoveNATConfig(clientSubnet)
	})

	// Peers
	egressBPort, err := egressRole.ListenPort()
	if err != nil {
		t.Fatalf("egressB.ListenPort: %v", err)
	}
	err = accessRoleB.AddPeer(egressBKP.Public,
		[]netip.Prefix{netip.PrefixFrom(egressBAddr, 32)},
		fmt.Sprintf("127.0.0.1:%d", egressBPort), 0)
	if err != nil {
		t.Fatalf("accessB.AddPeer(egress): %v", err)
	}

	err = egressRole.AddPeer(accessBKP.Public,
		[]netip.Prefix{netip.PrefixFrom(clientAddr, 32)},
		"", 0)
	if err != nil {
		t.Fatalf("egressB.AddPeer(access): %v", err)
	}

	client, err := New(Config{
		PrivateKey: clientKP.Private,
		Addresses:  []netip.Addr{clientAddr},
	})
	if err != nil {
		t.Fatalf("New (client): %v", err)
	}
	t.Cleanup(client.Close)

	accessAPort, err := accessRoleA.ListenPort()
	if err != nil {
		t.Fatalf("accessA.ListenPort: %v", err)
	}
	err = client.AddPeer(accessAKP.Public,
		[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		fmt.Sprintf("127.0.0.1:%d", accessAPort), 0)
	if err != nil {
		t.Fatalf("client.AddPeer(access): %v", err)
	}

	err = accessRoleA.AddPeer(clientKP.Public,
		[]netip.Prefix{netip.PrefixFrom(clientAddr, 32)},
		"", 0)
	if err != nil {
		t.Fatalf("accessA.AddPeer(client): %v", err)
	}

	// The proof: dial a real Internet address through both hops.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	conn, err := client.Net().DialContext(ctx, "tcp", realInternetTarget)
	if err != nil {
		t.Fatalf("DialContext(%s) through access+egress failed: %v\n"+
			"this means either a bug in the 3-hop setup above, or this "+
			"environment has no real outbound internet access -- check "+
			"that manually before assuming it is a code bug", realInternetTarget, err)
	}
	defer func() { _ = conn.Close() }()

	t.Logf("TCP handshake with %s completed through access+egress (local=%s remote=%s)",
		realInternetTarget, conn.LocalAddr(), conn.RemoteAddr())

	tx, rx, err := client.PeerStats(accessAKP.Public)
	if err != nil {
		t.Fatalf("client.PeerStats: %v", err)
	}
	if tx == 0 || rx == 0 {
		t.Errorf("expected nonzero encrypted traffic client<->access: tx=%d rx=%d", tx, rx)
	}
}
