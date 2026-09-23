package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"testing"
	"time"
)

// realInternetTarget is a well-known, stable public IP dialed on 443.
// The test only requires the TCP three-way handshake to complete: that
// alone proves a full round trip through client -> gateway TUN -> kernel
// routing -> NAT -> the real internet -> NAT (reverse) -> gateway TUN ->
// client. It deliberately does not depend on any particular
// application-layer response, which would make the test fragile to a
// specific service's behavior rather than to the tunnel/NAT path this
// stage is actually about.
const realInternetTarget = "1.1.1.1:443"

// TestGateway_RealInternetRoundTrip is the end-to-end:
// a netstack-backed client, tunneling through a gateway with a real
// OS-level TUN interface, real kernel IP forwarding, and a real NAT
// (MASQUERADE) rule, reaching a genuine external Internet address and
// back.
func TestGateway_RealInternetRoundTrip(t *testing.T) {
	const (
		vpnSubnetCIDR = "10.201.0.0/24"
		gatewayAddr   = "10.201.0.1"
		clientAddrStr = "10.201.0.2"
		ifaceName     = "egressa-t4d"
	)

	vpnSubnet := netip.MustParsePrefix(vpnSubnetCIDR)
	gwAddr := netip.MustParseAddr(gatewayAddr)
	clientAddr := netip.MustParseAddr(clientAddrStr)

	clientKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (client): %v", err)
	}
	gatewayKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (gateway): %v", err)
	}

	// Gateway: real TUN, real routing, real NAT
	gw, err := NewReal(RealConfig{
		PrivateKey:    gatewayKP.Private,
		InterfaceName: ifaceName,
	})
	if err != nil {
		skipIfNoTUNPermission(t, err)
		t.Fatalf("NewReal (gateway): %v", err)
	}
	t.Cleanup(gw.Close)

	if err := ConfigureInterface(gw.Name(), netip.PrefixFrom(gwAddr, 24)); err != nil {
		skipIfPrivilegedCommandFailed(t, "ip", err)
		t.Fatalf("ConfigureInterface: %v", err)
	}

	originalForwarding, err := IPForwardingEnabled()
	if err != nil {
		t.Fatalf("IPForwardingEnabled: %v", err)
	}
	t.Cleanup(func() {
		val := []byte("0\n")
		if originalForwarding {
			val = []byte("1\n")
		}
		_ = os.WriteFile(ipForwardPath, val, 0644)
	})
	if err := EnableIPForwarding(); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("skipping: %v (needs root)", err)
		}
		t.Fatalf("EnableIPForwarding: %v", err)
	}

	// net.ipv4.ip_forward alone only lets the kernel consider forwarding;
	// it does not override the FORWARD chain's own policy, which hosts
	// with Docker installed (this one included) commonly default to DROP
	// for container isolation. Without this, ip_forward+NAT alone produces
	// silent packet loss, not an error, on exactly this test's path.
	forwardRule := ForwardRule{Interface: gw.Name()}
	if err := AddForward(forwardRule); err != nil {
		skipIfPrivilegedCommandFailed(t, "iptables", err)
		t.Fatalf("AddForward: %v", err)
	}
	t.Cleanup(func() {
		_ = RemoveForward(forwardRule)
	})

	natRule := NATRule{Subnet: vpnSubnet}
	if err := AddNAT(natRule); err != nil {
		skipIfPrivilegedCommandFailed(t, "iptables", err)
		t.Fatalf("AddNAT: %v", err)
	}
	t.Cleanup(func() {
		_ = RemoveNAT(natRule)
	})

	gwPort, err := gw.ListenPort()
	if err != nil {
		t.Fatalf("gw.ListenPort: %v", err)
	}

	// Gateway's peer entry for the client stays narrow (client_addr/32):
	// this is also what wireguard-go's own AllowedIPs check validates
	// decrypted packets' source address against on receive, and what it
	// uses to look up "which peer" for return traffic addressed to the
	// client on send.
	err = gw.AddPeer(clientKP.Public,
		[]netip.Prefix{netip.PrefixFrom(clientAddr, 32)},
		"", 0)
	if err != nil {
		t.Fatalf("gw.AddPeer: %v", err)
	}

	//Client: userspace netstack, full-tunnel routing
	client, err := New(Config{
		PrivateKey: clientKP.Private,
		Addresses:  []netip.Addr{clientAddr},
	})
	if err != nil {
		t.Fatalf("New (client): %v", err)
	}
	t.Cleanup(client.Close)

	// 0.0.0.0/0: route everything through the gateway, the standard
	// WireGuard full-tunnel pattern.
	err = client.AddPeer(gatewayKP.Public,
		[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		fmt.Sprintf("127.0.0.1:%d", gwPort), 0)
	if err != nil {
		t.Fatalf("client.AddPeer: %v", err)
	}

	// The actual proof: dial a real Internet address through it
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := client.Net().DialContext(ctx, "tcp", realInternetTarget)
	if err != nil {
		t.Fatalf("DialContext(%s) through the tunnel failed: %v\n"+
			"this means either a bug in the gateway/NAT setup above, or "+
			"this environment has no real outbound internet access, "+
			"check that manually before assuming it is a code bug", realInternetTarget, err)
	}
	defer func() { _ = conn.Close() }()

	t.Logf("TCP handshake with %s completed through the tunnel (local=%s remote=%s)",
		realInternetTarget, conn.LocalAddr(), conn.RemoteAddr())

	tx, rx, err := client.PeerStats(gatewayKP.Public)
	if err != nil {
		t.Fatalf("client.PeerStats: %v", err)
	}
	if tx == 0 || rx == 0 {
		t.Errorf("expected nonzero encrypted traffic to/from the gateway: tx=%d rx=%d", tx, rx)
	}
}
