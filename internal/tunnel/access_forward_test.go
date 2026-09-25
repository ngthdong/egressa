package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

// TestAccessForwardsToBackbone verifies that an access gateway forwards
// client traffic over a separate backbone tunnel to an egress gateway
// without performing address translation.
//
// Topology:
//
//		Client (netstack, 10.203.0.2)
//		   |
//		   |  WireGuard tunnel 1 (client-facing)
//	       |
//		Access TUN-A (10.203.0.1) --- kernel forward (ip_forward=1) --- Access TUN-B (10.204.0.1)
//		   |                                                                |
//		   +---------------------------- one process -----------------------+
//																			|
//		                                                                    |  WireGuard tunnel 2 (backbone)
//																			|
//		                                                          	    Egress TUN-B (10.204.0.2)
//		                                                             		|
//		                                                          	    plain TCP listener, no NAT
//
// The egress terminates traffic locally. Internet forwarding and NAT are
// covered. The test verifies end-to-end forwarding across both tunnel
// hops while preserving the client's source address.
func TestAccessForwardsToBackbone(t *testing.T) {
	const (
		clientAddrStr  = "10.203.0.2"
		accessAAddrStr = "10.203.0.1" // access, client-facing side

		accessBAddrStr = "10.204.0.1" // access, egress-facing side
		egressBAddrStr = "10.204.0.2" // egress, backbone side

		accessAIface = "eg-acc-a"
		accessBIface = "eg-acc-b"
		egressBIface = "eg-egr-b"

		echoPort = 7100
	)

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

	// access is wrapped in both roles at once for this test: its TUN-A
	// side plays access, and nothing about TUN-B needs NAT either.
	// It forwards to a peer, not to the real Internet. Only a true
	// egress (below) ever NATs.
	accessRoleA, accessRoleB := setupAccessGateway(t,
		accessAKP.Private, accessAIface, accessAAddr,
		accessBKP.Private, accessBIface, accessBAddr,
	)

	// Egress, backbone side (TUN-B).
	egressB, err := NewReal(RealConfig{PrivateKey: egressBKP.Private, InterfaceName: egressBIface})
	if err != nil {
		t.Fatalf("NewReal (egress TUN-B): %v", err)
	}
	t.Cleanup(egressB.Close)
	if err := ConfigureInterface(egressB.Name(), netip.PrefixFrom(egressBAddr, 24)); err != nil {
		t.Fatalf("ConfigureInterface (egress TUN-B): %v", err)
	}
	egressRole := NewEgressGateway(egressB)
	_ = egressRole

	egressBPort, err := egressRole.ListenPort()
	if err != nil {
		t.Fatalf("egressB.ListenPort: %v", err)
	}

	// Access -> egress: allowed_ip is egress's own backbone address.
	// This is what lets access's outbound peer-routing find "egress"
	// when a forwarded packet's destination is egressBAddr.
	err = accessRoleB.AddPeer(egressBKP.Public,
		[]netip.Prefix{netip.PrefixFrom(egressBAddr, 32)},
		fmt.Sprintf("127.0.0.1:%d", egressBPort), 0)
	if err != nil {
		t.Fatalf("accessB.AddPeer(egress): %v", err)
	}

	// Egress routes the original client address through the backbone peer.
	// No endpoint is configured; the peer endpoint is learned from the
	// WireGuard handshake initiated by the access gateway.
	err = egressRole.AddPeer(accessBKP.Public,
		[]netip.Prefix{netip.PrefixFrom(clientAddr, 32)},
		"", 0)
	if err != nil {
		t.Fatalf("egressB.AddPeer(access): %v", err)
	}

	// Client (netstack).

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

	// The actual proof: echo server on egress's backbone address,
	// dialed by the client, forwarded through access with no NAT.
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: egressBAddr.AsSlice(), Port: echoPort})
	if err != nil {
		t.Fatalf("ListenTCP on egress: %v", err)
	}
	defer func() { _ = ln.Close() }()

	const message = "through access, no NAT"
	serverDone := make(chan error, 1)
	var observedRemote string
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- fmt.Errorf("Accept: %w", err)
			return
		}
		defer func() { _ = conn.Close() }()
		observedRemote = conn.RemoteAddr().String()

		buf := make([]byte, len(message))
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverDone <- fmt.Errorf("ReadFull: %w", err)
			return
		}
		if _, err := conn.Write(buf); err != nil {
			serverDone <- fmt.Errorf("Write: %w", err)
			return
		}
		serverDone <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := client.Net().DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", egressBAddr, echoPort))
	if err != nil {
		t.Fatalf("DialContext through access to egress: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte(message)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := make([]byte, len(message))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull (echo): %v", err)
	}
	if string(got) != message {
		t.Errorf("echo mismatch: got %q, want %q", got, message)
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("server goroutine: %v", err)
	}

	// The whole point: egress must have seen the client's virtual IP as
	// the source, not access's backbone address. If this shows
	// accessBAddr instead, access is incorrectly rewriting the source
	// address somewhere.
	t.Logf("egress observed remote address: %s", observedRemote)
	if remoteHost, _, splitErr := net.SplitHostPort(observedRemote); splitErr == nil {
		if remoteHost != clientAddrStr {
			t.Errorf("egress saw source %s, want the client's own virtual IP %s (access must not NAT)", remoteHost, clientAddrStr)
		}
	}
}
