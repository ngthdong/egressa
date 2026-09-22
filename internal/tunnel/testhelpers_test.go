package tunnel

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// testPeerPair constructs two Devices, a "client" and a "gateway", peered
// with each other over loopback UDP. Both are closed automatically at the
// end of the test.
//
// If keepalive is positive, it is set on both peers, which triggers a
// handshake immediately with no data packet needed. Passing 0 leaves the
// handshake to be triggered lazily by the caller's first data packet.
func testPeerPair(t *testing.T, keepalive time.Duration) (client, gateway *Device, clientAddr, gatewayAddr netip.Addr, clientKP, gatewayKP KeyPair) {
	t.Helper()

	clientAddr = netip.MustParseAddr("10.99.0.1")
	gatewayAddr = netip.MustParseAddr("10.99.0.2")

	var err error
	clientKP, err = GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (client): %v", err)
	}
	gatewayKP, err = GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (gateway): %v", err)
	}

	client, err = New(Config{PrivateKey: clientKP.Private, Addresses: []netip.Addr{clientAddr}})
	if err != nil {
		t.Fatalf("New (client): %v", err)
	}
	t.Cleanup(client.Close)

	gateway, err = New(Config{PrivateKey: gatewayKP.Private, Addresses: []netip.Addr{gatewayAddr}})
	if err != nil {
		t.Fatalf("New (gateway): %v", err)
	}
	t.Cleanup(gateway.Close)

	clientPort, err := client.ListenPort()
	if err != nil {
		t.Fatalf("client.ListenPort: %v", err)
	}
	gatewayPort, err := gateway.ListenPort()
	if err != nil {
		t.Fatalf("gateway.ListenPort: %v", err)
	}

	err = client.AddPeer(
		gatewayKP.Public,
		[]netip.Prefix{netip.PrefixFrom(gatewayAddr, 32)},
		fmt.Sprintf("127.0.0.1:%d", gatewayPort),
		keepalive,
	)
	if err != nil {
		t.Fatalf("client.AddPeer: %v", err)
	}

	err = gateway.AddPeer(
		clientKP.Public,
		[]netip.Prefix{netip.PrefixFrom(clientAddr, 32)},
		fmt.Sprintf("127.0.0.1:%d", clientPort),
		keepalive,
	)
	if err != nil {
		t.Fatalf("gateway.AddPeer: %v", err)
	}

	return client, gateway, clientAddr, gatewayAddr, clientKP, gatewayKP
}

func waitForHandshake(t *testing.T, dev *Device, peerKey [KeySize]byte, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ts, err := dev.LastHandshake(peerKey)
		if err != nil {
			t.Fatalf("LastHandshake: %v", err)
		}
		if !ts.IsZero() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no handshake with peer %x within %s", peerKey, timeout)
}
