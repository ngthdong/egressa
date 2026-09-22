package tunnel

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestHandshake(t *testing.T) {
	clientAddr := netip.MustParseAddr("10.99.0.1")
	gatewayAddr := netip.MustParseAddr("10.99.0.2")

	clientKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (client): %v", err)
	}
	gatewayKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (gateway): %v", err)
	}

	client, err := New(Config{
		PrivateKey: clientKP.Private,
		Addresses:  []netip.Addr{clientAddr},
	})
	if err != nil {
		t.Fatalf("New (client): %v", err)
	}
	defer client.Close()

	gateway, err := New(Config{
		PrivateKey: gatewayKP.Private,
		Addresses:  []netip.Addr{gatewayAddr},
	})
	if err != nil {
		t.Fatalf("New (gateway): %v", err)
	}
	defer gateway.Close()

	clientPort, err := client.ListenPort()
	if err != nil {
		t.Fatalf("client.ListenPort: %v", err)
	}
	gatewayPort, err := gateway.ListenPort()
	if err != nil {
		t.Fatalf("gateway.ListenPort: %v", err)
	}
	if clientPort == 0 || gatewayPort == 0 {
		t.Fatalf("expected nonzero listen ports, got client=%d gateway=%d", clientPort, gatewayPort)
	}

	// persistent_keepalive_interval triggers a handshake on its own, with
	// no data packet needed. Sending actual packets through the tunnel is
	// a separate concern (see the next stage).
	const keepalive = time.Second

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

	// wireguard-go primes a freshly-added peer to send its handshake-init
	// immediately. That first attempt can be lost (e.g. it can beat the
	// other side's AddPeer, which is still configuring the responder), and
	// the library then waits device.RekeyTimeout (5s, plus jitter) before
	// retrying, so the wait budget here must clear one full retry cycle,
	// not just "long enough for a network round trip".
	const handshakeTimeout = 10 * time.Second
	waitForHandshake(t, client, gatewayKP.Public, handshakeTimeout)
	waitForHandshake(t, gateway, clientKP.Public, handshakeTimeout)
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
