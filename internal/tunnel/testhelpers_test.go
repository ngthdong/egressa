package tunnel

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
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

func skipIfPrivilegedCommandFailed(t *testing.T, cmdName string, err error) {
	t.Helper()
	if errors.Is(err, exec.ErrNotFound) {
		t.Skipf("skipping: %s not installed: %v", cmdName, err)
	}
	msg := err.Error()
	if strings.Contains(msg, "Permission denied") ||
		strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "must be root") ||
		strings.Contains(msg, "Operation not permitted") {
		t.Skipf("skipping: insufficient privilege for %s: %v", cmdName, err)
	}
}

func enableForwardingWithCleanup(t *testing.T) {
	t.Helper()
	original, err := IPForwardingEnabled()
	if err != nil {
		t.Fatalf("IPForwardingEnabled: %v", err)
	}
	t.Cleanup(func() {
		val := []byte("0\n")
		if original {
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
}

func setupAccessGateway(
	t *testing.T,
	aKey [KeySize]byte, aIface string, aAddr netip.Addr,
	bKey [KeySize]byte, bIface string, bAddr netip.Addr,
) (roleA, roleB *AccessGateway) {
	t.Helper()

	devA, err := NewReal(RealConfig{PrivateKey: aKey, InterfaceName: aIface})
	if err != nil {
		skipIfNoTUNPermission(t, err)
		t.Fatalf("NewReal (access, client-facing): %v", err)
	}
	t.Cleanup(devA.Close)
	if err := ConfigureInterface(devA.Name(), netip.PrefixFrom(aAddr, 24)); err != nil {
		skipIfPrivilegedCommandFailed(t, "ip", err)
		t.Fatalf("ConfigureInterface (access, client-facing): %v", err)
	}

	devB, err := NewReal(RealConfig{PrivateKey: bKey, InterfaceName: bIface})
	if err != nil {
		t.Fatalf("NewReal (access, backbone-facing): %v", err)
	}
	t.Cleanup(devB.Close)
	if err := ConfigureInterface(devB.Name(), netip.PrefixFrom(bAddr, 24)); err != nil {
		t.Fatalf("ConfigureInterface (access, backbone-facing): %v", err)
	}

	enableForwardingWithCleanup(t)

	return NewAccessGateway(devA), NewAccessGateway(devB)
}
