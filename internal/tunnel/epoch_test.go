package tunnel

import (
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/ngthdong/egressa/pkg/wire"
)

// TestDevice_SetEpochAndAdmit checks the two migration hooks end to end:
// SetEpoch changes the epoch stamped on packets already flowing, and a
// gateway's Admit hook drops every packet it rejects, so a client still
// on an old epoch is fenced off entirely.
func TestDevice_SetEpochAndAdmit(t *testing.T) {
	clientAddr := netip.MustParseAddr("10.98.0.1")
	gatewayAddr := netip.MustParseAddr("10.98.0.2")
	clientKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	gatewayKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	var minEpoch atomic.Uint32
	var lastEpoch atomic.Uint32
	client, err := New(Config{PrivateKey: clientKP.Private, Addresses: []netip.Addr{clientAddr}, SessionID: 9, Epoch: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	gateway, err := New(Config{
		PrivateKey:      gatewayKP.Private,
		Addresses:       []netip.Addr{gatewayAddr},
		OnSessionPacket: func(h wire.SessionHeader) { lastEpoch.Store(h.Epoch) },
		Admit:           func(h wire.SessionHeader) bool { return h.Epoch >= minEpoch.Load() },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gateway.Close)

	gwPort, err := gateway.ListenPort()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AddPeer(gatewayKP.Public, []netip.Prefix{netip.PrefixFrom(gatewayAddr, 32)}, fmt.Sprintf("127.0.0.1:%d", gwPort), 0); err != nil {
		t.Fatal(err)
	}
	if err := gateway.AddPeer(clientKP.Public, []netip.Prefix{netip.PrefixFrom(clientAddr, 32)}, "", 0); err != nil {
		t.Fatal(err)
	}

	ln, err := gateway.Net().ListenUDP(&net.UDPAddr{Port: 7200})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := ln.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = ln.WriteTo(buf[:n], from)
		}
	}()

	c, err := client.Net().DialUDP(nil, &net.UDPAddr{IP: gatewayAddr.AsSlice(), Port: 7200})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	echo := func(timeout time.Duration) bool {
		deadline := time.Now().Add(timeout)
		buf := make([]byte, 64)
		for time.Now().Before(deadline) {
			if _, err := c.Write([]byte("ping")); err != nil {
				t.Fatal(err)
			}
			_ = c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if _, err := c.Read(buf); err == nil {
				return true
			}
		}
		return false
	}

	if !echo(5 * time.Second) {
		t.Fatal("no echo at epoch 1")
	}
	if got := lastEpoch.Load(); got != 1 {
		t.Fatalf("gateway saw epoch %d, want 1", got)
	}

	minEpoch.Store(2) // the session moved on; epoch 1 is now stale
	for i := 0; i < 5; i++ {
		_ = echo(0) // drain anything already in flight
	}
	if echo(time.Second) {
		t.Fatal("a stale-epoch client still got through the Admit hook")
	}

	client.SetEpoch(2)
	if !echo(5 * time.Second) {
		t.Fatal("no echo after SetEpoch(2)")
	}
	if got := lastEpoch.Load(); got != 2 {
		t.Fatalf("gateway saw epoch %d after SetEpoch(2), want 2", got)
	}
}

func TestSessionBind_AdmitDropsRejected(t *testing.T) {
	stale := wire.SessionHeader{Version: wire.Version, SessionID: 5, Epoch: 1}.Encode()
	fresh := wire.SessionHeader{Version: wire.Version, SessionID: 5, Epoch: 2}.Encode()
	real := fakeBind{recv: func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		sizes[0] = copy(packets[0], append(stale, 'a'))
		sizes[1] = copy(packets[1], append(fresh, 'b'))
		return 2, nil
	}}
	b := newSessionBind(real, 0, 0, nil)
	b.admit = func(h wire.SessionHeader) bool { return h.Epoch >= 2 }
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	packets := [][]byte{make([]byte, 64), make([]byte, 64)}
	sizes := make([]int, 2)
	eps := make([]conn.Endpoint, 2)
	n, err := fns[0](packets, sizes, eps)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || string(packets[0][:sizes[0]]) != "b" {
		t.Fatalf("got %d packets, first %q; want only the epoch-2 one", n, packets[0][:sizes[0]])
	}
}

func TestPublicKey_MatchesGenerated(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKey(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	if pub != kp.Public {
		t.Fatalf("PublicKey = %x, want %x", pub, kp.Public)
	}
}
