package tunnel

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/ngthdong/egressa/pkg/wire"
)

// TestSessionHeader_RoundTrip proves the session-layer hook actually
// carries session_id and epoch through the wire, on the cleartext UDP
// datagram that carries WireGuard's own encrypted payload (see
// sessionbind.go for why it can't ride inside that encryption), by
// observing the decoded header on the receiving side.
func TestSessionHeader_RoundTrip(t *testing.T) {
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

	const wantSessionID = 0xC0FFEE
	const wantEpoch = 7

	received := make(chan wire.SessionHeader, 4)

	client, err := New(Config{
		PrivateKey: clientKP.Private,
		Addresses:  []netip.Addr{clientAddr},
		SessionID:  wantSessionID,
		Epoch:      wantEpoch,
	})
	if err != nil {
		t.Fatalf("New (client): %v", err)
	}
	t.Cleanup(client.Close)

	gateway, err := New(Config{
		PrivateKey: gatewayKP.Private,
		Addresses:  []netip.Addr{gatewayAddr},
		OnSessionPacket: func(h wire.SessionHeader) {
			received <- h
		},
	})
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

	err = client.AddPeer(gatewayKP.Public,
		[]netip.Prefix{netip.PrefixFrom(gatewayAddr, 32)},
		fmt.Sprintf("127.0.0.1:%d", gatewayPort), 0)
	if err != nil {
		t.Fatalf("client.AddPeer: %v", err)
	}
	err = gateway.AddPeer(clientKP.Public,
		[]netip.Prefix{netip.PrefixFrom(clientAddr, 32)},
		fmt.Sprintf("127.0.0.1:%d", clientPort), 0)
	if err != nil {
		t.Fatalf("gateway.AddPeer: %v", err)
	}

	ln, err := gateway.Net().ListenTCP(&net.TCPAddr{Port: 7001})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.Net().DialContext(ctx, "tcp", fmt.Sprintf("%s:7001", gatewayAddr))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer func() { _ = conn.Close() }()

	select {
	case h := <-received:
		if h.SessionID != wantSessionID {
			t.Errorf("SessionID = %d, want %d", h.SessionID, uint64(wantSessionID))
		}
		if h.Epoch != wantEpoch {
			t.Errorf("Epoch = %d, want %d", h.Epoch, uint32(wantEpoch))
		}
		if h.SessionSeq == 0 {
			t.Error("SessionSeq is 0, want nonzero")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a session packet at the gateway")
	}
}

// TestSessionBind_SetMark checks that sessionBind forwards SetMark to the
// wrapped conn.Bind rather than silently swallowing it, since it's the one
// conn.Bind method sessionBind doesn't otherwise touch.
func TestSessionBind_SetMark(t *testing.T) {
	b := newSessionBind(conn.NewDefaultBind(), 0, 0, nil)
	if err := b.SetMark(0); err != nil {
		t.Fatalf("SetMark: %v", err)
	}
}

// fakeBind is a minimal conn.Bind whose one ReceiveFunc yields whatever
// datagrams a test preloads into it, so sessionBind's receive-side framing
// can be unit tested without a real network round trip.
type fakeBind struct {
	recv func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error)
}

func (b fakeBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{b.recv}, port, nil
}
func (fakeBind) Close() error                       { return nil }
func (fakeBind) SetMark(uint32) error               { return nil }
func (fakeBind) Send([][]byte, conn.Endpoint) error { return nil }
func (fakeBind) ParseEndpoint(string) (conn.Endpoint, error) {
	return nil, nil
}
func (fakeBind) BatchSize() int { return 1 }

// TestSessionBind_WrapReceiveFunc_DropsShortDatagram checks that a
// datagram too short to have carried a session header is dropped rather
// than handed to wireguard-go, which would otherwise choke on it.
func TestSessionBind_WrapReceiveFunc_DropsShortDatagram(t *testing.T) {
	real := fakeBind{
		recv: func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			copy(packets[0], []byte{1, 2, 3})
			sizes[0] = 3
			return 1, nil
		},
	}
	b := newSessionBind(real, 0, 0, nil)

	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(fns) != 1 {
		t.Fatalf("Open returned %d ReceiveFuncs, want 1", len(fns))
	}

	packets := [][]byte{make([]byte, 100)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := fns[0](packets, sizes, eps)
	if err != nil {
		t.Fatalf("wrapped ReceiveFunc: %v", err)
	}
	if n != 0 {
		t.Errorf("n = %d, want 0 (short datagram should be dropped)", n)
	}
}
