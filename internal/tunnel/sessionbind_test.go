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
