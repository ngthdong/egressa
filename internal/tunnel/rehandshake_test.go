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

// TestVirtualIP_StableAcrossRehandshake proves that when the client's
// WireGuard session with a peer is fully torn down and rebuilt (not a
// routine key rotation, but the peer state itself removed and re-added),
// the client keeps running on the same netstack instance with the same
// virtual IP, and an existing TCP connection survives, resuming once a
// fresh handshake completes underneath it.
func TestVirtualIP_StableAcrossRehandshake(t *testing.T) {
	client, gateway, _, gatewayAddr, _, gatewayKP := testPeerPair(t, 0)

	ln, err := gateway.Net().ListenTCP(&net.TCPAddr{Port: 7003})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer func() { _ = ln.Close() }()

	echo := func(conn net.Conn) {
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 64)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go echo(c)
		}
	}()

	dial := func() net.Conn {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := client.Net().DialContext(ctx, "tcp", fmt.Sprintf("%s:7003", gatewayAddr))
		if err != nil {
			t.Fatalf("DialContext: %v", err)
		}
		return conn
	}

	roundTrip := func(conn net.Conn, msg string) string {
		t.Helper()
		if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
			t.Fatalf("SetDeadline: %v", err)
		}
		if _, err := conn.Write([]byte(msg)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("ReadFull: %v", err)
		}
		return string(got)
	}

	// Baseline: a connection opened before the reset works normally.
	conn := dial()
	defer func() { _ = conn.Close() }()
	if got := roundTrip(conn, "before reset"); got != "before reset" {
		t.Fatalf("baseline echo mismatch: got %q", got)
	}

	firstHandshake, err := client.LastHandshake(gatewayKP.Public)
	if err != nil {
		t.Fatalf("LastHandshake (before): %v", err)
	}
	if firstHandshake.IsZero() {
		t.Fatal("expected a completed handshake before the reset")
	}

	if err := client.RemovePeer(gatewayKP.Public); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	if ts, err := client.LastHandshake(gatewayKP.Public); err != nil {
		t.Fatalf("LastHandshake (after remove): %v", err)
	} else if !ts.IsZero() {
		t.Fatal("expected LastHandshake to reset to zero after RemovePeer")
	}

	gatewayPort, err := gateway.ListenPort()
	if err != nil {
		t.Fatalf("gateway.ListenPort: %v", err)
	}
	err = client.AddPeer(gatewayKP.Public,
		[]netip.Prefix{netip.PrefixFrom(gatewayAddr, 32)},
		fmt.Sprintf("127.0.0.1:%d", gatewayPort), 0)
	if err != nil {
		t.Fatalf("client.AddPeer (re-add): %v", err)
	}

	// The existing connection has no idea any of this happened. Writing
	// on it should trigger a fresh handshake underneath, lazily, the same
	// way any other outbound data does (see TestSendPacket_TCPEcho); once
	// that completes, the write should get through and echo back.
	if got := roundTrip(conn, "after reset"); got != "after reset" {
		t.Fatalf("post-reset echo on the SAME connection mismatch: got %q", got)
	}

	// A brand new connection, opened after the reset, must also reach the
	// gateway. It is dialed from the exact same client.Net() instance, so
	// this is only possible if the client's virtual IP never moved.
	conn2 := dial()
	defer func() { _ = conn2.Close() }()
	if got := roundTrip(conn2, "new conn, same IP"); got != "new conn, same IP" {
		t.Fatalf("new-connection echo mismatch: got %q", got)
	}

	secondHandshake, err := client.LastHandshake(gatewayKP.Public)
	if err != nil {
		t.Fatalf("LastHandshake (after): %v", err)
	}
	if secondHandshake.IsZero() {
		t.Fatal("expected a completed handshake after the reset")
	}
	if !secondHandshake.After(firstHandshake) {
		t.Errorf("second handshake (%v) is not after the first (%v)", secondHandshake, firstHandshake)
	}
}
