package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// TestSendPacket_TCPEcho sends a TCP payload from client to gateway
// through the tunnel and back, with no persistent_keepalive_interval set.
// This proves two things at once: that a data packet alone triggers the
// Noise handshake (there is no separate handshake step here, unlike
// TestHandshake), and that the payload survives an encrypt/decrypt round
// trip intact.
func TestSendPacket_TCPEcho(t *testing.T) {
	client, gateway, _, gatewayAddr, clientKP, gatewayKP := testPeerPair(t, 0)

	ln, err := gateway.Net().ListenTCP(&net.TCPAddr{Port: 7000})
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer func() { _ = ln.Close() }()

	const message = "hello through the tunnel"
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- fmt.Errorf("Accept: %w", err)
			return
		}
		defer func() { _ = conn.Close() }()

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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := client.Net().DialContext(ctx, "tcp", fmt.Sprintf("%s:7000", gatewayAddr))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
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

	// Cross-check that traffic really went through WireGuard's encrypted
	// transport layer, not some accidental shortcut that bypassed it.
	// A correct echo alone would not catch that class of bug.
	clientTx, clientRx, err := client.PeerStats(gatewayKP.Public)
	if err != nil {
		t.Fatalf("client.PeerStats: %v", err)
	}
	if clientTx == 0 || clientRx == 0 {
		t.Errorf("client peer stats show no encrypted traffic: tx=%d rx=%d", clientTx, clientRx)
	}

	gatewayTx, gatewayRx, err := gateway.PeerStats(clientKP.Public)
	if err != nil {
		t.Fatalf("gateway.PeerStats: %v", err)
	}
	if gatewayTx == 0 || gatewayRx == 0 {
		t.Errorf("gateway peer stats show no encrypted traffic: tx=%d rx=%d", gatewayTx, gatewayRx)
	}
}
