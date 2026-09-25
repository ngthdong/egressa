package tunnel

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestAddPeer_RemovePeer_ClosedDevice(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dev, err := New(Config{PrivateKey: kp.Private, Addresses: []netip.Addr{testAddr(t)}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	dev.Close()

	peerKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (peer): %v", err)
	}

	if err := dev.AddPeer(peerKP.Public, nil, "", 0); err == nil {
		t.Error("AddPeer on a closed device: expected error, got nil")
	}
	if err := dev.RemovePeer(peerKP.Public); err == nil {
		t.Error("RemovePeer on a closed device: expected error, got nil")
	}
}

func TestAddPeer_KeepaliveRoundsUpNotDownToZero(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dev, err := New(Config{PrivateKey: kp.Private, Addresses: []netip.Addr{testAddr(t)}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer dev.Close()

	peerKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (peer): %v", err)
	}

	if err := dev.AddPeer(peerKP.Public, nil, "", 200*time.Millisecond); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	cfg, err := dev.uapiConfig()
	if err != nil {
		t.Fatalf("uapiConfig: %v", err)
	}
	block := peerConfigBlock(t, cfg, Hex(peerKP.Public))
	if strings.Contains(block, "persistent_keepalive_interval=0") {
		t.Fatalf("200ms keepalive was configured as persistent_keepalive_interval=0 (disabled), want a rounded-up positive value:\n%s", block)
	}
	if !strings.Contains(block, "persistent_keepalive_interval=1") {
		t.Fatalf("200ms keepalive: want persistent_keepalive_interval=1, got:\n%s", block)
	}
}
