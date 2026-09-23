package tunnel

import (
	"net/netip"
	"testing"
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
