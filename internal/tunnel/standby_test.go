package tunnel

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const standbyTestKeepalive = 1 * time.Second

func newStandbyPair(t *testing.T) (self, candidate *Device, selfKP, candidateKP KeyPair) {
	t.Helper()

	var err error
	selfKP, err = GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (self): %v", err)
	}
	candidateKP, err = GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (candidate): %v", err)
	}

	self, err = New(Config{PrivateKey: selfKP.Private, Addresses: []netip.Addr{netip.MustParseAddr("10.98.0.1")}})
	if err != nil {
		t.Fatalf("New (self): %v", err)
	}
	t.Cleanup(self.Close)

	candidate, err = New(Config{PrivateKey: candidateKP.Private, Addresses: []netip.Addr{netip.MustParseAddr("10.98.0.2")}})
	if err != nil {
		t.Fatalf("New (candidate): %v", err)
	}
	t.Cleanup(candidate.Close)

	if err := candidate.AddPeer(selfKP.Public, nil, "", 0); err != nil {
		t.Fatalf("candidate.AddPeer(self): %v", err)
	}

	return self, candidate, selfKP, candidateKP
}

func TestStandbyManager_HandshakeViaKeepaliveOnly(t *testing.T) {
	self, candidate, _, candidateKP := newStandbyPair(t)

	candidatePort, err := candidate.ListenPort()
	if err != nil {
		t.Fatalf("candidate.ListenPort: %v", err)
	}

	mgr, err := NewStandbyManager(self, standbyTestKeepalive)
	if err != nil {
		t.Fatalf("NewStandbyManager: %v", err)
	}

	warm, err := mgr.IsWarm("candidate", time.Second)
	if err == nil {
		t.Fatalf("IsWarm before Add returned (%v, nil), want an error for an unknown candidate", warm)
	}

	err = mgr.Add(StandbyCandidate{
		ID:        "candidate",
		PublicKey: candidateKP.Public,
		Endpoint:  fmt.Sprintf("127.0.0.1:%d", candidatePort),
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	const warmupTimeout = 25 * time.Second
	deadline := time.Now().Add(warmupTimeout)
	for {
		warm, err := mgr.IsWarm("candidate", 2*time.Second)
		if err != nil {
			t.Fatalf("IsWarm: %v", err)
		}
		if warm {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("candidate never became warm from keepalive alone within %s", warmupTimeout)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestStandbyManager_IsWarm_NeverHandshaked(t *testing.T) {
	self, _, _, _ := newStandbyPair(t)

	mgr, err := NewStandbyManager(self, standbyTestKeepalive)
	if err != nil {
		t.Fatalf("NewStandbyManager: %v", err)
	}

	unreachableKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	// Port 1 is reserved and nothing will ever be listening there; no
	// handshake response can ever arrive.
	if err := mgr.Add(StandbyCandidate{ID: "ghost", PublicKey: unreachableKP.Public, Endpoint: "127.0.0.1:1"}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	warm, err := mgr.IsWarm("ghost", time.Hour)
	if err != nil {
		t.Fatalf("IsWarm: %v", err)
	}
	if warm {
		t.Fatal("IsWarm reported true for a candidate that never handshaked")
	}
}

func TestStandbyManager_NewStandbyManager_RequiresPositiveKeepalive(t *testing.T) {
	self, _, _, _ := newStandbyPair(t)
	for _, ka := range []time.Duration{0, -time.Second} {
		if _, err := NewStandbyManager(self, ka); err == nil {
			t.Fatalf("NewStandbyManager(keepalive=%s): expected an error", ka)
		}
	}
}

// peerConfigBlock returns the lines of cfg (as returned by the device's
// UAPI get operation) belonging to the peer identified by publicKeyHex,
// from its "public_key=" line up to (excluding) the next "public_key="
// line or the end of the config. It is the direct way to check what was
// actually configured for one peer, as opposed to inferring it indirectly
// from behavior.
func peerConfigBlock(t *testing.T, cfg, publicKeyHex string) string {
	t.Helper()
	lines := strings.Split(cfg, "\n")
	start := -1
	for i, line := range lines {
		if line == "public_key="+publicKeyHex {
			start = i
			break
		}
	}
	if start == -1 {
		return ""
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "public_key=") {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

func TestStandbyManager_Add_ConfiguresNoAllowedIPs(t *testing.T) {
	self, candidate, _, candidateKP := newStandbyPair(t)

	candidatePort, err := candidate.ListenPort()
	if err != nil {
		t.Fatalf("candidate.ListenPort: %v", err)
	}

	mgr, err := NewStandbyManager(self, standbyTestKeepalive)
	if err != nil {
		t.Fatalf("NewStandbyManager: %v", err)
	}
	err = mgr.Add(StandbyCandidate{
		ID:        "candidate",
		PublicKey: candidateKP.Public,
		Endpoint:  fmt.Sprintf("127.0.0.1:%d", candidatePort),
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	cfg, err := self.uapiConfig()
	if err != nil {
		t.Fatalf("uapiConfig: %v", err)
	}
	block := peerConfigBlock(t, cfg, Hex(candidateKP.Public))
	if block == "" {
		t.Fatal("standby peer not found in device config at all")
	}
	if strings.Contains(block, "allowed_ip=") {
		t.Fatalf("standby peer config has an allowed_ip entry, which defeats the whole point of a standby peer:\n%s", block)
	}
	if !strings.Contains(block, "persistent_keepalive_interval=") {
		t.Fatalf("standby peer config is missing persistent_keepalive_interval, so it will never stay warm:\n%s", block)
	}
}

func TestStandbyManager_Remove(t *testing.T) {
	self, candidate, _, candidateKP := newStandbyPair(t)

	candidatePort, err := candidate.ListenPort()
	if err != nil {
		t.Fatalf("candidate.ListenPort: %v", err)
	}
	mgr, err := NewStandbyManager(self, standbyTestKeepalive)
	if err != nil {
		t.Fatalf("NewStandbyManager: %v", err)
	}
	if err := mgr.Add(StandbyCandidate{ID: "c", PublicKey: candidateKP.Public, Endpoint: fmt.Sprintf("127.0.0.1:%d", candidatePort)}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Removing an id that was never added must be a harmless no-op.
	if err := mgr.Remove("never-added"); err != nil {
		t.Fatalf("Remove(never-added): %v", err)
	}

	if err := mgr.Remove("c"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	cfg, err := self.uapiConfig()
	if err != nil {
		t.Fatalf("uapiConfig: %v", err)
	}
	if peerConfigBlock(t, cfg, Hex(candidateKP.Public)) != "" {
		t.Fatal("peer still present in device config after Remove")
	}

	if _, err := mgr.IsWarm("c", time.Second); err == nil {
		t.Fatal("IsWarm(\"c\") after Remove: expected an error for an unknown candidate")
	}
}

func TestStandbyManager_Add_ReplacesOldPeerOnKeyChange(t *testing.T) {
	self, candidateA, _, candidateAKP := newStandbyPair(t)

	candidateAPort, err := candidateA.ListenPort()
	if err != nil {
		t.Fatalf("candidateA.ListenPort: %v", err)
	}

	candidateBKP, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (candidateB): %v", err)
	}
	candidateB, err := New(Config{PrivateKey: candidateBKP.Private, Addresses: []netip.Addr{netip.MustParseAddr("10.98.0.3")}})
	if err != nil {
		t.Fatalf("New (candidateB): %v", err)
	}
	t.Cleanup(candidateB.Close)
	candidateBPort, err := candidateB.ListenPort()
	if err != nil {
		t.Fatalf("candidateB.ListenPort: %v", err)
	}

	mgr, err := NewStandbyManager(self, standbyTestKeepalive)
	if err != nil {
		t.Fatalf("NewStandbyManager: %v", err)
	}

	// Same logical candidate ID, "primary", first pointed at A's key/port...
	if err := mgr.Add(StandbyCandidate{ID: "primary", PublicKey: candidateAKP.Public, Endpoint: fmt.Sprintf("127.0.0.1:%d", candidateAPort)}); err != nil {
		t.Fatalf("Add (A): %v", err)
	}
	// ...then re-pointed at B's key/port, as if the control plane picked
	// a different concrete gateway for the same role.
	if err := mgr.Add(StandbyCandidate{ID: "primary", PublicKey: candidateBKP.Public, Endpoint: fmt.Sprintf("127.0.0.1:%d", candidateBPort)}); err != nil {
		t.Fatalf("Add (B): %v", err)
	}

	cfg, err := self.uapiConfig()
	if err != nil {
		t.Fatalf("uapiConfig: %v", err)
	}
	if peerConfigBlock(t, cfg, Hex(candidateAKP.Public)) != "" {
		t.Fatal("old peer (A) is still configured after Add replaced it with B: two live peers instead of one")
	}
	if peerConfigBlock(t, cfg, Hex(candidateBKP.Public)) == "" {
		t.Fatal("new peer (B) was not configured")
	}

	if candidates := mgr.Candidates(); len(candidates) != 1 || candidates[0] != "primary" {
		t.Fatalf("Candidates() = %v, want exactly [\"primary\"]", candidates)
	}
}
