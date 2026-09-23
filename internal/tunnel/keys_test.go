package tunnel

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeyPair_Valid(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	var zero [KeySize]byte
	if kp.Private == zero {
		t.Error("Private key is all zero")
	}
	if kp.Public == zero {
		t.Error("Public key is all zero")
	}
	if kp.Private == kp.Public {
		t.Error("Private and public key are equal")
	}
}

func TestGenerateKeyPair_Unique(t *testing.T) {
	a, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	b, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if a.Private == b.Private {
		t.Error("two calls produced the same private key")
	}
}

// TestGenerateKeyPair_PublicMatchesPrivate cross-checks that Public really
// is derived from Private via X25519, not just copied or unrelated.
func TestGenerateKeyPair_PublicMatchesPrivate(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	priv, err := ecdh.X25519().NewPrivateKey(kp.Private[:])
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	want := priv.PublicKey().Bytes()
	if !bytes.Equal(kp.Public[:], want) {
		t.Errorf("Public = %x, want %x", kp.Public, want)
	}
}

// TestKnownAnswer_RFC7748 checks our key handling against the standard
// X25519 test vector from RFC 7748 Section 6.1 (Alice's key pair).
func TestKnownAnswer_RFC7748(t *testing.T) {
	const (
		privHex    = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
		wantPubHex = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	)

	priv, err := DecodeHex(privHex)
	if err != nil {
		t.Fatalf("DecodeHex: %v", err)
	}

	ecdhPriv, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	var pub [KeySize]byte
	copy(pub[:], ecdhPriv.PublicKey().Bytes())

	if got := Hex(pub); got != wantPubHex {
		t.Errorf("public key = %s, want %s", got, wantPubHex)
	}
}

func TestHex_RoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	s := Hex(kp.Private)
	if len(s) != KeySize*2 {
		t.Errorf("Hex length = %d, want %d", len(s), KeySize*2)
	}

	got, err := DecodeHex(s)
	if err != nil {
		t.Fatalf("DecodeHex: %v", err)
	}
	if got != kp.Private {
		t.Errorf("round trip mismatch: got %x, want %x", got, kp.Private)
	}
}

func TestBase64_RoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	s := Base64(kp.Private)
	got, err := DecodeBase64(s)
	if err != nil {
		t.Fatalf("DecodeBase64: %v", err)
	}
	if got != kp.Private {
		t.Errorf("round trip mismatch: got %x, want %x", got, kp.Private)
	}
}

func TestDecodeHex_Errors(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"too short", "aabb"},
		{"too long", Hex([KeySize]byte{}) + "aa"},
		{"not hex", "zz" + Hex([KeySize]byte{})[2:]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeHex(tc.in); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestDecodeBase64_Errors(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"too short", "YWFhYQ=="},
		{"too long", base64.StdEncoding.EncodeToString(make([]byte, KeySize+1))},
		{"not base64", "***not valid***"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeBase64(tc.in); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestLoadOrCreatePrivateKey_EmptyPath(t *testing.T) {
	kp1, err := LoadOrCreatePrivateKey("")
	if err != nil {
		t.Fatalf("LoadOrCreatePrivateKey: %v", err)
	}
	kp2, err := LoadOrCreatePrivateKey("")
	if err != nil {
		t.Fatalf("LoadOrCreatePrivateKey: %v", err)
	}
	if kp1.Private == kp2.Private {
		t.Error("LoadOrCreatePrivateKey(\"\") returned the same key twice; expected a fresh one each call")
	}
}

func TestLoadOrCreatePrivateKey_CreatesAndReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.key")

	created, err := LoadOrCreatePrivateKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreatePrivateKey (create): %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist after create: %v", path, err)
	}

	loaded, err := LoadOrCreatePrivateKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreatePrivateKey (reload): %v", err)
	}
	if loaded.Private != created.Private {
		t.Error("reloaded private key does not match the one just created")
	}
}

func TestLoadOrCreatePrivateKey_MalformedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.key")
	if err := os.WriteFile(path, []byte("***not valid base64***"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := LoadOrCreatePrivateKey(path); err == nil {
		t.Fatal("LoadOrCreatePrivateKey with a malformed key file: expected error, got nil")
	}
}

// TestLoadOrCreatePrivateKey_UnreadableExistingFile covers the "exists but
// os.ReadFile fails for a reason other than not-exist" branch, using a
// directory in place of a file to get a deterministic, privilege-free
// ReadFile error.
func TestLoadOrCreatePrivateKey_UnreadableExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.key")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}

	if _, err := LoadOrCreatePrivateKey(path); err == nil {
		t.Fatal("LoadOrCreatePrivateKey with a directory at path: expected error, got nil")
	}
}

// TestLoadOrCreatePrivateKey_SaveFails covers os.WriteFile's error branch
// by pointing at a path inside a directory that doesn't exist.
func TestLoadOrCreatePrivateKey_SaveFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "no-such-dir", "client.key")

	if _, err := LoadOrCreatePrivateKey(path); err == nil {
		t.Fatal("LoadOrCreatePrivateKey with an unwritable path: expected error, got nil")
	}
}
