package tunnel

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

const KeySize = 32

type KeyPair struct {
	Private [KeySize]byte
	Public  [KeySize]byte
}

func GenerateKeyPair() (KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("tunnel: generate key: %w", err)
	}

	var kp KeyPair
	copy(kp.Private[:], priv.Bytes())
	clamp(&kp.Private)
	copy(kp.Public[:], priv.PublicKey().Bytes())
	return kp, nil
}

// clamp applies the RFC 7748 X25519 clamping bits to a private key in
// place. X25519 scalar multiplication clamps its input internally
// regardless, so this does not change which key pair k represents. It
// just makes the stored bytes match the canonical form every X25519
// implementation (including wireguard-go) reports back.
func clamp(k *[KeySize]byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

// PublicKey derives the X25519 public key of a private key.
func PublicKey(private [KeySize]byte) ([KeySize]byte, error) {
	var pub [KeySize]byte
	priv, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil {
		return pub, fmt.Errorf("tunnel: derive public key: %w", err)
	}
	copy(pub[:], priv.PublicKey().Bytes())
	return pub, nil
}

func Hex(key [KeySize]byte) string {
	return hex.EncodeToString(key[:])
}

func DecodeHex(s string) ([KeySize]byte, error) {
	var key [KeySize]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return key, fmt.Errorf("tunnel: decode hex key: %w", err)
	}
	if len(b) != KeySize {
		return key, fmt.Errorf("tunnel: decode hex key: got %d bytes, want %d", len(b), KeySize)
	}
	copy(key[:], b)
	return key, nil
}

func Base64(key [KeySize]byte) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

func DecodeBase64(s string) ([KeySize]byte, error) {
	var key [KeySize]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return key, fmt.Errorf("tunnel: decode base64 key: %w", err)
	}
	if len(b) != KeySize {
		return key, fmt.Errorf("tunnel: decode base64 key: got %d bytes, want %d", len(b), KeySize)
	}
	copy(key[:], b)
	return key, nil
}

func LoadOrCreatePrivateKey(path string) (KeyPair, error) {
	if path == "" {
		kp, err := GenerateKeyPair()
		if err != nil {
			return KeyPair{}, err
		}
		return kp, nil
	}

	data, err := os.ReadFile(path)
	if err == nil {
		priv, err := DecodeBase64(strings.TrimSpace(string(data)))
		if err != nil {
			return KeyPair{}, fmt.Errorf("tunnel: parse private key at %s: %w", path, err)
		}
		pub, err := PublicKey(priv)
		if err != nil {
			return KeyPair{}, err
		}
		return KeyPair{Private: priv, Public: pub}, nil
	}
	if !os.IsNotExist(err) {
		return KeyPair{}, fmt.Errorf("tunnel: read private key at %s: %w", path, err)
	}

	kp, err := GenerateKeyPair()
	if err != nil {
		return KeyPair{}, err
	}
	if err := os.WriteFile(path, []byte(Base64(kp.Private)), 0600); err != nil {
		return KeyPair{}, fmt.Errorf("tunnel: save private key to %s: %w", path, err)
	}
	return kp, nil
}
