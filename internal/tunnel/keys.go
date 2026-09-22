package tunnel

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
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
	copy(kp.Public[:], priv.PublicKey().Bytes())
	return kp, nil
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
