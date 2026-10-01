package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ngthdong/egressa/internal/tunnel"
)

// StateFile is what a client keeps across restarts: its key, and the
// session that key holds with the secret that reopens it.
type StateFile struct {
	PrivateKey string `json:"private_key"`
	SessionID  string `json:"session_id,omitempty"`
	Secret     string `json:"secret,omitempty"`
}

// LoadState reads path, creating a new key if it does not exist.
func LoadState(path string) (StateFile, tunnel.KeyPair, error) {
	var st StateFile
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		kp, err := tunnel.GenerateKeyPair()
		if err != nil {
			return st, kp, err
		}
		st.PrivateKey = tunnel.Base64(kp.Private)
		return st, kp, nil
	case err != nil:
		return st, tunnel.KeyPair{}, fmt.Errorf("client: read state: %w", err)
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, tunnel.KeyPair{}, fmt.Errorf("client: parse state file %s: %w", path, err)
	}
	priv, err := tunnel.DecodeBase64(st.PrivateKey)
	if err != nil {
		return st, tunnel.KeyPair{}, fmt.Errorf("client: state file %s: %w", path, err)
	}
	pub, err := tunnel.PublicKey(priv)
	if err != nil {
		return st, tunnel.KeyPair{}, err
	}
	return st, tunnel.KeyPair{Private: priv, Public: pub}, nil
}

// SaveState writes st to path, readable by its owner only: it holds a
// private key and a session secret.
func SaveState(path string, st StateFile) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("client: save state: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("client: save state: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("client: save state: %w", err)
	}
	return nil
}
