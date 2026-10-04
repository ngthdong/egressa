//go:build linux

package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ngthdong/egressa/internal/api"
)

// Paths can be moved with environment variables, for tests and for
// hosts laid out differently.
func confPath() string   { return envOr("EGRESSA_CONF", "/etc/egressa/client.conf") }
func statePath() string  { return envOr("EGRESSA_STATE", "/var/lib/egressa/client.json") }
func statusPath() string { return envOr("EGRESSA_STATUS", "/run/egressa/status.json") }
func logPath() string    { return envOr("EGRESSA_LOG", "/var/log/egressa.log") }

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// conf is what `egressa join` saves: where the controller is, the client
// token, and the egress `egressa connect` last asked for.
type conf struct {
	Controller string `json:"controller"`
	Token      string `json:"token"`
	Egress     string `json:"egress,omitempty"`
	// MetricsListen, if set, is where `egressa run` serves /metrics.
	MetricsListen string `json:"metrics_listen,omitempty"`
}

var errNotJoined = errors.New("this machine has not joined a VPN yet; run: sudo egressa join <invite>")

func readConf(path string) (conf, error) {
	var c conf
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, errNotJoined
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	if c.Controller == "" || c.Token == "" {
		return c, fmt.Errorf("%s has no controller or token; run egressa join again", path)
	}
	return c, nil
}

// writeConf saves c readable by root only: it holds the client token.
func writeConf(path string, c conf) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// An invite carries a controller URL and a client token in one string
// an admin can hand to a user. It is a secret: it holds the token.
const invitePrefix = "egressa1."

type invite struct {
	Controller string `json:"c"`
	Token      string `json:"t"`
}

func encodeInvite(controller, token string) (string, error) {
	if _, err := api.NewClient(controller, token); err != nil {
		return "", err
	}
	if token == "" {
		return "", errors.New("no client token")
	}
	data, err := json.Marshal(invite{Controller: controller, Token: token})
	if err != nil {
		return "", err
	}
	return invitePrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func decodeInvite(s string) (invite, error) {
	var inv invite
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), invitePrefix)
	if !ok {
		return inv, fmt.Errorf("an invite starts with %q", invitePrefix)
	}
	data, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return inv, fmt.Errorf("the invite is damaged: %w", err)
	}
	if err := json.Unmarshal(data, &inv); err != nil {
		return inv, fmt.Errorf("the invite is damaged: %w", err)
	}
	if inv.Token == "" {
		return inv, errors.New("the invite has no token")
	}
	if _, err := api.NewClient(inv.Controller, inv.Token); err != nil {
		return inv, err
	}
	return inv, nil
}
