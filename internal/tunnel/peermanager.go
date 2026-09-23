package tunnel

import (
	"bytes"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

// peerManager is the peer/config surface shared by every wireguard-go
// backed device in this package. Everything here only ever talks to
// *device.Device.IpcSet/IpcGetOperation, so it has no dependency on
// which tun.Device backend (netstack, a real OS TUN, ...) sits underneath.
type peerManager struct {
	dev *device.Device
}

func (m *peerManager) Close() {
	m.dev.Close()
}

func (m *peerManager) uapiConfig() (string, error) {
	var buf bytes.Buffer
	if err := m.dev.IpcGetOperation(&buf); err != nil {
		return "", fmt.Errorf("tunnel: read device config: %w", err)
	}
	return buf.String(), nil
}

func (m *peerManager) AddPeer(
	publicKey [KeySize]byte,
	allowedIPs []netip.Prefix,
	endpoint string,
	keepaliveInterval time.Duration,
) error {
	var b strings.Builder
	fmt.Fprintf(&b, "public_key=%s\n", Hex(publicKey))
	if endpoint != "" {
		fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	}
	for _, ip := range allowedIPs {
		fmt.Fprintf(&b, "allowed_ip=%s\n", ip.String())
	}
	if keepaliveInterval > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(keepaliveInterval.Seconds()))
	}

	if err := m.dev.IpcSet(b.String()); err != nil {
		return fmt.Errorf("tunnel: add peer: %w", err)
	}
	return nil
}

func (m *peerManager) ListenPort() (uint16, error) {
	cfg, err := m.uapiConfig()
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(cfg, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || key != "listen_port" {
			continue
		}
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return 0, fmt.Errorf("tunnel: parse listen_port: %w", err)
		}
		return uint16(port), nil
	}
	return 0, fmt.Errorf("tunnel: listen_port not found in device config")
}

// LastHandshake returns the time of the most recent Noise handshake with the
// peer identified by publicKey, or the zero Time if none has happened yet.
func (m *peerManager) LastHandshake(publicKey [KeySize]byte) (time.Time, error) {
	cfg, err := m.uapiConfig()
	if err != nil {
		return time.Time{}, err
	}

	want := Hex(publicKey)
	var inPeer bool
	var sec, nsec int64
	for _, line := range strings.Split(cfg, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			inPeer = value == want
		case "last_handshake_time_sec":
			if inPeer {
				sec, err = strconv.ParseInt(value, 10, 64)
				if err != nil {
					return time.Time{}, fmt.Errorf("tunnel: parse last_handshake_time_sec: %w", err)
				}
			}
		case "last_handshake_time_nsec":
			if inPeer {
				nsec, err = strconv.ParseInt(value, 10, 64)
				if err != nil {
					return time.Time{}, fmt.Errorf("tunnel: parse last_handshake_time_nsec: %w", err)
				}
			}
		}
	}
	if sec == 0 && nsec == 0 {
		return time.Time{}, nil
	}
	return time.Unix(sec, nsec), nil
}

func (m *peerManager) RemovePeer(publicKey [KeySize]byte) error {
	uapi := fmt.Sprintf("public_key=%s\nremove=true\n", Hex(publicKey))
	if err := m.dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("tunnel: remove peer: %w", err)
	}
	return nil
}

// PeerStats returns the number of bytes sent to and received from the
// peer identified by publicKey, as counted by WireGuard at the encrypted
// transport layer. Both are 0 before any traffic has been exchanged.
func (m *peerManager) PeerStats(publicKey [KeySize]byte) (tx, rx uint64, err error) {
	cfg, err := m.uapiConfig()
	if err != nil {
		return 0, 0, err
	}

	want := Hex(publicKey)
	var inPeer bool
	for _, line := range strings.Split(cfg, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "public_key":
			inPeer = value == want
		case "tx_bytes":
			if inPeer {
				tx, err = strconv.ParseUint(value, 10, 64)
				if err != nil {
					return 0, 0, fmt.Errorf("tunnel: parse tx_bytes: %w", err)
				}
			}
		case "rx_bytes":
			if inPeer {
				rx, err = strconv.ParseUint(value, 10, 64)
				if err != nil {
					return 0, 0, fmt.Errorf("tunnel: parse rx_bytes: %w", err)
				}
			}
		}
	}
	return tx, rx, nil
}
