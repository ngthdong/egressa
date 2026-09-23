package tunnel

import (
	"bytes"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/ngthdong/egressa/pkg/wire"
)

// DefaultMTU matches WireGuard's own default tunnel MTU.
const DefaultMTU = 1420

// Config configures a Device.
type Config struct {
	// PrivateKey is this device's own private key.
	PrivateKey [KeySize]byte
	// ListenPort is the UDP port this device listens on. 0 picks a free
	// port, which is what tests should use.
	ListenPort uint16
	// Addresses are the virtual IPs this device answers to on the tunnel.
	Addresses []netip.Addr
	// MTU is the tunnel MTU. Zero means DefaultMTU.
	MTU int
	// SessionID and Epoch are stamped into every outbound packet's
	// session header. Zero values are valid; session management proper
	// (assigning real IDs, bumping epoch on migration) comes later.
	SessionID uint64
	Epoch     uint32
	// OnSessionPacket, if set, is called with every inbound packet's
	// decoded session header, before the packet is delivered locally.
	// Optional; used for observability and tests.
	OnSessionPacket func(wire.SessionHeader)
}

// Device wraps a wireguard-go device backed by a userspace (netstack) TUN.
// This needs no OS-level TUN device and no elevated privileges, so it can
// be created and torn down freely in tests.
//
// A real OS-level TUN device (which does need root) is a separate concern,
// added later when the gateway needs to route real system traffic.
type Device struct {
	dev *device.Device
	net *netstack.Net
}

func New(cfg Config) (*Device, error) {
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}

	realTUN, tnet, err := netstack.CreateNetTUN(cfg.Addresses, nil, mtu)
	if err != nil {
		return nil, fmt.Errorf("tunnel: create TUN: %w", err)
	}
	wrappedBind := newSessionBind(conn.NewDefaultBind(), cfg.SessionID, cfg.Epoch, cfg.OnSessionPacket)

	logger := device.NewLogger(device.LogLevelSilent, "")
	dev := device.NewDevice(realTUN, wrappedBind, logger)

	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\n", Hex(cfg.PrivateKey), cfg.ListenPort)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: configure device: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("tunnel: bring device up: %w", err)
	}

	return &Device{dev: dev, net: tnet}, nil
}

func (d *Device) Close() {
	d.dev.Close()
}

func (d *Device) Net() *netstack.Net {
	return d.net
}

// uapiConfig reads the device's current configuration back via the UAPI
// get operation. Used by tests to confirm a set actually took effect.
func (d *Device) uapiConfig() (string, error) {
	var buf bytes.Buffer
	if err := d.dev.IpcGetOperation(&buf); err != nil {
		return "", fmt.Errorf("tunnel: read device config: %w", err)
	}
	return buf.String(), nil
}

// AddPeer configures a peer: its public key, the IP prefixes routed to it,
// and its UDP endpoint. Calling AddPeer again with a different public key
// adds another peer without disturbing existing ones.
//
// keepaliveInterval, if positive, sets persistent_keepalive_interval, so
// WireGuard sends periodic keepalives to this peer even with no traffic.
// This is what lets a handshake happen without sending any data packet
// first, which is useful for tests and for links behind NAT.
func (d *Device) AddPeer(
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

	if err := d.dev.IpcSet(b.String()); err != nil {
		return fmt.Errorf("tunnel: add peer: %w", err)
	}
	return nil
}

// ListenPort returns the UDP port this device is actually listening on.
// Needed after New with ListenPort: 0, which picks a free port at random.
func (d *Device) ListenPort() (uint16, error) {
	cfg, err := d.uapiConfig()
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

// LastHandshake returns the time of the most recent Noise handshake with
// the peer identified by publicKey, or the zero Time if none has happened
// yet. Resolution is nanosecond, not second: on a fast loopback test,
// two handshakes can easily complete within the same wall-clock second,
// so comparing LastHandshake results with time.Time.After needs the full
// precision UAPI actually reports.
func (d *Device) LastHandshake(publicKey [KeySize]byte) (time.Time, error) {
	cfg, err := d.uapiConfig()
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

func (d *Device) RemovePeer(publicKey [KeySize]byte) error {
	uapi := fmt.Sprintf("public_key=%s\nremove=true\n", Hex(publicKey))
	if err := d.dev.IpcSet(uapi); err != nil {
		return fmt.Errorf("tunnel: remove peer: %w", err)
	}
	return nil
}

// PeerStats returns the number of bytes sent to and received from the
// peer identified by publicKey, as counted by WireGuard at the encrypted
// transport layer. Both are 0 before any traffic has been exchanged.
func (d *Device) PeerStats(publicKey [KeySize]byte) (tx, rx uint64, err error) {
	cfg, err := d.uapiConfig()
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
