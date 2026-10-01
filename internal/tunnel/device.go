package tunnel

import (
	"fmt"
	"net/netip"
	"os"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/ngthdong/egressa/pkg/wire"
)

const DefaultMTU = 1420

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
	// Admit, if set, is called with every inbound packet's session header
	// before WireGuard sees the packet; returning false drops it.
	Admit func(wire.SessionHeader) bool
}

// Device wraps a wireguard-go device backed by a userspace (netstack) TUN.
// This needs no OS-level TUN device and no elevated privileges, so it can
// be created and torn down freely in tests.
type Device struct {
	peerManager
	net  *netstack.Net
	bind *sessionBind
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
	wrappedBind.admit = cfg.Admit

	logger := newLogger("netstack")
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

	return &Device{peerManager: peerManager{dev: dev}, net: tnet, bind: wrappedBind}, nil
}

// SetEpoch changes the epoch stamped into every packet sent from now on,
// after a migration commits.
func (d *Device) SetEpoch(epoch uint32) { d.bind.setEpoch(epoch) }

// newLogger is silent unless EGRESSA_WG_DEBUG=1, which logs every
// handshake and keepalive wireguard-go sends or receives.
func newLogger(name string) *device.Logger {
	if os.Getenv("EGRESSA_WG_DEBUG") == "1" {
		return device.NewLogger(device.LogLevelVerbose, "wireguard "+name+": ")
	}
	return device.NewLogger(device.LogLevelSilent, "")
}

func (d *Device) Net() *netstack.Net {
	return d.net
}
