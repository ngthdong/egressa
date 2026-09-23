package tunnel

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/ngthdong/egressa/pkg/wire"
)

type RealConfig struct {
	PrivateKey      [KeySize]byte
	ListenPort      uint16
	InterfaceName   string
	MTU             int
	SessionID       uint64
	Epoch           uint32
	OnSessionPacket func(wire.SessionHeader)
}

type RealDevice struct {
	dev  *device.Device
	tun  tun.Device
	name string
}

func NewReal(cfg RealConfig) (*RealDevice, error) {
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = DefaultMTU
	}

	realTUN, err := tun.CreateTUN(cfg.InterfaceName, mtu)
	if err != nil {
		return nil, classifyTUNError(cfg.InterfaceName, err)
	}

	actualName, err := realTUN.Name()
	if err != nil {
		_ = realTUN.Close()
		return nil, fmt.Errorf("tunnel: get TUN interface name: %w", err)
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

	return &RealDevice{dev: dev, tun: realTUN, name: actualName}, nil
}

func (d *RealDevice) Close() {
	d.dev.Close()
}

func (d *RealDevice) Name() string {
	return d.name
}

func (d *RealDevice) MTU() (int, error) {
	return d.tun.MTU()
}

var ErrPermissionDenied = errors.New("tunnel: insufficient privilege to create a TUN device (needs CAP_NET_ADMIN / root)")

func classifyTUNError(name string, err error) error {
	if errors.Is(err, os.ErrPermission) ||
		errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EACCES) ||
		strings.Contains(err.Error(), "operation not permitted") ||
		strings.Contains(err.Error(), "permission denied") {
		return fmt.Errorf("tunnel: create TUN %q: %w: %w", name, ErrPermissionDenied, err)
	}
	return fmt.Errorf("tunnel: create TUN %q: %w", name, err)
}
