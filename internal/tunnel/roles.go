package tunnel

import (
	"net/netip"
	"time"
)

type AccessGateway struct {
	dev *RealDevice
}

func NewAccessGateway(dev *RealDevice) *AccessGateway {
	return &AccessGateway{dev: dev}
}

func (a *AccessGateway) Name() string      { return a.dev.Name() }
func (a *AccessGateway) MTU() (int, error) { return a.dev.MTU() }
func (a *AccessGateway) Close()            { a.dev.Close() }

func (a *AccessGateway) AddPeer(publicKey [KeySize]byte, allowedIPs []netip.Prefix, endpoint string, keepaliveInterval time.Duration) error {
	return a.dev.AddPeer(publicKey, allowedIPs, endpoint, keepaliveInterval)
}

func (a *AccessGateway) RemovePeer(publicKey [KeySize]byte) error {
	return a.dev.RemovePeer(publicKey)
}

func (a *AccessGateway) ListenPort() (uint16, error) { return a.dev.ListenPort() }

func (a *AccessGateway) LastHandshake(publicKey [KeySize]byte) (time.Time, error) {
	return a.dev.LastHandshake(publicKey)
}

func (a *AccessGateway) PeerStats(publicKey [KeySize]byte) (tx, rx uint64, err error) {
	return a.dev.PeerStats(publicKey)
}

type EgressGateway struct {
	dev *RealDevice
}

func NewEgressGateway(dev *RealDevice) *EgressGateway {
	return &EgressGateway{dev: dev}
}

func (e *EgressGateway) Name() string      { return e.dev.Name() }
func (e *EgressGateway) MTU() (int, error) { return e.dev.MTU() }
func (e *EgressGateway) Close()            { e.dev.Close() }

func (e *EgressGateway) AddPeer(publicKey [KeySize]byte, allowedIPs []netip.Prefix, endpoint string, keepaliveInterval time.Duration) error {
	return e.dev.AddPeer(publicKey, allowedIPs, endpoint, keepaliveInterval)
}

func (e *EgressGateway) RemovePeer(publicKey [KeySize]byte) error {
	return e.dev.RemovePeer(publicKey)
}

func (e *EgressGateway) ListenPort() (uint16, error) { return e.dev.ListenPort() }

func (e *EgressGateway) LastHandshake(publicKey [KeySize]byte) (time.Time, error) {
	return e.dev.LastHandshake(publicKey)
}

func (e *EgressGateway) PeerStats(publicKey [KeySize]byte) (tx, rx uint64, err error) {
	return e.dev.PeerStats(publicKey)
}

func (e *EgressGateway) ConfigureNAT(subnet netip.Prefix) error {
	return AddNAT(NATRule{Subnet: subnet})
}

func (e *EgressGateway) RemoveNATConfig(subnet netip.Prefix) error {
	return RemoveNAT(NATRule{Subnet: subnet})
}
