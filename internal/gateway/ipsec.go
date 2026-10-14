package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/ipsec"
	"github.com/ngthdong/egressa/internal/telemetry"
)

const (
	ipsecDevice = "egi0"
	ipsecIfID   = 7001
	ipsecDPD    = 10 * time.Second
	ipsecOpWait = 10 * time.Second
)

// IPsecConfig enables IPsec clients on a gateway.
type IPsecConfig struct {
	// IKE is the gateway's charon, over vici.
	IKE ipsec.IKE
	// Net creates the XFRM interface.
	Net ipsec.Net
}

func ipsecConnName(session string) string { return "egressa-s" + session }

// ipsecConnection is session's IKE connection on gateway me.
func ipsecConnection(me, session string, c IPsecClient) ipsec.Connection {
	return ipsec.Connection{
		Name:     ipsecConnName(session),
		LocalID:  api.IPsecGatewayID(me),
		RemoteID: api.IPsecClientID(session),
		Auth:     ipsec.AuthPSK,
		PSK:      c.PSK,
		LocalTS:  []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		RemoteTS: []netip.Prefix{netip.PrefixFrom(c.VirtualIP, 32)},
		IfID:     ipsecIfID,
		DPDDelay: ipsecDPD,
		Start:    ipsec.StartNone,
	}
}

func (a *Agent) setupIPsec() error {
	n := a.cfg.IPsec.Net
	_ = n.DeleteLink(ipsecDevice) // left behind by a crash
	if err := n.AddXfrmInterface(ipsecDevice, ipsecIfID, ""); err != nil {
		return fmt.Errorf("create the IPsec interface: %w", err)
	}
	a.undo = append(a.undo, func() { _ = n.DeleteLink(ipsecDevice) })
	if err := addrUp(ipsecDevice, a.nodeIP, a.cfg.MTU); err != nil {
		return err
	}
	for _, r := range forwardRules(ipsecDevice) {
		if err := ensureIptables(r); err != nil {
			return err
		}
		a.undo = append(a.undo, func() { _ = deleteIptables(r) })
	}
	return nil
}

func (a *Agent) removeIPsecLocked(ctx context.Context, p Plan) []error {
	var errs []error
	for session, have := range a.ipsecConns {
		if want, ok := p.IPsec[session]; ok && want == have {
			continue
		}
		errs = append(errs, a.unloadIPsec(ctx, session, have)...)
		delete(a.ipsecConns, session)
	}
	for vip := range a.ipsecHere {
		if !p.IPsecHere[vip] {
			if err := ipIgnore("route", "del", netip.PrefixFrom(vip, 32).String(), "dev", ipsecDevice); err != nil {
				errs = append(errs, err)
			}
			delete(a.ipsecHere, vip)
		}
	}
	return errs
}

func (a *Agent) unloadIPsec(ctx context.Context, session string, c IPsecClient) []error {
	ike := a.cfg.IPsec.IKE
	name := ipsecConnName(session)
	errs := []error{
		ignoreIPsecNotFound(ike.TerminateIKE(ctx, name)),
		ignoreIPsecNotFound(ike.UnloadConn(ctx, name)),
		ignoreIPsecNotFound(ike.UnloadShared(ctx, name)),
		ipIgnore("route", "del", netip.PrefixFrom(c.VirtualIP, 32).String(), "dev", ipsecDevice, "table", strconv.Itoa(probeTable)),
	}
	a.log.Info("IPsec client removed", "session", session)
	return errs
}

func (a *Agent) addIPsecLocked(ctx context.Context, p Plan) []error {
	ike := a.cfg.IPsec.IKE
	var errs []error
	for session, c := range p.IPsec {
		if _, ok := a.ipsecConns[session]; ok {
			continue
		}
		conn := ipsecConnection(a.cfg.ID, session, c)
		secret := ipsec.SharedSecret{ID: conn.Name, PSK: c.PSK, Owners: []string{conn.RemoteID}}
		if err := ike.LoadShared(ctx, secret); err != nil {
			errs = append(errs, fmt.Errorf("IPsec session %s: %w", session, err))
			continue
		}
		if err := ike.LoadConn(ctx, conn); err != nil {
			errs = append(errs, fmt.Errorf("IPsec session %s: %w", session, err))
			_ = ike.UnloadShared(ctx, secret.ID)
			continue
		}
		// Probe replies leave from the node IP through the IPsec interface.
		if err := ip("route", "replace", netip.PrefixFrom(c.VirtualIP, 32).String(), "dev", ipsecDevice, "table", strconv.Itoa(probeTable)); err != nil {
			errs = append(errs, err)
		}
		a.ipsecConns[session] = c
		a.log.Info("IPsec client added", "session", session, "virtual_ip", c.VirtualIP.String())
	}
	for vip := range p.IPsecHere {
		if a.ipsecHere[vip] {
			continue
		}
		if err := ip("route", "replace", netip.PrefixFrom(vip, 32).String(), "dev", ipsecDevice); err != nil {
			errs = append(errs, err)
			continue
		}
		a.ipsecHere[vip] = true
	}
	return errs
}

func (a *Agent) teardownIPsec() {
	ctx, cancel := context.WithTimeout(context.Background(), ipsecOpWait)
	defer cancel()
	for session, c := range a.ipsecConns {
		if err := errors.Join(a.unloadIPsec(ctx, session, c)...); err != nil {
			a.log.Warn("unloading an IPsec client failed", "session", session, telemetry.Err(err))
		}
	}
	a.ipsecConns = map[string]IPsecClient{}
}

func ignoreIPsecNotFound(err error) error {
	if errors.Is(err, ipsec.ErrNotFound) {
		return nil
	}
	return err
}
