package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/ipsec"
	"github.com/ngthdong/egressa/internal/telemetry"
)

type IPsecConfig struct {
	IKE ipsec.IKE
	Net ipsec.Net
}

const (
	ipsecAddWait  = 20 * time.Second
	ipsecRetry    = 5 * time.Second
	ipsecDPDDelay = 10 * time.Second
)

// ipsecPeer is one access gateway the client keeps an SA with.
type ipsecPeer struct {
	gw      api.Gateway
	ifID    uint32
	up      bool
	adding  bool
	lastTry time.Time
}

// ipsecPlane keeps a warm SA with every access gateway that takes IPsec
// clients, each on its own XFRM interface, and points the full-tunnel
// routes at the active one. Each gateway's node IP is routed through that
// gateway's own SA, so every gateway can be probed directly.
type ipsecPlane struct {
	cl     *ipsec.Client
	vip    netip.Addr
	log    *slog.Logger
	ctx    context.Context
	split  []netip.Prefix // routes when not in full-tunnel mode
	wg     sync.WaitGroup
	mu     sync.Mutex
	peers  map[string]*ipsecPeer
	nextID uint32
	active string
	epoch  uint64
}

func newIPsecPlane(ctx context.Context, cfg IPsecConfig, sess api.Session, full bool, controllers []netip.Addr, split []netip.Prefix, log *slog.Logger) (*ipsecPlane, error) {
	if sess.IPsecPSK == "" {
		return nil, errors.New("client: the controller gave this IPsec session no key")
	}
	cl, err := ipsec.NewClient(ipsec.ClientConfig{
		Name:        "egressa",
		LocalID:     api.IPsecClientID(sess.ID),
		PSK:         sess.IPsecPSK,
		VirtualIP:   sess.VirtualIP,
		FullTunnel:  full,
		Controllers: controllers,
		DPDDelay:    ipsecDPDDelay,
	}, cfg.IKE, cfg.Net)
	if err != nil {
		return nil, err
	}
	return &ipsecPlane{
		cl: cl, vip: sess.VirtualIP, log: log, ctx: ctx, split: split,
		peers: make(map[string]*ipsecPeer), nextID: 1, active: sess.Access, epoch: sess.Epoch,
	}, nil
}

func ipsecIface(ifID uint32) string {
	return ipsec.DefaultInterfacePrefix + strconv.FormatUint(uint64(ifID), 10)
}

// sync starts bringing up an SA with every gateway in gws that does not
// have one, and drops warm-standby SAs that died. It never blocks on IKE.
func (p *ipsecPlane) sync(gws []api.Gateway) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for _, g := range gws {
		pe := p.peers[g.ID]
		if pe == nil {
			pe = &ipsecPeer{gw: g, ifID: p.nextID}
			p.nextID++
			p.peers[g.ID] = pe
		}
		pe.gw = g
		if pe.up && g.ID != p.active {
			// DPD clears a dead gateway's SA; take it down so it is
			// brought up again on a later pass.
			if warm, err := p.cl.Warm(p.ctx, g.ID); err == nil && !warm {
				p.log.Warn("IPsec SA to a standby gateway is gone; re-establishing", "gateway", g.ID)
				_ = p.cl.Remove(p.ctx, g.ID)
				pe.up = false
			}
		}
		if pe.up || pe.adding || now.Sub(pe.lastTry) < ipsecRetry {
			continue
		}
		pe.adding, pe.lastTry = true, now
		p.wg.Add(1)
		go p.add(pe)
	}
}

func (p *ipsecPlane) add(pe *ipsecPeer) {
	defer p.wg.Done()
	ctx, cancel := context.WithTimeout(p.ctx, ipsecAddWait)
	defer cancel()
	host, err := pe.gw.Host()
	if err == nil {
		p.mu.Lock()
		epoch := p.epoch
		p.mu.Unlock()
		err = p.cl.Add(ctx, ipsec.Peer{
			Name: pe.gw.ID, Addr: host, ID: api.IPsecGatewayID(pe.gw.ID), IfID: pe.ifID, Epoch: epoch,
		})
	}
	if err == nil {
		// Probes to this gateway's node IP go through this gateway's SA.
		err = ipCmd("route", "replace", netip.PrefixFrom(pe.gw.NodeIP, 32).String(),
			"dev", ipsecIface(pe.ifID), "src", p.vip.String())
	}
	p.mu.Lock()
	pe.adding = false
	pe.up = err == nil
	promote := err == nil && pe.gw.ID == p.active
	p.mu.Unlock()
	if err != nil {
		if p.ctx.Err() == nil {
			p.log.Warn("IPsec SA to a gateway failed; retrying", "gateway", pe.gw.ID, telemetry.Err(err))
		}
		_ = p.cl.Remove(context.WithoutCancel(ctx), pe.gw.ID)
		return
	}
	p.log.Info("IPsec SA up", "gateway", pe.gw.ID, "interface", ipsecIface(pe.ifID))
	if promote {
		if err := p.promote(pe.gw.ID); err != nil {
			p.log.Warn("routing through the access gateway failed", "gateway", pe.gw.ID, telemetry.Err(err))
		}
	}
}

func (p *ipsecPlane) promote(id string) error {
	if err := p.cl.Promote(p.ctx, id, p.split...); err != nil {
		return err
	}
	p.log.Info("traffic now goes through IPsec to the access gateway", "gateway", id)
	return nil
}

// activate makes gateway id the access: its SA gets the tunnel routes now
// if it is up, or as soon as it comes up.
func (p *ipsecPlane) activate(id string, epoch uint64) error {
	p.mu.Lock()
	p.active, p.epoch = id, epoch
	pe := p.peers[id]
	up := pe != nil && pe.up
	p.mu.Unlock()
	if !up {
		return fmt.Errorf("no IPsec SA with %s yet; it gets the traffic once one is up", id)
	}
	return p.promote(id)
}

func (p *ipsecPlane) close() {
	p.wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := p.cl.Close(ctx); err != nil {
		p.log.Warn("closing the IPsec SAs failed", telemetry.Err(err))
	}
}
