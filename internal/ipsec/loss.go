package ipsec

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

// ErrLossUnavailable reports that the kernel keeps an SA's anti-replay
// state in a form the netlink library (vishvananda/netlink v1.3.1) does
// not decode. The kernel uses the extended XFRMA_REPLAY_ESN_VAL attribute
// instead of the legacy XFRMA_REPLAY_VAL whenever the SA has extended
// sequence numbers or a replay window above 32 (charon's default window is
// 32 and its default proposals have no ESN, so the legacy form is used
// unless a proposal or charon.replay_window asks otherwise). Loss is then
// unknown rather than reported as zero.
var ErrLossUnavailable = errors.New("ipsec: the SA's anti-replay state is not readable (ESN, or a replay window above 32)")

// Loss is passive packet loss on one inbound ESP SA, read from the
// kernel's own counters with no probing traffic.
type Loss struct {
	SPI uint32
	// HighestSeq is s_max, the highest ESP sequence number the SA has
	// accepted; Received is how many packets it has accepted.
	HighestSeq uint32
	Received   uint64
	// Lost is HighestSeq - Received: sequence numbers at or below the
	// highest one seen that never arrived (or arrived late and were
	// rejected). It is never negative.
	Lost uint64
}

// lossFor reads the loss of the newest installed CHILD_SA of connection
// conn from the kernel's XFRM state.
func lossFor(ctx context.Context, ike IKE, n Net, conn string) (Loss, error) {
	sas, err := ike.ListSAs(ctx, conn)
	if err != nil {
		return Loss{}, err
	}
	var child *ChildSA
	for i := range sas {
		if sas[i].Name != conn {
			continue
		}
		for j := range sas[i].Children {
			c := &sas[i].Children[j]
			if c.State == ChildStateInstalled && (child == nil || c.UniqueID > child.UniqueID) {
				child = c
			}
		}
	}
	if child == nil {
		return Loss{}, fmt.Errorf("ipsec: %s has no installed CHILD_SA: %w", conn, ErrNotFound)
	}
	spi, err := strconv.ParseUint(child.SPIIn, 16, 32)
	if err != nil {
		return Loss{}, fmt.Errorf("ipsec: %s: inbound SPI %q: %w", conn, child.SPIIn, err)
	}
	states, err := n.XfrmStates()
	if err != nil {
		return Loss{}, err
	}
	for _, st := range states {
		if st.SPI != uint32(spi) || st.IfID != child.IfIDIn {
			continue
		}
		if !st.HasReplay {
			return Loss{}, fmt.Errorf("ipsec: %s (SPI %08x): %w", conn, spi, ErrLossUnavailable)
		}
		return computeLoss(st), nil
	}
	return Loss{}, fmt.Errorf("ipsec: %s: no kernel state for inbound SPI %08x: %w", conn, spi, ErrNotFound)
}

func computeLoss(st XfrmState) Loss {
	l := Loss{SPI: st.SPI, HighestSeq: st.ReplaySeq, Received: st.Packets}
	if uint64(st.ReplaySeq) > st.Packets {
		l.Lost = uint64(st.ReplaySeq) - st.Packets
	}
	return l
}

// Loss reads the passive loss of gateway name's current inbound SA.
func (c *Client) Loss(ctx context.Context, name string) (Loss, error) {
	p, err := c.peer(name)
	if err != nil {
		return Loss{}, err
	}
	return lossFor(ctx, c.ike, c.net, p.conn.Name)
}

// BackboneLoss reads the passive loss of the inbound backbone SA from
// peer name.
func (g *Gateway) BackboneLoss(ctx context.Context, name string) (Loss, error) {
	p, err := g.peer(name)
	if err != nil {
		return Loss{}, err
	}
	return lossFor(ctx, g.ike, g.net, p.conn.Name)
}
