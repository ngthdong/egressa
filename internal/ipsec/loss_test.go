package ipsec

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
)

func TestComputeLoss(t *testing.T) {
	for name, tc := range map[string]struct {
		seq     uint32
		packets uint64
		lost    uint64
	}{
		"nothing lost":   {seq: 40, packets: 40, lost: 0},
		"three lost":     {seq: 43, packets: 40, lost: 3},
		"nothing yet":    {seq: 0, packets: 0, lost: 0},
		"never negative": {seq: 10, packets: 12, lost: 0}, // counters read a moment apart
	} {
		got := computeLoss(XfrmState{SPI: 7, ReplaySeq: tc.seq, Packets: tc.packets, HasReplay: true})
		if got.Lost != tc.lost || got.HighestSeq != tc.seq || got.Received != tc.packets || got.SPI != 7 {
			t.Errorf("%s: computeLoss = %+v, want Lost %d", name, got, tc.lost)
		}
	}
}

// lossClient returns a client with gateway hk up, and the inbound SPI of
// its CHILD_SA as fakeIKE assigned it.
func lossClient(t *testing.T) (*Client, *fakeIKE, *fakeNet, uint32) {
	t.Helper()
	c, ike, n := newTestClient(t, nil)
	if err := c.Add(context.Background(), testPeer("hk", 7, "203.0.113.1")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	sas, _ := ike.ListSAs(context.Background(), "egressa-hk")
	return c, ike, n, parseSPI(t, sas[0].Children[0].SPIIn)
}

func parseSPI(t *testing.T, s string) uint32 {
	t.Helper()
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		t.Fatalf("SPI %q: %v", s, err)
	}
	return uint32(v)
}

func TestClient_Loss(t *testing.T) {
	c, ike, n, spi := lossClient(t)
	ctx := context.Background()

	if _, err := c.Loss(ctx, "hk"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Loss with no kernel state = %v, want ErrNotFound", err)
	}
	n.states = []XfrmState{
		{SPI: spi, IfID: 99, ReplaySeq: 1, Packets: 1, HasReplay: true}, // same SPI, other if_id
		{SPI: spi, IfID: 7, ReplaySeq: 105, Packets: 100, HasReplay: true},
	}
	l, err := c.Loss(ctx, "hk")
	if err != nil || l.Lost != 5 || l.Received != 100 || l.HighestSeq != 105 || l.SPI != spi {
		t.Fatalf("Loss = %+v, %v; want 5 lost of 105 on SPI %08x", l, err, spi)
	}

	// A newer CHILD_SA (after a rekey or an Advance) is the one measured.
	if err := c.Advance(ctx, "hk", 2); err != nil {
		t.Fatalf("Advance: %v", err)
	}
	if _, err := c.Loss(ctx, "hk"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Loss after Advance read the old SA's state: %v", err)
	}

	n.states = []XfrmState{{SPI: spi, IfID: 7, Packets: 3}}
	ike.mu.Lock()
	ike.sas[0].Children[0].SPIIn = fmt.Sprintf("%08x", spi)
	ike.mu.Unlock()
	if _, err := c.Loss(ctx, "hk"); !errors.Is(err, ErrLossUnavailable) {
		t.Fatalf("Loss on an ESN-replay state = %v, want ErrLossUnavailable", err)
	}
}

func TestClient_LossErrors(t *testing.T) {
	c, ike, n, _ := lossClient(t)
	ctx := context.Background()
	if _, err := c.Loss(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Loss of an unknown gateway = %v", err)
	}
	n.setErr("xfrm-states", errors.New("netlink down"))
	if _, err := c.Loss(ctx, "hk"); err == nil {
		t.Fatal("Loss hid a netlink error")
	}
	ike.mu.Lock()
	ike.sas[0].Children[0].SPIIn = "not-hex"
	ike.mu.Unlock()
	if _, err := c.Loss(ctx, "hk"); err == nil {
		t.Fatal("Loss accepted an unparseable SPI")
	}
	ike.mu.Lock()
	ike.sas[0].Children[0].State = ChildStateRekeyed
	ike.mu.Unlock()
	if _, err := c.Loss(ctx, "hk"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Loss with no installed child = %v", err)
	}
	ike.addSA(IKESA{Name: "other", State: IKEStateEstablished, Children: []ChildSA{{State: ChildStateInstalled}}})
	ike.setErr("list", errors.New("down"))
	if _, err := c.Loss(ctx, "hk"); err == nil {
		t.Fatal("Loss hid a query error")
	}
}

func TestGateway_BackboneLoss(t *testing.T) {
	g, ike, n := startedGateway(t, nil)
	ctx := context.Background()
	if _, err := g.BackboneLoss(ctx, "gw-c"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("BackboneLoss of an unknown peer = %v", err)
	}
	if err := g.AddBackbone(ctx, testBackbone("gw-c", 11, "203.0.113.3")); err != nil {
		t.Fatalf("AddBackbone: %v", err)
	}
	if err := ike.Initiate(ctx, "egressa-bb-gw-c", "egressa-bb-gw-c-e1"); err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	sas, _ := ike.ListSAs(ctx, "egressa-bb-gw-c")
	spi := parseSPI(t, sas[0].Children[0].SPIIn)
	n.states = []XfrmState{{SPI: spi, IfID: 11, ReplaySeq: 9, Packets: 9, HasReplay: true}}
	if l, err := g.BackboneLoss(ctx, "gw-c"); err != nil || l.Lost != 0 || l.Received != 9 {
		t.Fatalf("BackboneLoss = %+v, %v", l, err)
	}
}
