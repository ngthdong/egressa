//go:build linux

package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

const (
	e2eClientPSK   = "client-psk-0123456789abcdef"
	e2eBackbonePSK = "backbone-psk-fedcba9876543210"
)

// TestIPsec_Vici drives ViciIKE directly against two real charons, which
// checks the vici message formats (load-conn, load-shared, list-sas,
// events, terminate) against the daemon rather than against the fake.
func TestIPsec_Vici(t *testing.T) {
	tb := newTestBed(t)
	ikeA, ikeB := tb.a.ike(t), tb.b.ike(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	responder := Connection{
		Name: "vici-resp", Epoch: 1,
		LocalAddr: netip.MustParseAddr(addrB),
		LocalID:   "gw-b", RemoteID: AnyID,
		Auth: AuthPSK, PSK: e2eClientPSK,
		LocalTS:  []netip.Prefix{netip.MustParsePrefix("10.210.0.1/32")},
		RemoteTS: []netip.Prefix{netip.MustParsePrefix("10.210.0.0/24")},
		IfID:     21,
	}
	if err := ikeB.LoadShared(ctx, SharedSecret{ID: "vici-resp", PSK: e2eClientPSK, Owners: []string{"gw-b", AnyID}}); err != nil {
		t.Fatalf("gateway LoadShared: %v", err)
	}
	if err := ikeB.LoadConn(ctx, responder); err != nil {
		t.Fatalf("gateway LoadConn: %v", err)
	}

	initiator := Connection{
		Name: "vici-init", Epoch: 4,
		LocalAddr: netip.MustParseAddr(addrA), RemoteAddr: netip.MustParseAddr(addrB),
		LocalID: "client-a", RemoteID: "gw-b",
		Auth: AuthPSK, PSK: e2eClientPSK,
		LocalTS:  []netip.Prefix{netip.MustParsePrefix("10.210.0.2/32")},
		RemoteTS: []netip.Prefix{netip.MustParsePrefix("10.210.0.1/32")},
		IfID:     11,
		DPDDelay: time.Second,
	}
	events, stopEvents := ikeA.Subscribe()
	defer stopEvents()
	if err := ikeA.LoadShared(ctx, SharedSecret{ID: "vici-init", PSK: e2eClientPSK, Owners: []string{"client-a", "gw-b"}}); err != nil {
		t.Fatalf("client LoadShared: %v", err)
	}
	if err := ikeA.LoadConn(ctx, initiator); err != nil {
		t.Fatalf("client LoadConn: %v", err)
	}
	if err := ikeA.Initiate(ctx, initiator.Name, ChildName(initiator.Name, initiator.Epoch)); err != nil {
		t.Fatalf("Initiate: %v\n%s\n%s", err, tb.a.log(), tb.b.log())
	}

	sas, err := ikeA.ListSAs(ctx, initiator.Name)
	if err != nil {
		t.Fatalf("ListSAs: %v", err)
	}
	sa, found := FindIKE(sas, initiator.Name)
	if !found || !sa.Warm() {
		t.Fatalf("after Initiate: %+v, want an established IKE_SA with an installed CHILD_SA", sas)
	}
	if sa.EncrAlg != "AES_GCM_16" || sa.PRFAlg != "PRF_HMAC_SHA2_256" || sa.DHGroup != "CURVE_25519" {
		t.Errorf("IKE algorithms = %s/%s/%s, want AES_GCM_16/PRF_HMAC_SHA2_256/CURVE_25519", sa.EncrAlg, sa.PRFAlg, sa.DHGroup)
	}
	if sa.LocalID != "client-a" || sa.RemoteID != "gw-b" || !sa.Initiator || sa.UniqueID == 0 {
		t.Errorf("IKE_SA identity = %+v", sa)
	}
	child := sa.Children[0]
	if child.Name != ChildName(initiator.Name, initiator.Epoch) || child.IfIDIn != 11 || child.IfIDOut != 11 ||
		child.SPIIn == "" || child.UniqueID == 0 || child.EncrAlg != "AES_GCM_16" {
		t.Errorf("CHILD_SA = %+v, want name %s, if_id 11 both ways, SPIs and AES_GCM_16", child, ChildName(initiator.Name, initiator.Epoch))
	}

	// The IKE_SA coming up must have been announced.
	waitEvent(t, events, func(ev Event) bool {
		return ev.Kind == EventIKEUpDown && ev.Up && ev.IKE.Name == initiator.Name
	})

	gwSAs, err := ikeB.ListSAs(ctx, responder.Name)
	if err != nil || len(gwSAs) != 1 || gwSAs[0].RemoteID != "client-a" || gwSAs[0].Initiator {
		t.Fatalf("gateway ListSAs = %+v, %v; want one responder IKE_SA from client-a", gwSAs, err)
	}

	if err := ikeA.TerminateChild(ctx, child.UniqueID); err != nil {
		t.Fatalf("TerminateChild: %v", err)
	}
	waitEvent(t, events, func(ev Event) bool {
		return ev.Kind == EventChildUpDown && !ev.Up && ev.IKE.Name == initiator.Name
	})
	if err := ikeA.TerminateIKE(ctx, initiator.Name); err != nil {
		t.Fatalf("TerminateIKE: %v", err)
	}
	waitEvent(t, events, func(ev Event) bool {
		return ev.Kind == EventIKEUpDown && !ev.Up && ev.IKE.Name == initiator.Name
	})
	if err := ikeA.TerminateIKE(ctx, initiator.Name); !errors.Is(err, ErrNotFound) {
		t.Errorf("TerminateIKE with nothing left = %v, want ErrNotFound", err)
	}

	// Wrong PSK: the gateway rejects it, and Initiate says so.
	if err := ikeA.LoadShared(ctx, SharedSecret{ID: "vici-init", PSK: "wrong-psk-0123456789", Owners: []string{"client-a", "gw-b"}}); err != nil {
		t.Fatalf("reload shared: %v", err)
	}
	err = ikeA.Initiate(ctx, initiator.Name, ChildName(initiator.Name, initiator.Epoch))
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Initiate with a wrong PSK = %v, want ErrAuthFailed\n%s", err, tb.a.log())
	}

	if err := ikeA.UnloadConn(ctx, initiator.Name); err != nil {
		t.Fatalf("UnloadConn: %v", err)
	}
	if err := ikeA.UnloadConn(ctx, initiator.Name); !errors.Is(err, ErrNotFound) {
		t.Errorf("UnloadConn twice = %v, want ErrNotFound", err)
	}
	if err := ikeA.UnloadShared(ctx, "vici-init"); err != nil {
		t.Fatalf("UnloadShared: %v", err)
	}
}

// waitEvent reads events until match accepts one.
func waitEvent(t *testing.T, events <-chan Event, match func(Event) bool) Event {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		select {
		case ev, ok := <-events:
			if !ok {
				t.Fatal("event channel closed")
			}
			if match(ev) {
				return ev
			}
		case <-deadline:
			t.Fatal("timed out waiting for the expected event")
		}
	}
}
