//go:build linux

package ipsec

import (
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	e2eSubnet  = "10.205.0.0/24"
	e2eInner   = "10.205.0.1"
	e2eGateway = "gwb"
)

// e2eClient builds a Client in namespace a that reaches the gateway in
// namespace b. Each one gets its own name, identity, virtual IP and
// if_id, so several share the one charon in namespace a.
func e2eClient(t *testing.T, tb *testBed, ike IKE, name, id, vip, psk string, ifID uint32) (*Client, Peer) {
	t.Helper()
	c, err := NewClient(ClientConfig{
		Name: name, LocalID: id, PSK: psk,
		VirtualIP: netip.MustParseAddr(vip),
		LocalAddr: netip.MustParseAddr(addrA),
		DPDDelay:  time.Second,
	}, ike, tb.a.net)
	if err != nil {
		t.Fatalf("NewClient %s: %v", name, err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c, Peer{
		Name: e2eGateway, Addr: netip.MustParseAddr(addrB), ID: "gw-b",
		IfID: ifID, Epoch: 1,
		Prefixes: []netip.Prefix{netip.MustParsePrefix(e2eInner + "/32")},
	}
}

// ping reports whether namespace ns reaches dst from src.
func ping(t *testing.T, ns *testNS, src, dst string) (bool, string) {
	t.Helper()
	out, err := ns.run("ping", "-n", "-c", "3", "-i", "0.2", "-W", "1", "-I", src, dst)
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatalf("running ping: %v\n%s", err, out)
	}
	return err == nil, string(out)
}

// TestIPsec_Backend runs Client and Gateway against two real charons.
func TestIPsec_Backend(t *testing.T) {
	tb := newTestBed(t)
	ikeA, ikeB := tb.a.ike(t), tb.b.ike(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	gw, err := NewGateway(GatewayConfig{
		LocalID: "gw-b", LocalAddr: netip.MustParseAddr(addrB),
		ClientPSK: e2eClientPSK, BackbonePSK: e2eBackbonePSK,
		ClientSubnet: netip.MustParsePrefix(e2eSubnet),
		InnerAddr:    netip.MustParseAddr(e2eInner),
		ClientIfID:   9,
		DPDDelay:     time.Second,
	}, ikeB, tb.b.net)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	if err := gw.Start(ctx); err != nil {
		t.Fatalf("gateway Start: %v\n%s", err, tb.b.log())
	}
	t.Cleanup(func() { _ = gw.Close(context.Background()) })
	// A backbone peer in namespace a whose identity sorts first: it
	// initiates, and this gateway (backbone identity gw-b-bb) responds.
	if err := gw.AddBackbone(ctx, BackbonePeer{Name: "gwa", ID: "gw-a-bb", Addr: netip.MustParseAddr(addrA), IfID: 31, Epoch: 1}); err != nil {
		t.Fatalf("AddBackbone: %v", err)
	}

	c1, peer1 := e2eClient(t, tb, ikeA, "c1", "client-1", "10.205.0.2", e2eClientPSK, 7)

	t.Run("handshake", func(t *testing.T) {
		if err := c1.Add(ctx, peer1); err != nil {
			t.Fatalf("Add: %v\n%s\n%s", err, tb.a.log(), tb.b.log())
		}
		sas, err := ikeA.ListSAs(ctx, "c1-"+e2eGateway)
		if err != nil {
			t.Fatalf("ListSAs: %v", err)
		}
		sa, ok := FindIKE(sas, "c1-"+e2eGateway)
		if !ok || !sa.Warm() {
			t.Fatalf("SAs = %+v, want a warm standby", sas)
		}
		if sa.EncrAlg != "AES_GCM_16" || sa.PRFAlg != "PRF_HMAC_SHA2_256" || sa.DHGroup != "CURVE_25519" {
			t.Fatalf("negotiated %s/%s/%s, want AES_GCM_16/PRF_HMAC_SHA2_256/CURVE_25519", sa.EncrAlg, sa.PRFAlg, sa.DHGroup)
		}
		if len(c1.Routes()) != 0 {
			t.Fatal("a standby has routes")
		}
	})

	t.Run("wrong PSK rejected", func(t *testing.T) {
		bad, peer := e2eClient(t, tb, ikeA, "bad", "client-bad", "10.205.0.9", "not-the-client-psk-123", 8)
		err := bad.Add(ctx, peer)
		if !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("Add with a wrong PSK = %v, want ErrAuthFailed", err)
		}
		if sas, _ := ikeA.ListSAs(ctx, "bad-"+e2eGateway); len(sas) != 0 {
			t.Fatalf("a rejected Add left SAs: %+v", sas)
		}
		if out, err := tb.a.run("ip", "link", "show", "egx8"); err == nil {
			t.Fatalf("a rejected Add left its interface:\n%s", out)
		}
	})

	t.Run("client with the backbone PSK rejected", func(t *testing.T) {
		bb, peer := e2eClient(t, tb, ikeA, "bb", "client-bb", "10.205.0.10", e2eBackbonePSK, 18)
		if err := bb.Add(ctx, peer); !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("Add with the backbone PSK = %v, want ErrAuthFailed", err)
		}
	})

	t.Run("backbone accepts only the backbone PSK", func(t *testing.T) {
		// Namespace a plays the backbone peer gw-a-bb.
		peer := Connection{
			Name: "bbpeer", Epoch: 1,
			LocalAddr: netip.MustParseAddr(addrA), RemoteAddr: netip.MustParseAddr(addrB),
			LocalID: "gw-a-bb", RemoteID: "gw-b-bb",
			Auth: AuthPSK, PSK: e2eClientPSK,
			LocalTS:  []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			RemoteTS: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			IfID:     41,
		}
		secret := SharedSecret{ID: "bbpeer", PSK: e2eClientPSK, Owners: []string{"gw-a-bb", "gw-b-bb"}}
		if err := ikeA.LoadShared(ctx, secret); err != nil {
			t.Fatalf("LoadShared: %v", err)
		}
		if err := ikeA.LoadConn(ctx, peer); err != nil {
			t.Fatalf("LoadConn: %v", err)
		}
		defer func() {
			_ = ikeA.TerminateIKE(context.Background(), peer.Name)
			_ = ikeA.UnloadConn(context.Background(), peer.Name)
			_ = ikeA.UnloadShared(context.Background(), secret.ID)
		}()
		if err := ikeA.Initiate(ctx, peer.Name, ChildName(peer.Name, 1)); !errors.Is(err, ErrAuthFailed) {
			t.Fatalf("a peer presenting the client PSK = %v, want ErrAuthFailed", err)
		}
		secret.PSK = e2eBackbonePSK
		if err := ikeA.LoadShared(ctx, secret); err != nil {
			t.Fatalf("LoadShared: %v", err)
		}
		if err := ikeA.Initiate(ctx, peer.Name, ChildName(peer.Name, 1)); err != nil {
			t.Fatalf("a peer presenting the backbone PSK: %v\n%s", err, tb.b.log())
		}
		wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
		defer wcancel()
		if sa, err := gw.WaitBackbone(wctx, "gwa"); err != nil || sa.RemoteID != "gw-a-bb" {
			t.Fatalf("gateway side of the backbone = %+v, %v", sa, err)
		}
	})

	t.Run("responder accepts many clients and FenceClient is precise", func(t *testing.T) {
		c2, p2 := e2eClient(t, tb, ikeA, "c2", "client-2", "10.205.0.3", e2eClientPSK, 17)
		c3, p3 := e2eClient(t, tb, ikeA, "c3", "client-3", "10.205.0.4", e2eClientPSK, 27)
		for c, p := range map[*Client]Peer{c2: p2, c3: p3} {
			if err := c.Add(ctx, p); err != nil {
				t.Fatalf("Add: %v", err)
			}
		}
		ids := func() []string {
			sas, err := gw.Clients(ctx)
			if err != nil {
				t.Fatalf("Clients: %v", err)
			}
			var out []string
			for _, sa := range sas {
				if sa.State == IKEStateEstablished {
					out = append(out, sa.RemoteID)
				}
			}
			slices.Sort(out)
			return out
		}
		if got := ids(); !slices.Equal(got, []string{"client-1", "client-2", "client-3"}) {
			t.Fatalf("gateway clients = %v, want client-1..3 on the one %%any responder", got)
		}
		n, err := gw.FenceClient(ctx, "client-2")
		if err != nil || n != 1 {
			t.Fatalf("FenceClient = %d, %v", n, err)
		}
		if got := ids(); !slices.Equal(got, []string{"client-1", "client-3"}) {
			t.Fatalf("gateway clients after fencing client-2 = %v", got)
		}
		// The fenced client learns it from the gateway's DELETE.
		wctx, wcancel := context.WithTimeout(ctx, 20*time.Second)
		defer wcancel()
		if err := c2.WaitDown(wctx, e2eGateway); err != nil {
			t.Fatalf("fenced client never saw its SA go: %v", err)
		}
		if warm, err := c3.Warm(ctx, e2eGateway); err != nil || !warm {
			t.Fatalf("an unfenced client lost its SA: %v %v", warm, err)
		}
	})

	t.Run("ESP data path", func(t *testing.T) {
		if ok, out := ping(t, tb.a, "10.205.0.2", e2eInner); ok {
			t.Fatalf("traffic passed through a standby nobody promoted:\n%s", out)
		}
		if err := c1.Promote(ctx, e2eGateway, netip.MustParsePrefix(e2eInner+"/32")); err != nil {
			t.Fatalf("Promote: %v", err)
		}
		if ok, out := ping(t, tb.a, "10.205.0.2", e2eInner); !ok {
			if strings.Contains(out, "Protocol not supported") || strings.Contains(out, "not permitted") {
				t.Skipf("skipping: the kernel cannot carry this ESP traffic here:\n%s", out)
			}
			t.Fatalf("no traffic after Promote:\n%s\n%s", out, tb.a.log())
		}
		loss, err := c1.Loss(ctx, e2eGateway)
		if err != nil {
			t.Fatalf("Loss: %v", err)
		}
		t.Logf("inbound SA %08x: received %d, highest seq %d, lost %d", loss.SPI, loss.Received, loss.HighestSeq, loss.Lost)
		if loss.Received < 3 || loss.Lost != 0 {
			t.Fatalf("Loss = %+v, want at least the 3 echo replies and nothing lost", loss)
		}
		if err := c1.FenceBelow(ctx, e2eGateway, 2); err != nil {
			t.Fatalf("FenceBelow: %v", err)
		}
		if ok, out := ping(t, tb.a, "10.205.0.2", e2eInner); ok {
			t.Fatalf("traffic still flows after FenceBelow:\n%s", out)
		}
	})

	t.Run("DPD clears the SA when the gateway dies", func(t *testing.T) {
		c4, p4 := e2eClient(t, tb, ikeA, "c4", "client-4", "10.205.0.5", e2eClientPSK, 37)
		if err := c4.Add(ctx, p4); err != nil {
			t.Fatalf("Add: %v", err)
		}
		events, stop := ikeA.Subscribe()
		defer stop()
		tb.b.kill()
		dctx, dcancel := context.WithTimeout(ctx, 30*time.Second)
		defer dcancel()
		start := time.Now()
		if err := c4.WaitDown(dctx, e2eGateway); err != nil {
			t.Fatalf("WaitDown after killing the gateway's charon: %v\n%s", err, tb.a.log())
		}
		t.Logf("DPD cleared the SA %s after the gateway died", time.Since(start).Round(100*time.Millisecond))
		waitEvent(t, events, func(ev Event) bool {
			return ev.Kind == EventIKEUpDown && !ev.Up && ev.IKE.Name == "c4-"+e2eGateway
		})
	})
}
