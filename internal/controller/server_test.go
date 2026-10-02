package controller

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/control"
	"github.com/ngthdong/egressa/internal/measurement"
	"github.com/ngthdong/egressa/internal/tunnel"
)

var testNetwork = api.Network{
	ClientSubnet: netip.MustParsePrefix("10.201.0.0/16"),
	NodeSubnet:   netip.MustParsePrefix("10.200.0.0/24"),
	ProbePort:    51900,
}

type testEnv struct {
	srv    *Server
	gw, cl *api.Client
	url    string
}

func newEnv(t *testing.T, store control.KVStore) *testEnv {
	t.Helper()
	if store == nil {
		store = control.NewMemStore()
	}
	srv, err := New(context.Background(), Config{
		Store: store, GatewayToken: "gw-token", ClientToken: "cl-token",
		Network: testNetwork, Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	gw, _ := api.NewClient(hs.URL, "gw-token")
	cl, _ := api.NewClient(hs.URL, "cl-token")
	return &testEnv{srv: srv, gw: gw, cl: cl, url: hs.URL}
}

func pubKey(t *testing.T) string {
	t.Helper()
	kp, err := tunnel.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return tunnel.Base64(kp.Public)
}

func (e *testEnv) register(t *testing.T, id string, roles api.Roles, endpoint string) api.RegisterGatewayResponse {
	t.Helper()
	resp, err := e.gw.RegisterGateway(context.Background(), id, api.RegisterGatewayRequest{
		Roles: roles, Endpoint: endpoint, PublicKey: pubKey(t),
	})
	if err != nil {
		t.Fatalf("register %s: %v", id, err)
	}
	return resp
}

const both = control.RoleAccess | control.RoleEgress

func statusCode(err error) int {
	var se *api.StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}

func TestNew_Validates(t *testing.T) {
	ctx := context.Background()
	if _, err := New(ctx, Config{Network: testNetwork}); err == nil {
		t.Error("accepted a nil store")
	}
	bad := testNetwork
	bad.NodeSubnet = netip.MustParsePrefix("10.201.5.0/24")
	if _, err := New(ctx, Config{Store: control.NewMemStore(), Network: bad}); err == nil {
		t.Error("accepted overlapping subnets")
	}
	if _, err := New(ctx, Config{Store: control.NewMemStore(), Network: api.Network{}}); err == nil {
		t.Error("accepted an empty network")
	}
	pol := control.DefaultPolicyDocument
	pol.Version = 7
	store := control.NewMemStore()
	if _, err := New(ctx, Config{Store: store, Network: testNetwork, Policy: &pol}); err != nil {
		t.Fatal(err)
	}
	if got, _ := control.NewPolicyService(store).Get(ctx); got.Version != 7 {
		t.Errorf("stored policy version %d, want 7", got.Version)
	}
}

func TestRegisterGateway(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	hk := e.register(t, "hk", both, "192.0.2.11:51820")
	sg := e.register(t, "sg", control.RoleAccess, "192.0.2.12:51820")
	if hk.NodeIP != netip.MustParseAddr("10.200.0.2") || sg.NodeIP != netip.MustParseAddr("10.200.0.3") {
		t.Fatalf("node IPs %s, %s", hk.NodeIP, sg.NodeIP)
	}
	if hk.Network != testNetwork {
		t.Errorf("network %+v", hk.Network)
	}
	again := e.register(t, "hk", both, "192.0.2.99:51820")
	if again.NodeIP != hk.NodeIP {
		t.Errorf("re-register moved the node IP to %s", again.NodeIP)
	}
	st, err := e.gw.GatewayState(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Gateways) != 2 || st.Gateways[0].ID != "hk" || st.Gateways[0].Endpoint != "192.0.2.99:51820" || !st.Gateways[0].Alive {
		t.Fatalf("gateways %+v", st.Gateways)
	}

	bad, _ := api.NewClient(e.url, "wrong")
	if _, err := bad.RegisterGateway(ctx, "x", api.RegisterGatewayRequest{}); statusCode(err) != http.StatusUnauthorized {
		t.Errorf("wrong token: %v", err)
	}
	for name, req := range map[string]api.RegisterGatewayRequest{
		"endpoint": {Roles: both, Endpoint: "nope", PublicKey: pubKey(t)},
		"key":      {Roles: both, Endpoint: "192.0.2.1:1", PublicKey: "short"},
		"roles":    {Endpoint: "192.0.2.1:1", PublicKey: pubKey(t)},
	} {
		if _, err := e.gw.RegisterGateway(ctx, "ok", req); statusCode(err) != http.StatusBadRequest {
			t.Errorf("bad %s: %v", name, err)
		}
	}
	if _, err := e.gw.RegisterGateway(ctx, "Bad_ID", api.RegisterGatewayRequest{Roles: both, Endpoint: "192.0.2.1:1", PublicKey: pubKey(t)}); statusCode(err) != http.StatusBadRequest {
		t.Errorf("bad id: %v", err)
	}
}

func TestSessions_OpenReopenMigrate(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	key := pubKey(t)
	if _, err := e.cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: key}); statusCode(err) != http.StatusServiceUnavailable {
		t.Fatalf("with no gateways: %v", err)
	}
	e.register(t, "hk", both, "192.0.2.11:51820")
	e.register(t, "sg", both, "192.0.2.12:51820")
	e.register(t, "eu", control.RoleEgress, "192.0.2.13:51820")

	resp, err := e.cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: key, Egress: "sg"})
	if err != nil {
		t.Fatal(err)
	}
	s := resp.Session
	if s.Access != "sg" || s.Egress != "sg" || s.Epoch != 1 || s.VirtualIP != netip.MustParseAddr("10.201.0.2") || resp.Secret == "" {
		t.Fatalf("session %+v", resp)
	}
	// An egress-only gateway gets the first access gateway as access.
	other, err := e.cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: pubKey(t), Egress: "eu"})
	if err != nil || other.Session.Access != "hk" || other.Session.VirtualIP != netip.MustParseAddr("10.201.0.3") {
		t.Fatalf("egress-only: %+v, %v", other, err)
	}
	if _, err := e.cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: pubKey(t), Egress: "nope"}); statusCode(err) != http.StatusServiceUnavailable {
		t.Errorf("unknown egress: %v", err)
	}

	if _, err := e.cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: key}); statusCode(err) != http.StatusConflict {
		t.Errorf("reopen without the secret: %v", err)
	}
	again, err := e.cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: key, Secret: resp.Secret})
	if err != nil || again.Session != s {
		t.Fatalf("reopen: %+v, %v", again.Session, err)
	}

	moved, err := e.cl.Migrate(ctx, s.ID, resp.Secret, api.MigrateRequest{Epoch: 1, Access: "hk", Egress: "sg"})
	if err != nil || moved.Access != "hk" || moved.Egress != "sg" || moved.Epoch != 2 {
		t.Fatalf("migrate: %+v, %v", moved, err)
	}
	_, err = e.cl.Migrate(ctx, s.ID, resp.Secret, api.MigrateRequest{Epoch: 1, Access: "sg", Egress: "sg"})
	var conflict *api.ConflictError
	if !errors.As(err, &conflict) || conflict.Current.Epoch != 2 || conflict.Current.Access != "hk" || !errors.Is(err, api.ErrConflict) {
		t.Fatalf("stale migrate: %v", err)
	}
	if _, err := e.cl.Migrate(ctx, s.ID, resp.Secret, api.MigrateRequest{Epoch: 2, Access: "eu", Egress: "sg"}); statusCode(err) != http.StatusBadRequest {
		t.Errorf("egress-only gateway as access: %v", err)
	}
	if _, err := e.cl.Migrate(ctx, s.ID, resp.Secret, api.MigrateRequest{Epoch: 2, Access: "hk", Egress: "nope"}); statusCode(err) != http.StatusBadRequest {
		t.Errorf("unknown egress: %v", err)
	}
	if _, err := e.cl.Migrate(ctx, s.ID, "wrong", api.MigrateRequest{Epoch: 2, Access: "hk", Egress: "sg"}); statusCode(err) != http.StatusUnauthorized {
		t.Errorf("wrong secret: %v", err)
	}
	if _, err := e.cl.ClientState(ctx, "12345", resp.Secret, 0, 0); statusCode(err) != http.StatusUnauthorized {
		t.Errorf("unknown session: %v", err)
	}

	st, err := e.gw.GatewayState(ctx, 0, 0)
	if err != nil || len(st.Sessions) != 2 {
		t.Fatalf("gateway state: %+v, %v", st, err)
	}
	cs, err := e.cl.ClientState(ctx, s.ID, resp.Secret, 0, 0)
	if err != nil || cs.Session.Epoch != 2 || len(cs.Gateways) != 3 || cs.Policy.Cost != measurement.DefaultCostWeights {
		t.Fatalf("client state: %+v, %v", cs, err)
	}
}

func TestLongPoll(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.register(t, "hk", both, "192.0.2.11:51820")
	st, err := e.gw.GatewayState(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	same, err := e.gw.GatewayState(ctx, st.Version, 200*time.Millisecond)
	if err != nil || same.Version != st.Version || time.Since(start) < 150*time.Millisecond {
		t.Fatalf("idle poll returned %d after %s: %v", same.Version, time.Since(start), err)
	}

	go func() {
		time.Sleep(100 * time.Millisecond)
		e.register(t, "sg", both, "192.0.2.12:51820")
	}()
	start = time.Now()
	next, err := e.gw.GatewayState(ctx, st.Version, 10*time.Second)
	if err != nil || next.Version <= st.Version || len(next.Gateways) != 2 {
		t.Fatalf("poll: %+v, %v", next, err)
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("a change took %s to wake the poll", time.Since(start))
	}
}

func TestLinksAndLiveness(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	e.register(t, "hk", both, "192.0.2.11:51820")
	e.register(t, "sg", both, "192.0.2.12:51820")
	resp, err := e.cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: pubKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	stats := measurement.SegmentStats{P50Micros: 1500, N: 30, Confidence: 0.6}
	if err := e.gw.ReportLinks(ctx, "sg", api.LinkReport{Links: []api.Link{{From: "spoofed", To: "hk", Stats: stats}}}); err != nil {
		t.Fatal(err)
	}
	if err := e.gw.ReportLinks(ctx, "nope", api.LinkReport{}); statusCode(err) != http.StatusNotFound {
		t.Errorf("unregistered gateway: %v", err)
	}
	cs, err := e.cl.ClientState(ctx, resp.Session.ID, resp.Secret, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.Links) != 1 || cs.Links[0].From != "sg" || cs.Links[0].To != "hk" || cs.Links[0].Stats != stats || cs.Links[0].Staleness < 0 {
		t.Fatalf("links %+v", cs.Links)
	}

	// Time passes with no report from either gateway.
	later := time.Now().Add(time.Minute)
	e.srv.now = func() time.Time { return later }
	before := cs.Version
	e.srv.sweep()
	cs, err = e.cl.ClientState(ctx, resp.Session.ID, resp.Secret, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Version <= before || cs.Gateways[0].Alive || cs.Gateways[1].Alive {
		t.Fatalf("after a silent minute: version %d (was %d), gateways %+v", cs.Version, before, cs.Gateways)
	}
	if cs.Links[0].Staleness < 59*time.Second {
		t.Errorf("staleness %s", cs.Links[0].Staleness)
	}
	// Without a live egress, no new session can open.
	if _, err := e.cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: pubKey(t)}); statusCode(err) != http.StatusServiceUnavailable {
		t.Errorf("open with every gateway down: %v", err)
	}
	if err := e.gw.ReportLinks(ctx, "hk", api.LinkReport{}); err != nil {
		t.Fatal(err)
	}
	cs, _ = e.cl.ClientState(ctx, resp.Session.ID, resp.Secret, 0, 0)
	if !cs.Gateways[0].Alive {
		t.Error("a report did not bring hk back")
	}
}

func TestClientToken(t *testing.T) {
	e := newEnv(t, nil)
	bad, _ := api.NewClient(e.url, "wrong")
	if _, err := bad.CreateSession(context.Background(), api.CreateSessionRequest{PublicKey: pubKey(t)}); statusCode(err) != http.StatusUnauthorized {
		t.Errorf("wrong client token: %v", err)
	}
	if _, err := e.cl.CreateSession(context.Background(), api.CreateSessionRequest{PublicKey: "x"}); statusCode(err) != http.StatusBadRequest {
		t.Errorf("bad key: %v", err)
	}
}

func TestAllocate(t *testing.T) {
	p := netip.MustParsePrefix("10.0.0.0/30")
	a, err := allocate(p, nil)
	if err != nil || a != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("allocate = %s, %v", a, err)
	}
	if _, err := allocate(p, map[netip.Addr]bool{a: true}); err == nil {
		t.Error("handed out the broadcast address")
	}
}

func TestFileStore_SurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	fs, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, fs)
	ctx := context.Background()
	e.register(t, "hk", both, "192.0.2.11:51820")
	resp, err := e.cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: pubKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.cl.Migrate(ctx, resp.Session.ID, resp.Secret, api.MigrateRequest{Epoch: 1, Access: "hk", Egress: "hk"}); err != nil {
		t.Fatal(err)
	}

	fs2, err := OpenFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	e2 := newEnv(t, fs2)
	cs, err := e2.cl.ClientState(ctx, resp.Session.ID, resp.Secret, 0, 0)
	if err != nil || cs.Session.Epoch != 2 || cs.Session.VirtualIP != resp.Session.VirtualIP {
		t.Fatalf("after restart: %+v, %v", cs.Session, err)
	}
	// The epoch keeps fencing after a restart.
	if _, err := e2.cl.Migrate(ctx, resp.Session.ID, resp.Secret, api.MigrateRequest{Epoch: 1, Access: "hk", Egress: "hk"}); !errors.Is(err, api.ErrConflict) {
		t.Errorf("stale migrate after restart: %v", err)
	}
}

func TestOpenFileStore_Corrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := writeFile(path, "{not json"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(path); err == nil {
		t.Error("loaded a corrupt state file")
	}
}

func writeFile(path, s string) error { return os.WriteFile(path, []byte(s), 0o600) }
