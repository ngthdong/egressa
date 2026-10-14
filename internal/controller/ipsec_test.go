package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/control"
	"github.com/ngthdong/egressa/internal/telemetry"
)

func newIPsecEnv(t *testing.T, key []byte) *testEnv {
	t.Helper()
	srv, err := New(context.Background(), Config{
		Store: control.NewMemStore(), GatewayToken: "gw-token", ClientToken: "cl-token",
		Network: testNetwork, Logger: telemetry.Discard(), IPsecKey: key,
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

func (e *testEnv) registerIPsec(t *testing.T, id string, ipsec bool) {
	t.Helper()
	if _, err := e.gw.RegisterGateway(context.Background(), id, api.RegisterGatewayRequest{
		Roles: both, Endpoint: "192.0.2.1:51820", PublicKey: pubKey(t), IPsec: ipsec,
	}); err != nil {
		t.Fatal(err)
	}
}

var pskRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func TestIPsecSessions(t *testing.T) {
	ctx := context.Background()

	// Without a master key, only WireGuard.
	plain := newIPsecEnv(t, nil)
	plain.registerIPsec(t, "hk", true)
	if _, err := plain.cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: pubKey(t), Backend: api.BackendIPsec}); statusCode(err) != http.StatusBadRequest {
		t.Errorf("IPsec session without a key: %v", err)
	}
	if _, err := plain.cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: pubKey(t), Backend: "gre"}); statusCode(err) != http.StatusBadRequest {
		t.Errorf("unknown backend: %v", err)
	}

	e := newIPsecEnv(t, []byte("master-key-for-tests"))
	e.registerIPsec(t, "hk", true)
	e.registerIPsec(t, "sg", false)

	// Egress sg takes no IPsec clients, so hk is the access.
	key := pubKey(t)
	resp, err := e.cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: key, Egress: "sg", Backend: api.BackendIPsec})
	if err != nil {
		t.Fatal(err)
	}
	s := resp.Session
	if s.Backend != api.BackendIPsec || s.Access != "hk" || s.Egress != "sg" || !pskRE.MatchString(s.IPsecPSK) {
		t.Fatalf("IPsec session %+v", s)
	}
	other, err := e.cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: pubKey(t), Backend: api.BackendIPsec})
	if err != nil {
		t.Fatal(err)
	}
	if other.Session.IPsecPSK == s.IPsecPSK {
		t.Error("two sessions share an IPsec key")
	}
	wg, err := e.cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: pubKey(t), Egress: "sg"})
	if err != nil || wg.Session.Backend != api.BackendWireGuard || wg.Session.IPsecPSK != "" || wg.Session.Access != "sg" {
		t.Fatalf("WireGuard session %+v, %v", wg.Session, err)
	}

	// Gateways see the key; a client sees its own key only.
	st, err := e.gw.GatewayState(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, gs := range st.Sessions {
		if gs.ID == s.ID && gs.IPsecPSK != s.IPsecPSK {
			t.Errorf("gateway state key %q, want the session's", gs.IPsecPSK)
		}
	}
	cs, err := e.cl.ClientState(ctx, s.ID, resp.Secret, 0, 0)
	if err != nil || cs.Session.IPsecPSK != s.IPsecPSK {
		t.Fatalf("client state: %+v, %v", cs.Session, err)
	}

	// An IPsec session cannot move its access to a gateway without IPsec.
	if _, err := e.cl.Migrate(ctx, s.ID, resp.Secret, api.MigrateRequest{Epoch: 1, Access: "sg", Egress: "sg"}); statusCode(err) != http.StatusBadRequest {
		t.Errorf("IPsec session to a WireGuard-only access: %v", err)
	}

	// Reopening with WireGuard switches the backend and drops the key.
	re, err := e.cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: key, Secret: resp.Secret})
	if err != nil || re.Session.Backend != api.BackendWireGuard || re.Session.IPsecPSK != "" || re.Session.Epoch != 1 {
		t.Fatalf("reopen as WireGuard: %+v, %v", re.Session, err)
	}
	if _, err := e.cl.Migrate(ctx, s.ID, resp.Secret, api.MigrateRequest{Epoch: 1, Access: "sg", Egress: "sg"}); err != nil {
		t.Fatalf("WireGuard session to sg: %v", err)
	}
	// Back to IPsec while on sg: the access moves to hk, the egress stays.
	re, err = e.cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: key, Secret: resp.Secret, Backend: api.BackendIPsec})
	if err != nil || re.Session.Backend != api.BackendIPsec || re.Session.Access != "hk" || re.Session.Egress != "sg" ||
		re.Session.Epoch != 3 || re.Session.IPsecPSK != s.IPsecPSK {
		t.Fatalf("reopen as IPsec from sg: %+v, %v", re.Session, err)
	}

	// The gateway list says which gateways take IPsec clients.
	gws, err := e.cl.Gateways(ctx)
	if err != nil || len(gws) != 2 || !gws[0].IPsec || gws[1].IPsec {
		t.Fatalf("gateways %+v, %v", gws, err)
	}
}

func TestIPsecNoAccessGateway(t *testing.T) {
	e := newIPsecEnv(t, []byte("k"))
	e.registerIPsec(t, "sg", false)
	_, err := e.cl.CreateSession(context.Background(), api.CreateSessionRequest{PublicKey: pubKey(t), Backend: api.BackendIPsec})
	if statusCode(err) != http.StatusServiceUnavailable {
		t.Errorf("IPsec session with no IPsec gateway: %v", err)
	}
}
