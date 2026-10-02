package gateway

import (
	"math/rand/v2"
	"strconv"
	"testing"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/telemetry"
	"github.com/ngthdong/egressa/pkg/wire"
)

func newAdmitAgent(t *testing.T, m *telemetry.GatewayMetrics) *Agent {
	t.Helper()
	ctl, _ := api.NewClient("http://127.0.0.1:1", "")
	a, err := New(Config{ID: "hk", Controller: ctl, Endpoint: "192.0.2.1:51820", Roles: both, Uplink: "eth0", Metrics: m, Logger: telemetry.Discard()})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// fenceTo records epochs the way apply does.
func fenceTo(a *Agent, epochs map[string]uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for s, e := range epochs {
		a.gate.Update(s, e)
	}
	a.updateFenceLocked(epochs)
}

const sessionID = 8245435961501267382 // a typical 19-digit ID

func TestAdmit_DoesNotAllocate(t *testing.T) {
	a := newAdmitAgent(t, telemetry.NewGatewayMetrics(telemetry.NewRegistry("gateway", "dev", "unknown")))
	fenceTo(a, map[string]uint64{strconv.FormatUint(sessionID, 10): 5})
	pass := wire.SessionHeader{SessionID: sessionID, Epoch: 5}
	stale := wire.SessionHeader{SessionID: sessionID, Epoch: 4}
	stranger := wire.SessionHeader{SessionID: 42, Epoch: 1}
	if !a.admit(pass) || a.admit(stale) || !a.admit(stranger) {
		t.Fatal("admit decided wrongly")
	}
	for name, h := range map[string]wire.SessionHeader{"admitted": pass, "fenced": stale, "unknown session": stranger} {
		if n := testing.AllocsPerRun(1000, func() { a.admit(h) }); n != 0 {
			t.Errorf("admit (%s) allocates %.1f times per packet", name, n)
		}
	}
}

func TestAdmit_CountsFencedPackets(t *testing.T) {
	reg := telemetry.NewRegistry("gateway", "dev", "unknown")
	m := telemetry.NewGatewayMetrics(reg)
	a := newAdmitAgent(t, m)
	fenceTo(a, map[string]uint64{"7": 3})
	for i := 0; i < 4; i++ {
		a.admit(wire.SessionHeader{SessionID: 7, Epoch: 2})
	}
	a.admit(wire.SessionHeader{SessionID: 7, Epoch: 3})
	rec := httptestScrape(t, reg)
	if !containsLine(rec, "egressa_gateway_fenced_packets_total 4") {
		t.Errorf("fenced count wrong:\n%s", rec)
	}
}

// TestAdmit_MatchesEpochGate checks the fence map decides exactly as
// control.EpochGate.Admit, which it replaces on the packet path.
func TestAdmit_MatchesEpochGate(t *testing.T) {
	a := newAdmitAgent(t, nil)
	r := rand.New(rand.NewPCG(1, 2))
	ids := []uint64{0, 1, 99, 100, sessionID, 1<<64 - 1}
	for round := 0; round < 50; round++ {
		epochs := map[string]uint64{}
		for _, id := range ids[1:] {
			if r.IntN(2) == 0 {
				epochs[strconv.FormatUint(id, 10)] = uint64(r.IntN(10))
			}
		}
		fenceTo(a, epochs)
		for _, id := range ids {
			for e := uint32(0); e < 12; e++ {
				h := wire.SessionHeader{SessionID: id, Epoch: e}
				want := id == 0 || a.gate.Admit(strconv.FormatUint(id, 10), uint64(e))
				if got := a.admit(h); got != want {
					t.Fatalf("round %d: admit(session %d, epoch %d) = %v, EpochGate says %v", round, id, e, got, want)
				}
			}
		}
	}
}
