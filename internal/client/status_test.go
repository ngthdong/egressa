package client

import (
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/measurement"
)

func TestStatus_WriteReadLive(t *testing.T) {
	sess := api.Session{ID: "42", VirtualIP: netip.MustParseAddr("10.201.0.2"), Access: "sing", Egress: "sg", Epoch: 3}
	gws := []api.Gateway{{ID: "sg", Endpoint: "103.153.255.243:51820"}, {ID: "sing", Endpoint: "38.47.176.90:51820"}}
	ps := []Path{
		{Access: "sg", Egress: "sg", Segments: []measurement.SegmentStats{seg(5)}, Reachable: true},
		{Access: "sing", Egress: "sg", Segments: []measurement.SegmentStats{seg(48), seg(45)}, Reachable: true},
		{Access: "sing", Egress: "sing", Segments: []measurement.SegmentStats{{}}, Reachable: false},
	}
	dec := Decision{Evals: []PathEval{{Cost: 82_000}, {Cost: 95_900}, {Cost: math.Inf(1)}}}
	st := statusOf(sess, gws, ps, false, true, dec)
	st.Started, st.Updated = time.Now(), time.Now()

	path := filepath.Join(t.TempDir(), "run", "status.json")
	if err := writeStatus(path, st); err != nil {
		t.Fatal(err)
	}
	got, err := ReadStatus(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Egress != "sg" || got.EgressIP != "103.153.255.243" || got.Epoch != 3 || got.PID != os.Getpid() || !got.ControllerUp {
		t.Fatalf("status %+v", got)
	}
	if len(got.Paths) != 3 || got.Paths[0].CostMS != 82 || !got.Paths[0].Usable || got.Paths[0].Active ||
		!got.Paths[1].Active || got.Paths[2].Usable || got.Paths[2].CostMS != 0 {
		t.Fatalf("paths %+v", got.Paths)
	}
	if !got.Live(time.Now(), 5*time.Second) {
		t.Error("a fresh status from a live process is not live")
	}
	if got.Live(time.Now().Add(time.Minute), 5*time.Second) {
		t.Error("a stale status is live")
	}
	got.PID = 1 << 30 // no such process
	if got.Live(time.Now(), 5*time.Second) {
		t.Error("a status from a dead process is live")
	}
	if _, err := ReadStatus(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Error("read a missing status file")
	}
	if err := os.WriteFile(path, []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStatus(path); err == nil {
		t.Error("parsed a corrupt status file")
	}
}
