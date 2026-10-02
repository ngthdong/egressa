//go:build linux

package e2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	"github.com/prometheus/client_golang/prometheus/testutil/promlint"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/telemetry"
)

// metricsURLs is where each process serves /metrics in the test.
var metricsURLs = map[string]string{
	"controller": "http://" + ctlAddr + ":9100/metrics",
	"gateway-hk": "http://" + hkWAN + ":9100/metrics",
	"gateway-sg": "http://" + sgWAN + ":9100/metrics",
	"client":     "http://" + cliWAN + ":9100/metrics",
}

// scrapeMetrics fetches a /metrics page, fails the test on any promlint
// problem, and parses it.
func scrapeMetrics(t *testing.T, name string) map[string]*dto.MetricFamily {
	t.Helper()
	c := http.Client{Timeout: 10 * time.Second}
	resp, err := c.Get(metricsURLs[name])
	if err != nil {
		t.Fatalf("scrape %s: %v", name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("scrape %s: %d, %v", name, resp.StatusCode, err)
	}
	problems, err := promlint.New(bytes.NewReader(body)).Lint()
	if err != nil {
		t.Fatalf("lint %s: %v", name, err)
	}
	for _, p := range problems {
		t.Errorf("%s /metrics: promlint: %s: %s", name, p.Metric, p.Text)
	}
	p := expfmt.NewTextParser(model.UTF8Validation)
	mfs, err := p.TextToMetricFamilies(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("parse %s /metrics: %v", name, err)
	}
	return mfs
}

// sum adds up the series of metric name whose labels include match.
func sum(mfs map[string]*dto.MetricFamily, name string, match map[string]string) (float64, int) {
	var total float64
	n := 0
	for _, m := range mfs[name].GetMetric() {
		labels := map[string]string{}
		for _, l := range m.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		ok := true
		for k, v := range match {
			ok = ok && labels[k] == v
		}
		if !ok {
			continue
		}
		n++
		if c := m.GetCounter(); c != nil {
			total += c.GetValue()
		} else {
			total += m.GetGauge().GetValue()
		}
	}
	return total, n
}

// readJSONLog parses every line of a process's log; with --log-format
// json, a line that is not a JSON object is a bug.
func readJSONLog(t *testing.T, dir, name string) []map[string]any {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, name+".log"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Errorf("%s: a log line is not JSON: %q", name, sc.Text())
			continue
		}
		out = append(out, rec)
	}
	return out
}

// checkTelemetry checks what the processes reported about the run: final
// is the session as the controller has it after every phase, and every
// epoch from 2 to final.Epoch is one migration.
func checkTelemetry(t *testing.T, dir, sessionID string, final api.Session) {
	t.Helper()
	moves := float64(final.Epoch - 1)

	// 4. Every /metrics passes promlint (scrapeMetrics fails on any problem).
	ctl := scrapeMetrics(t, "controller")
	hk := scrapeMetrics(t, "gateway-hk")
	sg := scrapeMetrics(t, "gateway-sg")

	// 2. The client's active path is the one the controller reports. Its
	// gauges come from the decision pass after the last move, at most
	// 500 ms later.
	var cli map[string]*dto.MetricFamily
	deadline := time.Now().Add(10 * time.Second)
	for {
		cli = scrapeMetrics(t, "client")
		active, _ := sum(cli, "egressa_client_active_path", map[string]string{"access": final.Access, "egress": final.Egress})
		all, _ := sum(cli, "egressa_client_active_path", nil)
		epoch, _ := sum(cli, "egressa_client_session_epoch", nil)
		if active == 1 && all == 1 && epoch == float64(final.Epoch) {
			t.Logf("telemetry: client active_path{access=%q,egress=%q} = 1 and session_epoch = %d, as the controller says",
				final.Access, final.Egress, final.Epoch)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("client active path %v (sum of all %v), epoch %v; the controller says %s/%s at epoch %d",
				active, all, epoch, final.Access, final.Egress, final.Epoch)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// 1. Committed migrations: client and controller agree with the epochs.
	clientCommitted, _ := sum(cli, "egressa_client_migrations_total", map[string]string{"result": "committed"})
	ctlCommitted, _ := sum(ctl, "egressa_controller_migrations_total", map[string]string{"result": "committed"})
	if clientCommitted != moves || ctlCommitted != moves {
		t.Errorf("committed migrations: client %v, controller %v; the epoch rose %v times", clientCommitted, ctlCommitted, moves)
	} else {
		t.Logf("telemetry: client and controller each count %v committed migrations, as many as the epoch rose", moves)
	}
	if v, _ := sum(cli, "egressa_client_controller_up", nil); v != 1 {
		t.Errorf("client controller_up = %v", v)
	}
	for name, mfs := range map[string]map[string]*dto.MetricFamily{"hk": hk, "sg": sg} {
		peer := map[string]string{"hk": "sg", "sg": "hk"}[name]
		if v, n := sum(mfs, "egressa_gateway_backbone_up", map[string]string{"peer": peer}); v != 1 || n != 1 {
			t.Errorf("%s backbone_up{peer=%q} = %v (%d series)", name, peer, v, n)
		}
	}

	// 3. Every migration's spans, in all four processes, share its trace.
	logs := map[string][]map[string]any{}
	for _, name := range []string{"client", "controller", "gateway-hk", "gateway-sg"} {
		logs[name] = readJSONLog(t, dir, name)
	}
	want := map[string][]string{
		"client":     {"migration.decide", "migration.commit", "migration.switch"},
		"controller": {"migration.cas"},
		"gateway-hk": {"migration.apply"},
		"gateway-sg": {"migration.apply"},
	}
	for epoch := uint64(2); epoch <= final.Epoch; epoch++ {
		trace := telemetry.MigrationTraceID(sessionID, epoch)
		for name, spans := range want {
			for _, span := range spans {
				found := false
				for _, rec := range logs[name] {
					if rec["trace_id"] == trace && rec["span"] == span {
						found = true
						if rec["status"] != "ok" {
							t.Errorf("epoch %d: %s's %s ended %v: %v", epoch, name, span, rec["status"], rec["err"])
						}
						break
					}
				}
				if !found {
					t.Errorf("epoch %d (trace %s): no %s span in %s's log", epoch, trace, span, name)
				}
			}
		}
	}
	if !t.Failed() {
		t.Logf("telemetry: each of the %v migrations has decide/commit/switch spans in the client, cas in the controller and apply in both gateways, under one trace ID", moves)
	}
	// Records carry who wrote them.
	for name, role := range map[string]string{"client": "client", "controller": "controller", "gateway-hk": "gateway"} {
		if len(logs[name]) == 0 || logs[name][0]["role"] != role || logs[name][0]["version"] == nil {
			t.Errorf("%s's first record lacks role %q or version: %v", name, role, logs[name])
		}
	}
	if logs["gateway-hk"][0]["node"] != "hk" {
		t.Errorf("gateway-hk's records lack node=hk")
	}
}
