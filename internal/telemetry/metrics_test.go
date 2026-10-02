package telemetry

import (
	"bytes"
	"context"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/prometheus/client_golang/prometheus/testutil/promlint"
)

// serve starts r's /metrics endpoint for the test and returns its URL.
func serve(t *testing.T, r *Registry) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	addr, err := ServeMetrics(ctx, "127.0.0.1:0", r, Discard())
	if err != nil {
		t.Fatal(err)
	}
	return "http://" + addr.String() + "/metrics"
}

// scrape fetches url, lints the exposition with promlint, and parses it.
func scrape(t *testing.T, url string) map[string]*dto.MetricFamily {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d, %v", url, resp.StatusCode, err)
	}
	problems, err := promlint.New(bytes.NewReader(body)).Lint()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Errorf("promlint: %s: %s", p.Metric, p.Text)
	}
	p := expfmt.NewTextParser(model.UTF8Validation)
	mfs, err := p.TextToMetricFamilies(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("parse the exposition: %v", err)
	}
	return mfs
}

// find returns the value of the series of mf whose labels are exactly
// labels.
func find(t *testing.T, mfs map[string]*dto.MetricFamily, name string, typ dto.MetricType, labels map[string]string) (float64, bool) {
	t.Helper()
	mf, ok := mfs[name]
	if !ok {
		return 0, false
	}
	if mf.GetType() != typ {
		t.Fatalf("%s is a %s, want %s", name, mf.GetType(), typ)
	}
	for _, m := range mf.GetMetric() {
		if len(m.GetLabel()) != len(labels) {
			continue
		}
		match := true
		for _, l := range m.GetLabel() {
			if labels[l.GetName()] != l.GetValue() {
				match = false
			}
		}
		if !match {
			continue
		}
		switch typ {
		case dto.MetricType_GAUGE:
			return m.GetGauge().GetValue(), true
		case dto.MetricType_COUNTER:
			return m.GetCounter().GetValue(), true
		case dto.MetricType_HISTOGRAM:
			return float64(m.GetHistogram().GetSampleCount()), true
		}
	}
	return 0, false
}

func expect(t *testing.T, mfs map[string]*dto.MetricFamily, name string, typ dto.MetricType, labels map[string]string, want float64) {
	t.Helper()
	got, ok := find(t, mfs, name, typ, labels)
	if !ok {
		t.Errorf("no %s%v", name, labels)
		return
	}
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("%s%v = %v, want %v", name, labels, got, want)
	}
}

func absent(t *testing.T, mfs map[string]*dto.MetricFamily, name string, typ dto.MetricType, labels map[string]string) {
	t.Helper()
	if v, ok := find(t, mfs, name, typ, labels); ok {
		t.Errorf("%s%v = %v, want no such series", name, labels, v)
	}
}

const (
	gaugeT     = dto.MetricType_GAUGE
	counterT   = dto.MetricType_COUNTER
	histogramT = dto.MetricType_HISTOGRAM
)

type L = map[string]string

func TestRegistry_BuildInfoAndRuntime(t *testing.T) {
	r := NewRegistry("gateway", "v1.2.3", "abc123")
	mfs := scrape(t, serve(t, r))
	expect(t, mfs, "egressa_build_info", gaugeT, L{"role": "gateway", "version": "v1.2.3", "commit": "abc123"}, 1)
	for _, name := range []string{"go_goroutines", "process_start_time_seconds"} {
		if _, ok := mfs[name]; !ok {
			t.Errorf("no %s from the runtime and process collectors", name)
		}
	}
	if problems, err := testutil.GatherAndLint(r.reg); err != nil || len(problems) != 0 {
		t.Errorf("lint: %v, %v", problems, err)
	}
}

func TestServeMetrics_Errors(t *testing.T) {
	if _, err := ServeMetrics(context.Background(), "127.0.0.1:0", nil, nil); err == nil {
		t.Error("served a nil registry")
	}
	if _, err := ServeMetrics(context.Background(), "256.0.0.1:bad", NewRegistry("x", "v", "c"), nil); err == nil {
		t.Error("listened on a bad address")
	}
	// Only /metrics is served, and the server stops with its context.
	ctx, cancel := context.WithCancel(context.Background())
	addr, err := ServeMetrics(ctx, "127.0.0.1:0", NewRegistry("x", "v", "c"), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get("http://" + addr.String() + "/v1/sessions")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("/v1/sessions on the metrics port: %d", resp.StatusCode)
	}
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get("http://" + addr.String() + "/metrics")
		if err != nil {
			break
		}
		_ = resp.Body.Close()
		if time.Now().After(deadline) {
			t.Fatal("the metrics server kept serving after its context ended")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A nil registry's handler answers 404.
	rec := httptest.NewRecorder()
	(*Registry)(nil).Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("nil registry handler: %d", rec.Code)
	}
}

func TestClientMetrics(t *testing.T) {
	r := NewRegistry("client", "dev", "unknown")
	m := NewClientMetrics(r)
	url := serve(t, r)

	// Before the first snapshot only the counters exist, all at zero.
	mfs := scrape(t, url)
	expect(t, mfs, "egressa_client_migrations_total", counterT, L{"cause": "external", "result": "committed"}, 0)
	absent(t, mfs, "egressa_client_session_epoch", gaugeT, L{})

	m.SetSnapshot(ClientSnapshot{
		Segments: []SegmentSample{
			{Gateway: "hk", P50Micros: 300_500, P95Micros: 310_000, LossRatio: 0.05, Confidence: 0.6, Samples: 40},
			{Gateway: "sg", Confidence: 0},
		},
		Paths: []PathSample{
			{Access: "hk", Egress: "hk", CostMicros: 320_000, Usable: true, Reachable: true},
			{Access: "sg", Egress: "hk", CostMicros: 2_000, Usable: true, Reachable: true, DeltaLowerMicros: 299_600, HasDelta: true},
			{Access: "sg", Egress: "sg", CostMicros: math.Inf(1), Usable: true, Reachable: true, DeltaLowerMicros: math.Inf(-1), HasDelta: true},
		},
		ThresholdMicros: 10_000,
		ActiveAccess:    "hk", ActiveEgress: "hk",
		Epoch: 3, CurrentDead: true, ControllerUp: true,
	})
	m.Decision(OutcomeStay)
	m.Decision(OutcomeStay)
	m.Decision(OutcomeMigrate)
	m.Decision("free text from a Reason")
	m.Migration(CauseBetterPath, ResultCommitted)
	m.Migration(CauseAccessDead, ResultConflict)
	m.MigrationDuration(CauseBetterPath, 120*time.Millisecond)

	mfs = scrape(t, url)
	expect(t, mfs, "egressa_client_segment_rtt_seconds", gaugeT, L{"gateway": "hk", "percentile": "50"}, 0.3005)
	expect(t, mfs, "egressa_client_segment_rtt_seconds", gaugeT, L{"gateway": "hk", "percentile": "95"}, 0.31)
	expect(t, mfs, "egressa_client_segment_loss_ratio", gaugeT, L{"gateway": "hk"}, 0.05)
	expect(t, mfs, "egressa_client_segment_confidence", gaugeT, L{"gateway": "hk"}, 0.6)
	// sg has no samples: its confidence (0) is exported, its RTT and loss are not.
	expect(t, mfs, "egressa_client_segment_confidence", gaugeT, L{"gateway": "sg"}, 0)
	absent(t, mfs, "egressa_client_segment_rtt_seconds", gaugeT, L{"gateway": "sg", "percentile": "50"})
	absent(t, mfs, "egressa_client_segment_loss_ratio", gaugeT, L{"gateway": "sg"})

	expect(t, mfs, "egressa_client_path_cost_seconds", gaugeT, L{"access": "hk", "egress": "hk"}, 0.32)
	expect(t, mfs, "egressa_client_path_cost_seconds", gaugeT, L{"access": "sg", "egress": "hk"}, 0.002)
	// A gated path: no +Inf cost, usable 0.
	absent(t, mfs, "egressa_client_path_cost_seconds", gaugeT, L{"access": "sg", "egress": "sg"})
	expect(t, mfs, "egressa_client_path_usable", gaugeT, L{"access": "sg", "egress": "sg"}, 0)
	expect(t, mfs, "egressa_client_path_usable", gaugeT, L{"access": "sg", "egress": "hk"}, 1)
	expect(t, mfs, "egressa_client_path_reachable", gaugeT, L{"access": "sg", "egress": "sg"}, 1)
	expect(t, mfs, "egressa_client_path_delta_lower_seconds", gaugeT, L{"access": "sg", "egress": "hk"}, 0.2996)
	absent(t, mfs, "egressa_client_path_delta_lower_seconds", gaugeT, L{"access": "sg", "egress": "sg"})
	absent(t, mfs, "egressa_client_path_delta_lower_seconds", gaugeT, L{"access": "hk", "egress": "hk"})
	expect(t, mfs, "egressa_client_decision_threshold_seconds", gaugeT, L{}, 0.01)
	expect(t, mfs, "egressa_client_active_path", gaugeT, L{"access": "hk", "egress": "hk"}, 1)
	expect(t, mfs, "egressa_client_active_path", gaugeT, L{"access": "sg", "egress": "hk"}, 0)
	expect(t, mfs, "egressa_client_session_epoch", gaugeT, L{}, 3)
	expect(t, mfs, "egressa_client_current_path_dead", gaugeT, L{}, 1)
	expect(t, mfs, "egressa_client_controller_up", gaugeT, L{}, 1)

	expect(t, mfs, "egressa_client_decisions_total", counterT, L{"outcome": "stay"}, 2)
	expect(t, mfs, "egressa_client_decisions_total", counterT, L{"outcome": "migrate"}, 1)
	expect(t, mfs, "egressa_client_decisions_total", counterT, L{"outcome": "confirming"}, 0)
	// A value outside the fixed set never becomes a label value.
	expect(t, mfs, "egressa_client_decisions_total", counterT, L{"outcome": "unknown"}, 1)
	expect(t, mfs, "egressa_client_migrations_total", counterT, L{"cause": "better_path", "result": "committed"}, 1)
	expect(t, mfs, "egressa_client_migrations_total", counterT, L{"cause": "access_dead", "result": "conflict"}, 1)
	expect(t, mfs, "egressa_client_migration_duration_seconds", histogramT, L{"cause": "better_path"}, 1)

	// hk leaves; the active path is one the snapshot does not score.
	m.SetSnapshot(ClientSnapshot{
		Segments:     []SegmentSample{{Gateway: "sg", P50Micros: 500, P95Micros: 700, Confidence: 0.5, Samples: 20}},
		Paths:        []PathSample{{Access: "sg", Egress: "sg", CostMicros: 700, Usable: true, Reachable: true}},
		ActiveAccess: "sg", ActiveEgress: "hk", Epoch: 4,
	})
	mfs = scrape(t, url)
	absent(t, mfs, "egressa_client_segment_rtt_seconds", gaugeT, L{"gateway": "hk", "percentile": "50"})
	absent(t, mfs, "egressa_client_segment_confidence", gaugeT, L{"gateway": "hk"})
	absent(t, mfs, "egressa_client_path_cost_seconds", gaugeT, L{"access": "hk", "egress": "hk"})
	absent(t, mfs, "egressa_client_active_path", gaugeT, L{"access": "hk", "egress": "hk"})
	expect(t, mfs, "egressa_client_active_path", gaugeT, L{"access": "sg", "egress": "hk"}, 1)
	expect(t, mfs, "egressa_client_active_path", gaugeT, L{"access": "sg", "egress": "sg"}, 0)
	expect(t, mfs, "egressa_client_current_path_dead", gaugeT, L{}, 0)
	// Counters keep counting across snapshots.
	expect(t, mfs, "egressa_client_decisions_total", counterT, L{"outcome": "stay"}, 2)

	if problems, err := testutil.GatherAndLint(r.reg); err != nil || len(problems) != 0 {
		t.Errorf("lint: %v, %v", problems, err)
	}
}

func TestGatewayMetrics(t *testing.T) {
	r := NewRegistry("gateway", "dev", "unknown")
	m := NewGatewayMetrics(r)
	url := serve(t, r)

	m.SetSnapshot(GatewaySnapshot{
		Backbones: []BackboneSample{
			{Peer: "sg", P50Micros: 200_000, P95Micros: 250_000, LossRatio: 0.1, Samples: 30, Up: true},
			{Peer: "jp", Up: false},
		},
		AccessSessions: 2, EgressSessions: 5, StateVersion: 17, ControllerUp: true,
	})
	for i := 0; i < 3; i++ {
		m.Fenced()
	}
	m.ApplyError()
	m.LinkReport(ReportOK)
	m.LinkReport(ReportOK)
	m.LinkReport(ReportError)

	mfs := scrape(t, url)
	expect(t, mfs, "egressa_gateway_backbone_rtt_seconds", gaugeT, L{"peer": "sg", "percentile": "50"}, 0.2)
	expect(t, mfs, "egressa_gateway_backbone_rtt_seconds", gaugeT, L{"peer": "sg", "percentile": "95"}, 0.25)
	expect(t, mfs, "egressa_gateway_backbone_loss_ratio", gaugeT, L{"peer": "sg"}, 0.1)
	expect(t, mfs, "egressa_gateway_backbone_up", gaugeT, L{"peer": "sg"}, 1)
	expect(t, mfs, "egressa_gateway_backbone_up", gaugeT, L{"peer": "jp"}, 0)
	absent(t, mfs, "egressa_gateway_backbone_rtt_seconds", gaugeT, L{"peer": "jp", "percentile": "50"})
	expect(t, mfs, "egressa_gateway_sessions", gaugeT, L{"role": "access"}, 2)
	expect(t, mfs, "egressa_gateway_sessions", gaugeT, L{"role": "egress"}, 5)
	expect(t, mfs, "egressa_gateway_state_version", gaugeT, L{}, 17)
	expect(t, mfs, "egressa_gateway_controller_up", gaugeT, L{}, 1)
	expect(t, mfs, "egressa_gateway_fenced_packets_total", counterT, L{}, 3)
	expect(t, mfs, "egressa_gateway_apply_errors_total", counterT, L{}, 1)
	expect(t, mfs, "egressa_gateway_link_reports_total", counterT, L{"result": "ok"}, 2)
	expect(t, mfs, "egressa_gateway_link_reports_total", counterT, L{"result": "error"}, 1)

	// sg is gone from the next snapshot, so from the next scrape.
	m.SetSnapshot(GatewaySnapshot{Backbones: []BackboneSample{{Peer: "jp", Up: true}}})
	mfs = scrape(t, url)
	for _, name := range []string{"egressa_gateway_backbone_up", "egressa_gateway_backbone_loss_ratio"} {
		absent(t, mfs, name, gaugeT, L{"peer": "sg"})
	}
	absent(t, mfs, "egressa_gateway_backbone_rtt_seconds", gaugeT, L{"peer": "sg", "percentile": "50"})
	expect(t, mfs, "egressa_gateway_backbone_up", gaugeT, L{"peer": "jp"}, 1)
	expect(t, mfs, "egressa_gateway_controller_up", gaugeT, L{}, 0)

	if problems, err := testutil.GatherAndLint(r.reg); err != nil || len(problems) != 0 {
		t.Errorf("lint: %v, %v", problems, err)
	}
}

func TestControllerMetrics(t *testing.T) {
	r := NewRegistry("controller", "dev", "unknown")
	m := NewControllerMetrics(r)
	url := serve(t, r)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sessions/{id}/migrate", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	})
	mux.HandleFunc("GET /v1/gateway-state", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{}")) })
	mux.HandleFunc("GET /healthz", func(http.ResponseWriter, *http.Request) {})
	h := m.Middleware(mux, "GET /v1/gateway-state")
	for _, req := range []*http.Request{
		httptest.NewRequest("POST", "/v1/sessions/8245435961501267382/migrate", strings.NewReader("{}")),
		httptest.NewRequest("POST", "/v1/sessions/1/migrate", strings.NewReader("{}")),
		httptest.NewRequest("GET", "/v1/gateway-state?after=3&wait=25000", nil),
		httptest.NewRequest("GET", "/healthz", nil),
		httptest.NewRequest("GET", "/nope/12345", nil),
	} {
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	m.Migration(MigrationCommitted)
	m.Migration(MigrationRejected)
	m.SetSnapshot(ControllerSnapshot{GatewaysAlive: 2, GatewaysDown: 1, Sessions: 4, StateVersion: 9})

	mfs := scrape(t, url)
	route := "POST /v1/sessions/{id}/migrate"
	expect(t, mfs, "egressa_controller_http_requests_total", counterT, L{"route": route, "code": "409"}, 2)
	expect(t, mfs, "egressa_controller_http_requests_total", counterT, L{"route": "GET /v1/gateway-state", "code": "200"}, 1)
	expect(t, mfs, "egressa_controller_http_requests_total", counterT, L{"route": "GET /healthz", "code": "200"}, 1)
	expect(t, mfs, "egressa_controller_http_requests_total", counterT, L{"route": "unmatched", "code": "404"}, 1)
	expect(t, mfs, "egressa_controller_http_request_duration_seconds", histogramT, L{"route": route}, 2)
	// The long poll is counted, not timed.
	absent(t, mfs, "egressa_controller_http_request_duration_seconds", histogramT, L{"route": "GET /v1/gateway-state"})
	// No URL, so no session ID, ever becomes a label value.
	for _, mf := range mfs {
		for _, mt := range mf.GetMetric() {
			for _, l := range mt.GetLabel() {
				if strings.Contains(l.GetValue(), "8245435961501267382") || strings.Contains(l.GetValue(), "/nope") {
					t.Errorf("%s has label %s=%q", mf.GetName(), l.GetName(), l.GetValue())
				}
			}
		}
	}
	expect(t, mfs, "egressa_controller_migrations_total", counterT, L{"result": "committed"}, 1)
	expect(t, mfs, "egressa_controller_migrations_total", counterT, L{"result": "rejected"}, 1)
	expect(t, mfs, "egressa_controller_migrations_total", counterT, L{"result": "conflict"}, 0)
	expect(t, mfs, "egressa_controller_gateways", gaugeT, L{"alive": "true"}, 2)
	expect(t, mfs, "egressa_controller_gateways", gaugeT, L{"alive": "false"}, 1)
	expect(t, mfs, "egressa_controller_sessions", gaugeT, L{}, 4)
	expect(t, mfs, "egressa_controller_state_version", gaugeT, L{}, 9)

	if problems, err := testutil.GatherAndLint(r.reg); err != nil || len(problems) != 0 {
		t.Errorf("lint: %v, %v", problems, err)
	}
}

func TestMetrics_NilReceivers(t *testing.T) {
	if NewClientMetrics(nil) != nil || NewGatewayMetrics(nil) != nil || NewControllerMetrics(nil) != nil {
		t.Fatal("metrics without a registry are not nil")
	}
	var c *ClientMetrics
	c.SetSnapshot(ClientSnapshot{Epoch: 1})
	c.Decision(OutcomeStay)
	c.Migration(CauseExternal, ResultCommitted)
	c.MigrationDuration(CauseExternal, time.Second)

	var g *GatewayMetrics
	g.SetSnapshot(GatewaySnapshot{})
	g.Fenced()
	g.ApplyError()
	g.LinkReport(ReportOK)

	var ctl *ControllerMetrics
	ctl.SetSnapshot(ControllerSnapshot{})
	ctl.Migration(MigrationCommitted)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	rec := httptest.NewRecorder()
	ctl.Middleware(next).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusTeapot {
		t.Errorf("a nil middleware changed the response: %d", rec.Code)
	}
}

func TestGatewayMetrics_FencedDoesNotAllocate(t *testing.T) {
	m := NewGatewayMetrics(NewRegistry("gateway", "dev", "unknown"))
	if n := testing.AllocsPerRun(1000, m.Fenced); n != 0 {
		t.Errorf("Fenced allocates %.1f times", n)
	}
	var nilM *GatewayMetrics
	if n := testing.AllocsPerRun(1000, nilM.Fenced); n != 0 {
		t.Errorf("nil Fenced allocates %.1f times", n)
	}
}

func TestStatusRecorder_FirstCodeWins(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	_, _ = rec.Write([]byte("x"))
	rec.WriteHeader(http.StatusInternalServerError)
	if rec.code != http.StatusOK {
		t.Errorf("code %d after an implicit 200", rec.code)
	}
}
