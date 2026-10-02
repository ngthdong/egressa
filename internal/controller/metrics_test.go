package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/control"
	"github.com/ngthdong/egressa/internal/telemetry"
)

func scrapeBody(t *testing.T, reg *telemetry.Registry) string {
	t.Helper()
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	return rec.Body.String()
}

func hasLine(body, line string) bool {
	for _, l := range strings.Split(body, "\n") {
		if l == line {
			return true
		}
	}
	return false
}

func TestMetrics_MigrationsAndRoutes(t *testing.T) {
	reg := telemetry.NewRegistry("controller", "dev", "unknown")
	srv, err := New(context.Background(), Config{
		Store: control.NewMemStore(), GatewayToken: "gw-token", ClientToken: "cl-token",
		Network: testNetwork, Logger: telemetry.Discard(), Metrics: telemetry.NewControllerMetrics(reg),
	})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	gw, _ := api.NewClient(hs.URL, "gw-token")
	cl, _ := api.NewClient(hs.URL, "cl-token")
	e := &testEnv{srv: srv, gw: gw, cl: cl, url: hs.URL}
	ctx := context.Background()
	e.register(t, "hk", both, "192.0.2.11:51820")
	e.register(t, "sg", both, "192.0.2.12:51820")
	resp, err := cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: pubKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	id, secret := resp.Session.ID, resp.Secret
	if _, err := cl.Migrate(ctx, id, secret, api.MigrateRequest{Epoch: 1, Access: "sg", Egress: "hk"}); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Migrate(ctx, id, secret, api.MigrateRequest{Epoch: 1, Access: "hk", Egress: "hk"}); !errors.Is(err, api.ErrConflict) {
		t.Fatalf("stale migrate: %v", err)
	}
	if _, err := cl.Migrate(ctx, id, secret, api.MigrateRequest{Epoch: 2, Access: "nope", Egress: "hk"}); err == nil {
		t.Fatal("bad access accepted")
	}
	if _, err := cl.ClientState(ctx, id, secret, 0, 0); err != nil {
		t.Fatal(err)
	}
	srv.publish(ctx)

	body := scrapeBody(t, reg)
	for _, line := range []string{
		`egressa_controller_migrations_total{result="committed"} 1`,
		`egressa_controller_migrations_total{result="conflict"} 1`,
		`egressa_controller_migrations_total{result="rejected"} 1`,
		`egressa_controller_migrations_total{result="error"} 0`,
		`egressa_controller_http_requests_total{code="200",route="POST /v1/sessions/{id}/migrate"} 1`,
		`egressa_controller_http_requests_total{code="409",route="POST /v1/sessions/{id}/migrate"} 1`,
		`egressa_controller_http_requests_total{code="400",route="POST /v1/sessions/{id}/migrate"} 1`,
		`egressa_controller_http_requests_total{code="200",route="GET /v1/sessions/{id}/state"} 1`,
		`egressa_controller_http_request_duration_seconds_count{route="POST /v1/sessions/{id}/migrate"} 3`,
		`egressa_controller_gateways{alive="true"} 2`,
		`egressa_controller_gateways{alive="false"} 0`,
		`egressa_controller_sessions 1`,
	} {
		if !hasLine(body, line) {
			t.Errorf("missing %s", line)
		}
	}
	if strings.Contains(body, `route="GET /v1/sessions/{id}/state"`) && strings.Contains(body, `http_request_duration_seconds_count{route="GET /v1/sessions/{id}/state"}`) {
		t.Error("a long poll was timed")
	}
	if strings.Contains(body, id) || strings.Contains(body, secret) {
		t.Error("a session ID or secret reached the metrics")
	}
}

func TestTrace_MigrateSpans(t *testing.T) {
	var buf bytes.Buffer
	l, err := telemetry.NewLogger(telemetry.LogConfig{Writer: &buf, Format: telemetry.FormatJSON, Role: "controller", Version: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(context.Background(), Config{
		Store: control.NewMemStore(), GatewayToken: "gw-token", ClientToken: "cl-token",
		Network: testNetwork, Logger: l, Tracer: telemetry.NewTracer(l, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	gw, _ := api.NewClient(hs.URL, "gw-token")
	cl, _ := api.NewClient(hs.URL, "cl-token")
	e := &testEnv{srv: srv, gw: gw, cl: cl, url: hs.URL}
	ctx := context.Background()
	e.register(t, "hk", both, "192.0.2.11:51820")
	e.register(t, "sg", both, "192.0.2.12:51820")
	resp, err := cl.CreateSession(ctx, api.CreateSessionRequest{PublicKey: pubKey(t)})
	if err != nil {
		t.Fatal(err)
	}
	id := resp.Session.ID
	_, _ = cl.Migrate(ctx, id, resp.Secret, api.MigrateRequest{Epoch: 1, Access: "sg", Egress: "hk"})   // ok -> epoch 2
	_, _ = cl.Migrate(ctx, id, resp.Secret, api.MigrateRequest{Epoch: 1, Access: "hk", Egress: "hk"})   // loses: targets 2
	_, _ = cl.Migrate(ctx, id, resp.Secret, api.MigrateRequest{Epoch: 2, Access: "nope", Egress: "hk"}) // rejected: targets 3

	var spans []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not JSON: %q", line)
		}
		if m["span"] == "migration.cas" {
			spans = append(spans, m)
		}
	}
	if len(spans) != 3 {
		t.Fatalf("%d migration.cas spans, want 3:\n%s", len(spans), buf.String())
	}
	for i, want := range []struct {
		status string
		trace  string
	}{
		{"ok", telemetry.MigrationTraceID(id, 2)},
		{"conflict", telemetry.MigrationTraceID(id, 2)}, // the losing attempt joins the trace it aimed at
		{"error", telemetry.MigrationTraceID(id, 3)},
	} {
		if spans[i]["status"] != want.status || spans[i]["trace_id"] != want.trace || spans[i]["session"] != id {
			t.Errorf("span %d: %v, want status %s trace %s", i, spans[i], want.status, want.trace)
		}
	}
	if strings.Contains(buf.String(), resp.Secret) || strings.Contains(buf.String(), "cl-token") || strings.Contains(buf.String(), "gw-token") {
		t.Error("a secret or token reached the logs")
	}
}
