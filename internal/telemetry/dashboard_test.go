package telemetry

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

const dashboardPath = "../../deploy/observability/grafana/dashboards/egressa.json"

// promqlWords are the PromQL functions, aggregations and keywords the
// dashboard may use, and Prometheus's own `up`: every other word in an
// expression must be a metric docs/metrics.md lists.
var promqlWords = []string{
	"up",
	"sum", "min", "max", "avg", "count", "count_values", "topk", "bottomk",
	"rate", "irate", "increase", "changes", "resets", "delta",
	"histogram_quantile", "round", "clamp_min", "clamp_max", "abs", "time",
	"max_over_time", "min_over_time", "avg_over_time", "last_over_time",
	"by", "without", "on", "ignoring", "group_left", "group_right",
	"and", "or", "unless", "bool", "offset",
}

var (
	// Parts of an expression that hold no metric names: label matchers,
	// range selectors, quoted strings, and the label lists of by, on and
	// the like.
	matchersRE = regexp.MustCompile(`\{[^}]*\}|\[[^\]]*\]|"[^"]*"|\b(by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)`)
	// label_values(metric, label): the label is not a metric.
	labelValuesRE = regexp.MustCompile(`label_values\(\s*([^,()]+),[^)]*\)`)
	wordRE        = regexp.MustCompile(`[a-zA-Z_:][a-zA-Z0-9_:]*`)
	// Series a histogram exports besides its own name.
	histogramSuffixRE = regexp.MustCompile(`_(bucket|sum|count)$`)
)

// dashboardExprs returns every PromQL expression in the dashboard: panel
// targets, annotations and the template variables' queries.
func dashboardExprs(t *testing.T, d map[string]any) []string {
	t.Helper()
	var exprs []string
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, x := range v {
				if s, ok := x.(string); ok && (k == "expr" || k == "definition") {
					exprs = append(exprs, s)
				}
				walk(x)
			}
		case []any:
			for _, x := range v {
				walk(x)
			}
		}
	}
	walk(d)
	return exprs
}

func TestDashboardUsesDocumentedMetrics(t *testing.T) {
	data, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("%s is not JSON: %v", dashboardPath, err)
	}
	docs := documentedMetrics(t)
	exprs := dashboardExprs(t, d)
	if len(exprs) < 20 {
		t.Fatalf("only %d expressions in the dashboard", len(exprs))
	}
	used := map[string]bool{}
	for _, e := range exprs {
		for _, w := range wordRE.FindAllString(matchersRE.ReplaceAllString(labelValuesRE.ReplaceAllString(e, "$1"), " "), -1) {
			if slices.Contains(promqlWords, w) {
				continue
			}
			name := w
			if !slices.Contains(docs, name) {
				name = histogramSuffixRE.ReplaceAllString(w, "")
			}
			if !slices.Contains(docs, name) {
				t.Errorf("the dashboard uses %q, which docs/metrics.md does not list (in %s)", w, e)
				continue
			}
			used[name] = true
		}
	}

	// What the dashboard must show, by the metrics that carry it.
	for _, want := range []string{
		"egressa_client_segment_rtt_seconds",        // RTT and jitter per path
		"egressa_client_segment_loss_ratio",         // loss per path
		"egressa_client_path_cost_seconds",          // cost per path
		"egressa_client_path_delta_lower_seconds",   // LCB(Δ)
		"egressa_client_decision_threshold_seconds", // against the margin
		"egressa_client_active_path",                // active gateway
		"egressa_client_path_reachable",             // warm standbys
		"egressa_client_session_epoch",              // migrations, epoch
		"egressa_client_migration_duration_seconds", // and duration
		"egressa_client_decisions_total",            // flap guard, outcomes
		"egressa_gateway_backbone_rtt_seconds",      // backbone RTT
		"egressa_gateway_backbone_loss_ratio",       // loss
		"egressa_gateway_backbone_up",               // and state
		"egressa_controller_gateways",               // members
		"egressa_controller_migrations_total",       // CAS conflicts
	} {
		if !used[want] {
			t.Errorf("the dashboard does not use %s", want)
		}
	}

	// A client variable, and migrations as annotations.
	tmpl, _ := d["templating"].(map[string]any)
	vars, _ := tmpl["list"].([]any)
	if len(vars) == 0 || vars[0].(map[string]any)["name"] != "client" {
		t.Errorf("no client variable: %v", vars)
	}
	ann, _ := d["annotations"].(map[string]any)
	var names []string
	for _, a := range ann["list"].([]any) {
		names = append(names, a.(map[string]any)["name"].(string))
	}
	if !slices.Contains(names, "Migrations") || !slices.Contains(names, "Migration duration") {
		t.Errorf("annotations %v", names)
	}
	// Every query goes to the provisioned data source.
	prov, err := os.ReadFile("../../deploy/observability/grafana/provisioning/datasources/prometheus.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(prov), "uid: egressa-prometheus") || strings.Count(string(data), `"uid": "egressa-prometheus"`) < len(exprs) {
		t.Error("the dashboard's queries do not all use the provisioned data source egressa-prometheus")
	}
}
