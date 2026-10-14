package telemetry

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// metricRowRE matches the first cell of a metric table row in
// docs/metrics.md: | `egressa_...` |
var metricRowRE = regexp.MustCompile("(?m)^\\| `(egressa_[a-z0-9_]+)` \\|")

// DocumentedMetrics returns the metric names docs/metrics.md lists.
func documentedMetrics(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("../../docs/metrics.md")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, m := range metricRowRE.FindAllStringSubmatch(string(data), -1) {
		names = append(names, m[1])
	}
	slices.Sort(names)
	return names
}

// registeredMetrics returns every egressa_* metric the three processes
// register, with each labelled series made to exist.
func registeredMetrics(t *testing.T) []string {
	t.Helper()
	r := NewRegistry("test", "v", "c")
	c := NewClientMetrics(r)
	g := NewGatewayMetrics(r)
	ctl := NewControllerMetrics(r)
	c.SetSnapshot(ClientSnapshot{
		Segments:     []SegmentSample{{Gateway: "a", Samples: 1}},
		Paths:        []PathSample{{Access: "a", Egress: "a", Usable: true, HasDelta: true}},
		ActiveAccess: "a", ActiveEgress: "a",
	})
	c.MigrationDuration(CauseBetterPath, time.Second)
	g.SetSnapshot(GatewaySnapshot{Backbones: []BackboneSample{{Peer: "b", Samples: 1}}})
	ctl.SetSnapshot(ControllerSnapshot{})
	ctl.requests.WithLabelValues("r", "200").Inc()
	ctl.duration.WithLabelValues("r").Observe(1)
	mfs, err := r.reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, mf := range mfs {
		if strings.HasPrefix(mf.GetName(), "egressa_") {
			names = append(names, mf.GetName())
		}
	}
	slices.Sort(names)
	return names
}

func TestDocsListEveryMetric(t *testing.T) {
	docs, code := documentedMetrics(t), registeredMetrics(t)
	if len(docs) == 0 {
		t.Fatal("docs/metrics.md lists no metric")
	}
	for _, n := range code {
		if !slices.Contains(docs, n) {
			t.Errorf("%s is registered but not documented in docs/metrics.md", n)
		}
	}
	for _, n := range docs {
		if !slices.Contains(code, n) {
			t.Errorf("docs/metrics.md lists %s, which no process registers", n)
		}
	}
}
