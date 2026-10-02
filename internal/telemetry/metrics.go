package telemetry

import (
	"context"
	"errors"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics follow the Prometheus conventions: times in seconds (the code
// measures microseconds; they are converted here), ratios in 0..1, and
// labels whose values come from a small fixed set or from gateway IDs.
// RTT percentiles are gauges labelled percentile="50"/"95", not
// quantile: Prometheus reserves the quantile label for summaries, and a
// summary needs a sample sum the P² estimators do not keep.
// No label ever holds a session ID, a virtual IP, a URL or an error
// message.
//
// Gauges are exported from snapshots: on each pass of its control loop
// an agent hands the latest values over as plain Go structs, and a
// collector turns the newest snapshot into metrics when Prometheus
// scrapes. A gateway that vanishes from the snapshot vanishes from the
// next scrape, with no stale series left behind and no gap between
// deleting a series and setting it again. Counters and histograms are
// recorded as events happen.

const namespace = "egressa"

// Registry holds one process's metrics. It is not the global default
// registry: each process has its own, with the Go runtime and process
// collectors and egressa_build_info.
type Registry struct {
	reg *prometheus.Registry
}

// NewRegistry returns a registry for a process of role (controller,
// gateway or client) running build version and commit.
func NewRegistry(role, version, commit string) *Registry {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	info := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace, Name: "build_info",
		Help:        "Always 1; its labels say which egressa build this process runs.",
		ConstLabels: prometheus.Labels{"role": role, "version": version, "commit": commit},
	})
	info.Set(1)
	reg.MustRegister(info)
	return &Registry{reg: reg}
}

// Handler serves the registry in the Prometheus exposition format.
func (r *Registry) Handler() http.Handler {
	if r == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
}

func (r *Registry) register(cs ...prometheus.Collector) {
	r.reg.MustRegister(cs...)
}

// ServeMetrics serves /metrics from r on addr until ctx ends, on a server
// of its own: the controller's API port may face the Internet, and
// /metrics has no authentication. It returns the address it listens on.
func ServeMetrics(ctx context.Context, addr string, r *Registry, logger *slog.Logger) (net.Addr, error) {
	if r == nil {
		return nil, errors.New("telemetry: no registry to serve")
	}
	if logger == nil {
		logger = Discard()
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", r.Handler())
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server stopped", Err(err))
		}
	}()
	logger.Info("serving metrics", "addr", ln.Addr().String())
	return ln.Addr(), nil
}

func seconds(micros float64) float64 { return micros / 1e6 }

func boolFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func finite(f float64) bool { return !math.IsInf(f, 0) && !math.IsNaN(f) }

// pick returns v if it is one of allowed, else "unknown": a label value
// is never taken from the caller unchecked.
func pick(v string, allowed []string) string {
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return "unknown"
}

func desc(name, help string, labels ...string) *prometheus.Desc {
	return prometheus.NewDesc(prometheus.BuildFQName(namespace, "", name), help, labels, nil)
}

// snapshotCollector exports the gauges of the newest snapshot.
type snapshotCollector[T any] struct {
	descs []*prometheus.Desc
	snap  *atomic.Pointer[T]
	emit  func(s *T, ch chan<- prometheus.Metric)
}

func (c snapshotCollector[T]) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range c.descs {
		ch <- d
	}
}

func (c snapshotCollector[T]) Collect(ch chan<- prometheus.Metric) {
	if s := c.snap.Load(); s != nil {
		c.emit(s, ch)
	}
}

func gauge(ch chan<- prometheus.Metric, d *prometheus.Desc, v float64, labels ...string) {
	ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, labels...)
}

// --- client ---

// Client decision outcomes, the values of egressa_client_decisions_total's
// outcome label.
const (
	OutcomeStay          = "stay"
	OutcomeConfirming    = "confirming"
	OutcomeMigrate       = "migrate"
	OutcomeNoAlternative = "no_alternative"
)

// Client migration causes and results, the values of
// egressa_client_migrations_total's labels.
const (
	CauseBetterPath   = "better_path"
	CauseAccessDead   = "access_dead"
	CauseEgressChange = "egress_change"
	CauseExternal     = "external"

	ResultCommitted = "committed"
	ResultConflict  = "conflict"
	ResultFailed    = "failed"
)

var (
	clientOutcomes = []string{OutcomeStay, OutcomeConfirming, OutcomeMigrate, OutcomeNoAlternative}
	clientCauses   = []string{CauseBetterPath, CauseAccessDead, CauseEgressChange, CauseExternal}
	clientResults  = []string{ResultCommitted, ResultConflict, ResultFailed}
)

// SegmentSample is the client's measurement of the segment to one access
// gateway, in microseconds.
type SegmentSample struct {
	Gateway    string
	P50Micros  float64
	P95Micros  float64
	LossRatio  float64
	Confidence float64
	// Samples is how many probes the stats cover; with none, RTT and
	// loss are not exported.
	Samples uint64
}

// PathSample is one candidate path as the client last scored it.
type PathSample struct {
	Access, Egress string
	// CostMicros is measurement.ScorePath's cost; exported only when
	// Usable.
	CostMicros float64
	// Usable: the cost is finite (no gate) and every segment has samples.
	Usable bool
	// Reachable: the client has heard back through Access recently and
	// every segment has been measured.
	Reachable bool
	// DeltaLowerMicros is the lower confidence bound of Cost(current) -
	// Cost(this path) from measurement.DecideMigration, when it was
	// computed and is finite.
	DeltaLowerMicros float64
	HasDelta         bool
}

// ClientSnapshot is the client's state after one decision pass.
type ClientSnapshot struct {
	Segments []SegmentSample
	Paths    []PathSample
	// ThresholdMicros is the improvement a migration must clear.
	ThresholdMicros float64
	ActiveAccess    string
	ActiveEgress    string
	Epoch           uint64
	CurrentDead     bool
	ControllerUp    bool
}

// ClientMetrics are a client's metrics. A nil *ClientMetrics records
// nothing.
type ClientMetrics struct {
	snap       atomic.Pointer[ClientSnapshot]
	decisions  *prometheus.CounterVec
	migrations *prometheus.CounterVec
	duration   *prometheus.HistogramVec
}

// NewClientMetrics registers a client's metrics in r; nil if r is nil.
func NewClientMetrics(r *Registry) *ClientMetrics {
	if r == nil {
		return nil
	}
	m := &ClientMetrics{
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "client", Name: "decisions_total",
			Help: "Decision passes, by outcome: stay, confirming (better path found, flap guard pending), migrate, no_alternative.",
		}, []string{"outcome"}),
		migrations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "client", Name: "migrations_total",
			Help: "Migrations, by cause (better_path, access_dead, egress_change, external) and result (committed, conflict, failed).",
		}, []string{"cause", "result"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "client", Name: "migration_duration_seconds",
			Help:    "Time from the decision to migrate until the new path is in use, for committed migrations.",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 14),
		}, []string{"cause"}),
	}
	for _, o := range clientOutcomes {
		m.decisions.WithLabelValues(o)
	}
	for _, c := range clientCauses {
		for _, res := range clientResults {
			m.migrations.WithLabelValues(c, res)
		}
	}

	var (
		segRTT    = desc("client_segment_rtt_seconds", "Round-trip time from the client to an access gateway: its 50th and 95th percentile.", "gateway", "percentile")
		segLoss   = desc("client_segment_loss_ratio", "Probe loss from the client to an access gateway, 0..1.", "gateway")
		segConf   = desc("client_segment_confidence", "How much the client trusts its measurement of an access gateway, 0..1.", "gateway")
		cost      = desc("client_path_cost_seconds", "Cost of a usable path: median RTT plus tail and loss penalties, summed over its segments.", "access", "egress")
		usable    = desc("client_path_usable", "1 if a path's cost is finite (no loss or capacity gate) and every segment is measured.", "access", "egress")
		reachable = desc("client_path_reachable", "1 if the client has heard back through the path's access gateway recently and every segment is measured.", "access", "egress")
		delta     = desc("client_path_delta_lower_seconds", "Lower confidence bound of the current path's cost minus this path's; above the threshold, the path is better enough to move to.", "access", "egress")
		threshold = desc("client_decision_threshold_seconds", "Improvement a migration must clear: migration cost plus safety margin.")
		active    = desc("client_active_path", "1 for the path the session is on, 0 for the others.", "access", "egress")
		epoch     = desc("client_session_epoch", "The session's epoch as the client has it.")
		dead      = desc("client_current_path_dead", "1 if the current path has stopped answering.")
		ctlUp     = desc("client_controller_up", "1 if the client's last request to the controller succeeded.")
	)
	r.register(m.decisions, m.migrations, m.duration, snapshotCollector[ClientSnapshot]{
		descs: []*prometheus.Desc{segRTT, segLoss, segConf, cost, usable, reachable, delta, threshold, active, epoch, dead, ctlUp},
		snap:  &m.snap,
		emit: func(s *ClientSnapshot, ch chan<- prometheus.Metric) {
			for _, g := range s.Segments {
				gauge(ch, segConf, g.Confidence, g.Gateway)
				if g.Samples == 0 {
					continue
				}
				gauge(ch, segRTT, seconds(g.P50Micros), g.Gateway, "50")
				gauge(ch, segRTT, seconds(g.P95Micros), g.Gateway, "95")
				gauge(ch, segLoss, g.LossRatio, g.Gateway)
			}
			activeSeen := false
			for _, p := range s.Paths {
				if p.Usable && finite(p.CostMicros) {
					gauge(ch, cost, seconds(p.CostMicros), p.Access, p.Egress)
				}
				gauge(ch, usable, boolFloat(p.Usable && finite(p.CostMicros)), p.Access, p.Egress)
				gauge(ch, reachable, boolFloat(p.Reachable), p.Access, p.Egress)
				if p.HasDelta && finite(p.DeltaLowerMicros) {
					gauge(ch, delta, seconds(p.DeltaLowerMicros), p.Access, p.Egress)
				}
				isActive := p.Access == s.ActiveAccess && p.Egress == s.ActiveEgress
				activeSeen = activeSeen || isActive
				gauge(ch, active, boolFloat(isActive), p.Access, p.Egress)
			}
			if !activeSeen && s.ActiveAccess != "" {
				gauge(ch, active, 1, s.ActiveAccess, s.ActiveEgress)
			}
			gauge(ch, threshold, seconds(s.ThresholdMicros))
			gauge(ch, epoch, float64(s.Epoch))
			gauge(ch, dead, boolFloat(s.CurrentDead))
			gauge(ch, ctlUp, boolFloat(s.ControllerUp))
		},
	})
	return m
}

// SetSnapshot replaces the snapshot the gauges are exported from.
func (m *ClientMetrics) SetSnapshot(s ClientSnapshot) {
	if m == nil {
		return
	}
	m.snap.Store(&s)
}

// Decision counts one decision pass with outcome.
func (m *ClientMetrics) Decision(outcome string) {
	if m == nil {
		return
	}
	m.decisions.WithLabelValues(pick(outcome, clientOutcomes)).Inc()
}

// Migration counts one migration with cause and result.
func (m *ClientMetrics) Migration(cause, result string) {
	if m == nil {
		return
	}
	m.migrations.WithLabelValues(pick(cause, clientCauses), pick(result, clientResults)).Inc()
}

// MigrationDuration records how long a committed migration with cause
// took, from decision to the new path in use.
func (m *ClientMetrics) MigrationDuration(cause string, d time.Duration) {
	if m == nil {
		return
	}
	m.duration.WithLabelValues(pick(cause, clientCauses)).Observe(d.Seconds())
}

// --- gateway ---

// Link report results, the values of egressa_gateway_link_reports_total's
// result label.
const (
	ReportOK    = "ok"
	ReportError = "error"
)

var reportResults = []string{ReportOK, ReportError}

// BackboneSample is a gateway's measurement of its backbone to one peer,
// in microseconds.
type BackboneSample struct {
	Peer      string
	P50Micros float64
	P95Micros float64
	LossRatio float64
	Samples   uint64
	// Up: the backbone tunnel has completed a handshake.
	Up bool
}

// GatewaySnapshot is a gateway's state after one pass of its loops.
type GatewaySnapshot struct {
	Backbones []BackboneSample
	// AccessSessions and EgressSessions count the sessions this gateway
	// carries as access and as egress, in the plan last applied.
	AccessSessions int
	EgressSessions int
	StateVersion   uint64
	ControllerUp   bool
}

// GatewayMetrics are a gateway's metrics. A nil *GatewayMetrics records
// nothing.
type GatewayMetrics struct {
	snap        atomic.Pointer[GatewaySnapshot]
	fenced      atomic.Uint64
	applyErrors prometheus.Counter
	reports     *prometheus.CounterVec
}

// NewGatewayMetrics registers a gateway's metrics in r; nil if r is nil.
func NewGatewayMetrics(r *Registry) *GatewayMetrics {
	if r == nil {
		return nil
	}
	m := &GatewayMetrics{
		applyErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "gateway", Name: "apply_errors_total",
			Help: "Passes that failed to make the host match the controller's state.",
		}),
		reports: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "gateway", Name: "link_reports_total",
			Help: "Backbone link reports (the heartbeat) sent to the controller, by result.",
		}, []string{"result"}),
	}
	for _, res := range reportResults {
		m.reports.WithLabelValues(res)
	}
	fenced := prometheus.NewCounterFunc(prometheus.CounterOpts{
		Namespace: namespace, Subsystem: "gateway", Name: "fenced_packets_total",
		Help: "Client packets dropped for carrying an epoch older than their session's.",
	}, func() float64 { return float64(m.fenced.Load()) })

	var (
		rtt      = desc("gateway_backbone_rtt_seconds", "Round-trip time over the backbone tunnel to a peer gateway: its 50th and 95th percentile.", "peer", "percentile")
		loss     = desc("gateway_backbone_loss_ratio", "Probe loss over the backbone tunnel to a peer gateway, 0..1.", "peer")
		up       = desc("gateway_backbone_up", "1 if the backbone tunnel to a peer gateway has completed a handshake.", "peer")
		sessions = desc("gateway_sessions", "Sessions this gateway carries, as access or as egress.", "role")
		version  = desc("gateway_state_version", "Version of the controller state last applied.")
		ctlUp    = desc("gateway_controller_up", "1 if the gateway's last request to the controller succeeded.")
	)
	r.register(m.applyErrors, m.reports, fenced, snapshotCollector[GatewaySnapshot]{
		descs: []*prometheus.Desc{rtt, loss, up, sessions, version, ctlUp},
		snap:  &m.snap,
		emit: func(s *GatewaySnapshot, ch chan<- prometheus.Metric) {
			for _, b := range s.Backbones {
				gauge(ch, up, boolFloat(b.Up), b.Peer)
				if b.Samples == 0 {
					continue
				}
				gauge(ch, rtt, seconds(b.P50Micros), b.Peer, "50")
				gauge(ch, rtt, seconds(b.P95Micros), b.Peer, "95")
				gauge(ch, loss, b.LossRatio, b.Peer)
			}
			gauge(ch, sessions, float64(s.AccessSessions), "access")
			gauge(ch, sessions, float64(s.EgressSessions), "egress")
			gauge(ch, version, float64(s.StateVersion))
			gauge(ch, ctlUp, boolFloat(s.ControllerUp))
		},
	})
	return m
}

// Fenced counts one fenced packet. It runs on the packet path: one
// atomic add, nothing else.
func (m *GatewayMetrics) Fenced() {
	if m != nil {
		m.fenced.Add(1)
	}
}

// SetSnapshot replaces the snapshot the gauges are exported from.
func (m *GatewayMetrics) SetSnapshot(s GatewaySnapshot) {
	if m == nil {
		return
	}
	m.snap.Store(&s)
}

// ApplyError counts one failed apply.
func (m *GatewayMetrics) ApplyError() {
	if m != nil {
		m.applyErrors.Inc()
	}
}

// LinkReport counts one link report with result (ReportOK or
// ReportError).
func (m *GatewayMetrics) LinkReport(result string) {
	if m != nil {
		m.reports.WithLabelValues(pick(result, reportResults)).Inc()
	}
}

// --- controller ---

// Controller migration results, the values of
// egressa_controller_migrations_total's result label.
const (
	MigrationCommitted = "committed"
	MigrationConflict  = "conflict"
	MigrationRejected  = "rejected"
	MigrationError     = "error"
)

var controllerResults = []string{MigrationCommitted, MigrationConflict, MigrationRejected, MigrationError}

// ControllerSnapshot is the controller's state after one sweep.
type ControllerSnapshot struct {
	GatewaysAlive int
	GatewaysDown  int
	Sessions      int
	StateVersion  uint64
}

// ControllerMetrics are the controller's metrics. A nil
// *ControllerMetrics records nothing.
type ControllerMetrics struct {
	snap       atomic.Pointer[ControllerSnapshot]
	requests   *prometheus.CounterVec
	duration   *prometheus.HistogramVec
	migrations *prometheus.CounterVec
}

// NewControllerMetrics registers the controller's metrics in r; nil if r
// is nil.
func NewControllerMetrics(r *Registry) *ControllerMetrics {
	if r == nil {
		return nil
	}
	m := &ControllerMetrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "controller", Name: "http_requests_total",
			Help: "API requests, by route pattern and status code.",
		}, []string{"route", "code"}),
		duration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "controller", Name: "http_request_duration_seconds",
			Help:    "API request duration, by route pattern; long polls are not included.",
			Buckets: prometheus.DefBuckets,
		}, []string{"route"}),
		migrations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "controller", Name: "migrations_total",
			Help: "Migration requests, by result: committed, conflict (the session had moved on), rejected (a bad request), error.",
		}, []string{"result"}),
	}
	for _, res := range controllerResults {
		m.migrations.WithLabelValues(res)
	}
	var (
		gateways = desc("controller_gateways", "Registered gateways, by whether they are reporting.", "alive")
		sessions = desc("controller_sessions", "Sessions in the store.")
		version  = desc("controller_state_version", "Version of the state the controller serves; it rises on every change.")
	)
	r.register(m.requests, m.duration, m.migrations, snapshotCollector[ControllerSnapshot]{
		descs: []*prometheus.Desc{gateways, sessions, version},
		snap:  &m.snap,
		emit: func(s *ControllerSnapshot, ch chan<- prometheus.Metric) {
			gauge(ch, gateways, float64(s.GatewaysAlive), "true")
			gauge(ch, gateways, float64(s.GatewaysDown), "false")
			gauge(ch, sessions, float64(s.Sessions))
			gauge(ch, version, float64(s.StateVersion))
		},
	})
	return m
}

// SetSnapshot replaces the snapshot the gauges are exported from.
func (m *ControllerMetrics) SetSnapshot(s ControllerSnapshot) {
	if m == nil {
		return
	}
	m.snap.Store(&s)
}

// Migration counts one migration request with result.
func (m *ControllerMetrics) Migration(result string) {
	if m != nil {
		m.migrations.WithLabelValues(pick(result, controllerResults)).Inc()
	}
}

type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (w *statusRecorder) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRecorder) Write(b []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Middleware counts and times the requests next serves. next must be (or
// wrap) an http.ServeMux: the route label is the pattern the mux matched
// (r.Pattern, such as "POST /v1/sessions/{id}/migrate"), never the URL,
// which holds session IDs; requests no pattern matched are "unmatched".
// Requests to the longPoll patterns are counted but not timed: they wait
// for a change for up to a minute, which would swamp the histogram.
func (m *ControllerMetrics) Middleware(next http.Handler, longPoll ...string) http.Handler {
	if m == nil {
		return next
	}
	skip := make(map[string]bool, len(longPoll))
	for _, p := range longPoll {
		skip[p] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		route := r.Pattern
		if route == "" {
			route = "unmatched"
		}
		code := rec.code
		if code == 0 {
			code = http.StatusOK
		}
		m.requests.WithLabelValues(route, strconv.Itoa(code)).Inc()
		if !skip[route] {
			m.duration.WithLabelValues(route).Observe(time.Since(start).Seconds())
		}
	})
}
