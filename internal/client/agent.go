// Package client is the client agent: it opens a session with the
// controller, keeps a WireGuard peer with every access gateway, measures
// the path through each, and moves the session to a better path when
// measurement says so, without changing its session ID or virtual IP.
package client

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/control"
	"github.com/ngthdong/egressa/internal/measurement"
	"github.com/ngthdong/egressa/internal/pathmon"
	"github.com/ngthdong/egressa/internal/telemetry"
	"github.com/ngthdong/egressa/internal/tunnel"
)

const (
	// DefaultMTU is gateway.DefaultMTU: the client's packets cross a
	// backbone tunnel with the same overhead.
	DefaultMTU       = 1380
	DefaultDeadAfter = 3 * time.Second
	peerKeepalive    = 10 * time.Second
	statePollWait    = 2 * time.Second
	decideInterval   = 500 * time.Millisecond
	statusInterval   = 10 * time.Second
	// maxLinkStaleness drops a backbone measurement the controller has
	// not had fresh for this long.
	maxLinkStaleness = 10 * time.Second
)

// Config configures an Agent.
type Config struct {
	Controller *api.Client
	StateFile  string
	Interface  string
	// Egress, if set, is the egress gateway asked for when the session is
	// first opened.
	Egress string
	// FullTunnel routes all of the host's traffic through the VPN.
	FullTunnel bool
	MTU        int
	DeadAfter  time.Duration
	Probe      pathmon.Config
	// Logger receives the agent's logs; nil means slog.Default().
	Logger *slog.Logger
	// Metrics, if set, receives the agent's metrics.
	Metrics *telemetry.ClientMetrics
}

// pendingMigration is a move the client has decided on and asked the
// controller to commit. Whichever path brings the new epoch in first (the
// controller's answer, or the state long poll) credits it to the cause.
type pendingMigration struct {
	toEpoch uint64
	cause   string
	start   time.Time
}

// Agent runs one client.
type Agent struct {
	cfg Config
	log *slog.Logger
	key tunnel.KeyPair
	// sessionID is set once, when the session opens, and never changes.
	sessionID string
	secret    string
	dev       *tunnel.RealDevice
	mon       *pathmon.Monitor
	start     time.Time
	// controllerUp is whether the last request to the controller got an
	// answer.
	controllerUp atomic.Bool

	mu       sync.Mutex
	session  api.Session
	network  api.Network
	gateways []api.Gateway
	links    map[[2]string]api.Link
	decider  *Decider
	peers    map[string]api.Gateway // access gateways configured as peers
	bypass   map[netip.Addr]bool
	since    time.Time // when the current path became current
	original tunnel.RouteInfo
	hadRoute bool
	pending  *pendingMigration
}

// New checks cfg and returns an Agent ready to Run.
func New(cfg Config) (*Agent, error) {
	if cfg.Controller == nil || cfg.StateFile == "" || cfg.Interface == "" {
		return nil, errors.New("client: a controller, a state file and an interface name are required")
	}
	if cfg.MTU == 0 {
		cfg.MTU = DefaultMTU
	}
	if cfg.DeadAfter <= 0 {
		cfg.DeadAfter = DefaultDeadAfter
	}
	if cfg.Probe.Budget == nil {
		cfg.Probe = pathmon.DefaultConfig()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Agent{cfg: cfg, log: cfg.Logger, links: make(map[[2]string]api.Link), peers: make(map[string]api.Gateway), bypass: make(map[netip.Addr]bool)}, nil
}

// logCtx carries the session, so every log record about it has its
// session ID and trace ID.
func (a *Agent) logCtx() context.Context {
	return telemetry.WithSession(context.Background(), a.sessionID)
}

// Session returns the session as the client currently has it.
func (a *Agent) Session() api.Session {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.session
}

func (a *Agent) open(ctx context.Context) error {
	st, kp, err := LoadState(a.cfg.StateFile)
	if err != nil {
		return err
	}
	a.key = kp
	for {
		resp, err := a.cfg.Controller.CreateSession(ctx, api.CreateSessionRequest{
			PublicKey: tunnel.Base64(kp.Public), Egress: a.cfg.Egress, Secret: st.Secret,
		})
		if err == nil {
			st.SessionID, st.Secret = resp.Session.ID, resp.Secret
			if err := SaveState(a.cfg.StateFile, st); err != nil {
				return err
			}
			a.secret, a.sessionID = resp.Secret, resp.Session.ID
			a.session, a.network = resp.Session, resp.Network
			return nil
		}
		var se *api.StatusError
		if errors.As(err, &se) && se.Code/100 == 4 {
			return fmt.Errorf("client: the controller refused the session: %w", err)
		}
		a.log.Warn("open session failed; retrying", telemetry.Err(err))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// Run connects and keeps the session on the best path until ctx ends,
// then restores the host's routing.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.open(ctx); err != nil {
		return err
	}
	st, err := a.cfg.Controller.ClientState(ctx, a.session.ID, a.secret, 0, 0)
	if err != nil {
		return fmt.Errorf("client: read state: %w", err)
	}
	a.controllerUp.Store(true)
	sessionID, err := strconv.ParseUint(a.session.ID, 10, 64)
	if err != nil {
		return fmt.Errorf("client: session ID %q: %w", a.session.ID, err)
	}
	a.log.InfoContext(a.logCtx(), "session opened", "virtual_ip", a.session.VirtualIP.String(),
		"access", a.session.Access, "egress", a.session.Egress, "epoch", a.session.Epoch)

	dev, err := tunnel.NewReal(tunnel.RealConfig{
		PrivateKey: a.key.Private, InterfaceName: a.cfg.Interface, MTU: a.cfg.MTU,
		SessionID: sessionID, Epoch: uint32(a.session.Epoch),
	})
	if err != nil {
		return err
	}
	a.dev = dev
	defer dev.Close()
	if err := tunnel.ConfigureInterface(dev.Name(), netip.PrefixFrom(a.session.VirtualIP, 32)); err != nil {
		return err
	}
	if err := ipCmd("link", "set", dev.Name(), "mtu", strconv.Itoa(a.cfg.MTU)); err != nil {
		return err
	}
	if err := ipCmd("route", "replace", a.network.NodeSubnet.String(), "dev", dev.Name()); err != nil {
		return err
	}

	if a.cfg.FullTunnel {
		a.original, err = tunnel.CurrentRoute(netip.MustParseAddr("1.1.1.1"))
		a.hadRoute = err == nil && a.original.Interface != dev.Name()
		if host, err := netip.ParseAddr(a.cfg.Controller.Host()); err == nil {
			a.addBypass(host)
		} else if addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", a.cfg.Controller.Host()); err == nil {
			for _, h := range addrs {
				a.addBypass(h)
			}
		}
	}

	probe, err := pathmon.ListenUDP(netip.AddrPortFrom(a.session.VirtualIP, 0))
	if err != nil {
		return err
	}
	a.mon = pathmon.NewMonitor(probe, a.cfg.Probe)
	a.start = time.Now()
	a.since = a.start
	a.decider = NewDecider(st.Policy, a.start)
	a.update(st)

	if a.cfg.FullTunnel {
		if err := tunnel.SetFullTunnelDefault(dev.Name()); err != nil {
			return err
		}
		defer a.restoreRoutes()
		a.log.Info("full tunnel on: all traffic goes through the VPN", "interface", dev.Name())
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(2)
	go func() { defer wg.Done(); _ = a.mon.Run(runCtx) }()
	go func() { defer wg.Done(); a.pollLoop(runCtx, st.Version) }()

	a.log.InfoContext(a.logCtx(), "ready")
	tick := time.NewTicker(decideInterval)
	defer tick.Stop()
	status := time.NewTicker(statusInterval)
	defer status.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-status.C:
			a.logStatus()
		case <-tick.C:
			a.decideOnce(runCtx)
		}
	}
}

func (a *Agent) restoreRoutes() {
	a.mu.Lock()
	defer a.mu.Unlock()
	var err error
	if a.hadRoute {
		err = tunnel.RestoreDefaultRoute(a.original)
	} else {
		err = ipCmd("route", "del", "default", "dev", a.dev.Name())
	}
	for h := range a.bypass {
		err = errors.Join(err, tunnel.RemoveBypassRoute(h))
	}
	if err != nil {
		a.log.Warn("restoring routes failed", telemetry.Err(err))
	}
}

// addBypass keeps traffic to host (a gateway or the controller) off the
// tunnel when the tunnel carries everything.
func (a *Agent) addBypass(host netip.Addr) {
	if !a.cfg.FullTunnel || a.bypass[host] {
		return
	}
	via := a.original
	if r, err := tunnel.CurrentRoute(host); err == nil && r.Interface != a.cfg.Interface {
		via = r
	}
	if via.Interface == "" {
		a.log.Warn("no route outside the tunnel", "host", host.String())
		return
	}
	_ = tunnel.RemoveBypassRoute(host)
	if err := tunnel.AddBypassRoute(host, via); err != nil {
		a.log.Warn("bypass route failed", "host", host.String(), telemetry.Err(err))
		return
	}
	a.bypass[host] = true
}

func (a *Agent) pollLoop(ctx context.Context, version uint64) {
	for {
		st, err := a.cfg.Controller.ClientState(ctx, a.sessionID, a.secret, version, statePollWait)
		a.noteController(err)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.Warn("controller unreachable", telemetry.Err(err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		version = st.Version
		a.update(st)
	}
}

// update takes in a state from the controller.
func (a *Agent) update(st api.ClientState) {
	a.mu.Lock()
	a.gateways = st.Gateways
	a.links = make(map[[2]string]api.Link, len(st.Links))
	for _, l := range st.Links {
		a.links[[2]string{l.From, l.To}] = l
	}
	if st.Policy.Version != a.decider.Policy().Version {
		a.decider = NewDecider(st.Policy, time.Now())
	}
	targets := make(map[string]netip.AddrPort)
	for _, g := range st.Gateways {
		if !g.Roles.Has(control.RoleAccess) {
			continue
		}
		targets[g.ID] = netip.AddrPortFrom(g.NodeIP, st.Network.ProbePort)
		if old, ok := a.peers[g.ID]; ok && old.PublicKey == g.PublicKey && old.Endpoint == g.Endpoint && old.NodeIP == g.NodeIP {
			continue
		}
		if host, err := g.Host(); err == nil {
			a.addBypass(host)
		}
		if err := a.configurePeerLocked(g, g.ID == a.session.Access); err != nil {
			a.log.Warn("configure peer failed", "gateway", g.ID, telemetry.Err(err))
			continue
		}
		a.peers[g.ID] = g
	}
	a.mu.Unlock()
	if err := a.mon.Set(targets); err != nil {
		a.log.Warn("set probe targets failed", telemetry.Err(err))
	}
	// Someone else moved the session (or a migration's answer was lost).
	a.adopt(st.Session)
}

// configurePeerLocked sets gateway g as a peer. The peer always carries
// g's NodeIP, so g can be probed; the active access also carries the
// default route. WireGuard keeps each allowed IP on one peer only, so
// giving 0.0.0.0/0 to the new access takes it from the old one.
func (a *Agent) configurePeerLocked(g api.Gateway, active bool) error {
	key, err := tunnel.DecodeBase64(g.PublicKey)
	if err != nil {
		return err
	}
	allowed := []netip.Prefix{netip.PrefixFrom(g.NodeIP, 32)}
	if active {
		allowed = append(allowed, netip.MustParsePrefix("0.0.0.0/0"))
	}
	return a.dev.AddPeer(key, allowed, g.Endpoint, peerKeepalive)
}

// adopt switches to sess if it is newer than the session the client has.
func (a *Agent) adopt(sess api.Session) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if sess.Epoch <= a.session.Epoch {
		return
	}
	old := a.session
	// The epoch first: the new access may already fence older epochs.
	a.dev.SetEpoch(uint32(sess.Epoch))
	if sess.Access != old.Access {
		g, ok := api.FindGateway(a.gateways, sess.Access)
		if !ok {
			a.log.Warn("new access gateway is unknown", "access", sess.Access)
		} else if err := a.configurePeerLocked(g, true); err != nil {
			a.log.Warn("switching the active peer failed", "access", sess.Access, telemetry.Err(err))
		} else {
			a.peers[g.ID] = g
		}
	}
	a.session = sess
	now := time.Now()
	a.since = now
	a.decider.Reset(now)
	// Credit the move to the client's own decision if it is the one the
	// client asked for, else to whoever else moved the session.
	cause, began := telemetry.CauseExternal, time.Time{}
	if p := a.pending; p != nil && p.toEpoch == sess.Epoch {
		cause, began = p.cause, p.start
	}
	a.pending = nil
	a.cfg.Metrics.Migration(cause, telemetry.ResultCommitted)
	if !began.IsZero() {
		a.cfg.Metrics.MigrationDuration(cause, now.Sub(began))
	}
	a.log.InfoContext(telemetry.WithMigration(context.Background(), sess.ID, sess.Epoch), "path changed",
		"access", sess.Access, "egress", sess.Egress, "from_access", old.Access, "from_egress", old.Egress)
}

// paths builds every path the client could use: through each access
// gateway, to each egress gateway.
func (a *Agent) paths(now time.Time) (paths []Path, currentDead bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	halfLife := float64(measurement.DefaultSegmentTrackerConfig.StalenessHalfLife)
	for _, acc := range a.gateways {
		if !acc.Roles.Has(control.RoleAccess) {
			continue
		}
		stats, lastReply, ok := a.mon.Stats(acc.ID)
		reachable := ok && stats.N > 0 && now.Sub(lastReply) <= a.cfg.DeadAfter
		if acc.ID == a.session.Access {
			// Dead once nothing has come back for DeadAfter, counted
			// from when this path became current at the earliest.
			last := lastReply
			if last.Before(a.since) {
				last = a.since
			}
			currentDead = now.Sub(last) > a.cfg.DeadAfter
		}
		for _, eg := range a.gateways {
			if !eg.Roles.Has(control.RoleEgress) || (!eg.Alive && eg.ID != a.session.Egress) {
				continue
			}
			p := Path{Access: acc.ID, Egress: eg.ID, Segments: []measurement.SegmentStats{stats}, Reachable: reachable}
			if acc.ID != eg.ID {
				l, ok := a.links[[2]string{acc.ID, eg.ID}]
				if !ok || l.Staleness > maxLinkStaleness {
					// Never measured: the path can be neither chosen
					// nor trusted.
					l.Stats = measurement.SegmentStats{}
					p.Reachable = false
				} else {
					// Freshness confidence decays exponentially, so a
					// report this much older scales by 2^(-staleness/halfLife).
					l.Stats.Age += l.Staleness
					l.Stats.Confidence *= math.Exp2(-float64(l.Staleness) / halfLife)
				}
				p.Segments = append(p.Segments, l.Stats)
			}
			paths = append(paths, p)
		}
	}
	return paths, currentDead
}

func (a *Agent) decideOnce(ctx context.Context) {
	now := time.Now()
	paths, dead := a.paths(now)
	a.mu.Lock()
	sess := a.session
	dec := a.decider.Decide(now, sess.Access, sess.Egress, paths, dead)
	if dec.Migrate {
		a.pending = &pendingMigration{toEpoch: sess.Epoch + 1, cause: dec.Cause, start: now}
	}
	accessIDs := make([]string, 0, len(a.gateways))
	for _, g := range a.gateways {
		if g.Roles.Has(control.RoleAccess) {
			accessIDs = append(accessIDs, g.ID)
		}
	}
	a.mu.Unlock()
	a.cfg.Metrics.Decision(dec.Outcome)
	a.publish(sess, accessIDs, paths, dead, dec)
	if !dec.Migrate {
		return
	}
	a.log.InfoContext(a.logCtx(), "migrating", "access", dec.Access, "egress", dec.Egress, "reason", dec.Reason)
	next, err := a.cfg.Controller.Migrate(ctx, sess.ID, a.secret, api.MigrateRequest{Epoch: sess.Epoch, Access: dec.Access, Egress: dec.Egress})
	a.noteController(err)
	var conflict *api.ConflictError
	switch {
	case errors.As(err, &conflict):
		a.log.InfoContext(a.logCtx(), "migration lost to a newer epoch", "now_epoch", conflict.Current.Epoch)
		a.cfg.Metrics.Migration(dec.Cause, telemetry.ResultConflict)
		a.clearPending()
		a.adopt(conflict.Current)
	case err != nil:
		a.log.WarnContext(a.logCtx(), "migration failed; staying", telemetry.Err(err))
		a.cfg.Metrics.Migration(dec.Cause, telemetry.ResultFailed)
		a.clearPending()
	default:
		a.adopt(next)
	}
}

func (a *Agent) clearPending() {
	a.mu.Lock()
	a.pending = nil
	a.mu.Unlock()
}

// noteController records whether a request reached the controller: any
// answer from it, an error status included, means it is up.
func (a *Agent) noteController(err error) {
	var se *api.StatusError
	var ce *api.ConflictError
	a.controllerUp.Store(err == nil || errors.As(err, &se) || errors.As(err, &ce))
}

// publish hands the decision pass's numbers to the metrics.
func (a *Agent) publish(sess api.Session, accessIDs []string, paths []Path, dead bool, dec Decision) {
	if a.cfg.Metrics == nil {
		return
	}
	snap := telemetry.ClientSnapshot{
		ThresholdMicros: dec.Threshold,
		ActiveAccess:    sess.Access, ActiveEgress: sess.Egress,
		Epoch: sess.Epoch, CurrentDead: dead, ControllerUp: a.controllerUp.Load(),
	}
	for _, id := range accessIDs {
		st, _, ok := a.mon.Stats(id)
		if !ok {
			continue
		}
		snap.Segments = append(snap.Segments, telemetry.SegmentSample{
			Gateway: id, P50Micros: st.P50Micros, P95Micros: st.P95Micros,
			LossRatio: st.LossRate, Confidence: st.Confidence, Samples: st.N,
		})
	}
	for i, p := range paths {
		ps := telemetry.PathSample{Access: p.Access, Egress: p.Egress, Reachable: p.Reachable}
		measured := true
		for _, seg := range p.Segments {
			measured = measured && seg.N > 0
		}
		if i < len(dec.Evals) {
			ev := dec.Evals[i]
			ps.CostMicros = ev.Cost
			ps.Usable = measured && !math.IsInf(ev.Cost, 0)
			ps.DeltaLowerMicros, ps.HasDelta = ev.Delta.Lower, ev.HasDelta
		}
		snap.Paths = append(snap.Paths, ps)
	}
	a.cfg.Metrics.SetSnapshot(snap)
}

func (a *Agent) logStatus() {
	now := time.Now()
	paths, dead := a.paths(now)
	sess := a.Session()
	a.mu.Lock()
	pol := a.decider.Policy()
	a.mu.Unlock()
	var costs, unreachable []any
	for _, p := range paths {
		if p.Egress != sess.Egress {
			continue
		}
		if c := measurement.ScorePath(p.candidate(), pol.Cost).Cost; !math.IsInf(c, 0) {
			costs = append(costs, slog.Float64(p.Access, c/1000))
		}
		if !p.Reachable {
			unreachable = append(unreachable, p.Access)
		}
	}
	a.log.InfoContext(telemetry.WithSession(context.Background(), sess.ID), "status",
		"access", sess.Access, "egress", sess.Egress, "epoch", sess.Epoch, "current_dead", dead,
		slog.Group("cost_ms", costs...), "unreachable", unreachable)
}

func ipCmd(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
