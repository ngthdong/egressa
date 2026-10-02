package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/control"
	"github.com/ngthdong/egressa/internal/pathmon"
	"github.com/ngthdong/egressa/internal/telemetry"
	"github.com/ngthdong/egressa/internal/tunnel"
	"github.com/ngthdong/egressa/pkg/wire"
)

const (
	clientDevice      = "egc0"
	backboneKeepalive = 5 * time.Second
	reportInterval    = time.Second
	pollWait          = 25 * time.Second
	// DefaultMTU leaves room under a 1500-byte path for WireGuard's 60
	// bytes of IPv4 overhead plus the 24-byte session header.
	DefaultMTU = 1380
)

// Config configures an Agent.
type Config struct {
	ID         string
	Controller *api.Client
	Roles      api.Roles
	Key        tunnel.KeyPair
	// ListenPort is the client-facing WireGuard port; Endpoint is the
	// ip:port clients reach it on, and its IP is where other gateways
	// reach this one's backbone tunnels.
	ListenPort uint16
	Endpoint   string
	// Uplink is the interface traffic leaves to the Internet from. An
	// egress gateway needs it.
	Uplink string
	MTU    int
	// Probe configures backbone probing; the zero value means
	// pathmon.DefaultConfig().
	Probe pathmon.Config
	// Logger receives the agent's logs; nil means slog.Default().
	Logger *slog.Logger
	// Metrics, if set, receives the agent's metrics.
	Metrics *telemetry.GatewayMetrics
	// Tracer, if set, logs a span each time a session's move is applied.
	Tracer *telemetry.Tracer
}

type backbone struct {
	dev  *tunnel.RealDevice
	name string
	want Backbone
	set  bool // want has been applied to dev
	up   bool // has completed a handshake
}

// Agent runs one gateway.
type Agent struct {
	cfg     Config
	log     *slog.Logger
	nodeIP  netip.Addr
	network api.Network
	gate    *control.EpochGate
	// fence is what admit reads on every packet: session ID -> the
	// lowest epoch admitted, copied from gate after each change. A plain
	// map of integers behind an atomic pointer, so the packet path never
	// formats a session ID or takes a lock.
	fence atomic.Pointer[map[uint64]uint64]
	egc   *tunnel.RealDevice
	mon   *pathmon.Monitor
	undo  []func()

	mu        sync.Mutex
	index     map[string]int // gateway ID -> n, for egb<n> and its table
	nextIndex int
	backbones map[string]*backbone
	peers     map[string]netip.Addr
	forward   map[netip.Addr]string
	ret       map[netip.Addr]string
	ports     map[string]uint16 // backbone ports as last registered
	// fenced holds every session ID ever applied, parsed, so the fence
	// map covers every session gate knows.
	fenced map[string]uint64
	// carried counts the sessions of the plan last applied, for metrics.
	accessSessions, egressSessions int
	// applied is each session's path as last applied, to tell which
	// sessions a plan moves.
	applied map[string]SessionPath

	stateVersion atomic.Uint64
	controllerUp atomic.Bool
}

// New checks cfg and returns an Agent ready to Run.
func New(cfg Config) (*Agent, error) {
	if cfg.ID == "" || cfg.Controller == nil || cfg.Endpoint == "" {
		return nil, errors.New("gateway: an ID, a controller and an endpoint are required")
	}
	if _, err := netip.ParseAddrPort(cfg.Endpoint); err != nil {
		return nil, fmt.Errorf("gateway: endpoint %q must be ip:port: %w", cfg.Endpoint, err)
	}
	if cfg.Roles.Has(control.RoleEgress) && cfg.Uplink == "" {
		return nil, errors.New("gateway: an egress gateway needs an uplink interface")
	}
	if cfg.MTU == 0 {
		cfg.MTU = DefaultMTU
	}
	if cfg.Probe.Budget == nil {
		cfg.Probe = pathmon.DefaultConfig()
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	a := &Agent{
		cfg:       cfg,
		log:       cfg.Logger,
		gate:      control.NewEpochGate(),
		index:     make(map[string]int),
		backbones: make(map[string]*backbone),
		peers:     make(map[string]netip.Addr),
		forward:   make(map[netip.Addr]string),
		ret:       make(map[netip.Addr]string),
		fenced:    make(map[string]uint64),
		applied:   make(map[string]SessionPath),
	}
	a.fence.Store(&map[uint64]uint64{})
	return a, nil
}

// Run registers, configures the host, and follows the controller until
// ctx ends; it then removes everything it installed.
func (a *Agent) Run(ctx context.Context) error {
	reg, err := a.registerRetry(ctx)
	if err != nil {
		return err
	}
	a.nodeIP, a.network = reg.NodeIP, reg.Network
	a.log.Info("registered", "node_ip", a.nodeIP.String(), "client_subnet", a.network.ClientSubnet.String())
	defer a.teardown()
	if err := a.setup(); err != nil {
		return err
	}

	var wg sync.WaitGroup
	defer wg.Wait()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	wg.Add(2)
	go func() { defer wg.Done(); _ = a.mon.Run(runCtx) }()
	go func() { defer wg.Done(); a.reportLoop(runCtx) }()

	a.log.Info("ready")
	var version uint64
	for {
		st, err := a.cfg.Controller.GatewayState(runCtx, version, pollWait)
		a.noteController(err)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			a.log.Warn("controller unreachable", telemetry.Err(err))
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
			continue
		}
		version = st.Version
		if err := a.apply(MakePlan(a.cfg.ID, a.cfg.Roles, st)); err != nil {
			a.log.Warn("apply failed", telemetry.Err(err))
			a.cfg.Metrics.ApplyError()
		}
		a.stateVersion.Store(st.Version)
		a.publish()
		if a.portsChanged() {
			if _, err := a.register(runCtx); err != nil {
				a.log.Warn("re-register failed", telemetry.Err(err))
			}
		}
	}
}

func (a *Agent) register(ctx context.Context) (api.RegisterGatewayResponse, error) {
	a.mu.Lock()
	ports := make(map[string]uint16, len(a.backbones))
	for id, b := range a.backbones {
		if p, err := b.dev.ListenPort(); err == nil {
			ports[id] = p
		}
	}
	a.mu.Unlock()
	resp, err := a.cfg.Controller.RegisterGateway(ctx, a.cfg.ID, api.RegisterGatewayRequest{
		Roles:         a.cfg.Roles,
		Endpoint:      a.cfg.Endpoint,
		PublicKey:     tunnel.Base64(a.cfg.Key.Public),
		BackbonePorts: ports,
	})
	if err != nil {
		return resp, err
	}
	a.mu.Lock()
	a.ports = ports
	a.mu.Unlock()
	if a.nodeIP.IsValid() && resp.NodeIP != a.nodeIP {
		a.log.Warn("the controller gives another node IP; restart the gateway", "node_ip", resp.NodeIP.String(), "in_use", a.nodeIP.String())
	}
	return resp, nil
}

func (a *Agent) registerRetry(ctx context.Context) (api.RegisterGatewayResponse, error) {
	for {
		resp, err := a.register(ctx)
		if err == nil {
			return resp, nil
		}
		var se *api.StatusError
		if errors.As(err, &se) && se.Code/100 == 4 {
			return resp, fmt.Errorf("gateway: the controller refused registration: %w", err)
		}
		a.log.Warn("register failed; retrying", telemetry.Err(err))
		select {
		case <-ctx.Done():
			return resp, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func (a *Agent) portsChanged() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.ports) != len(a.backbones) {
		return true
	}
	for id, b := range a.backbones {
		p, err := b.dev.ListenPort()
		if err != nil || a.ports[id] != p {
			return true
		}
	}
	return false
}

// admit fences a client packet stamped with an epoch older than its
// session's current one: it is from before a migration this gateway has
// already seen committed. It runs for every packet, so it neither
// allocates nor locks: it reads the fence map, a copy of gate's epochs
// (an unknown session is admitted, as gate.Admit admits it).
func (a *Agent) admit(h wire.SessionHeader) bool {
	if h.SessionID == 0 {
		return true
	}
	if known, ok := (*a.fence.Load())[h.SessionID]; ok && uint64(h.Epoch) < known {
		a.cfg.Metrics.Fenced()
		return false
	}
	return true
}

// updateFenceLocked copies gate's epoch of every session seen so far into
// a new fence map.
func (a *Agent) updateFenceLocked(epochs map[string]uint64) {
	for session := range epochs {
		if _, ok := a.fenced[session]; ok {
			continue
		}
		if id, err := strconv.ParseUint(session, 10, 64); err == nil {
			a.fenced[session] = id
		}
	}
	next := make(map[uint64]uint64, len(a.fenced))
	for session, id := range a.fenced {
		if epoch, ok := a.gate.Known(session); ok {
			next[id] = epoch
		}
	}
	a.fence.Store(&next)
}

// noteController records whether a request reached the controller: any
// answer from it, an error status included, means it is up.
func (a *Agent) noteController(err error) {
	var se *api.StatusError
	a.controllerUp.Store(err == nil || errors.As(err, &se))
}

// publish hands the gateway's numbers to the metrics.
func (a *Agent) publish() {
	if a.cfg.Metrics == nil {
		return
	}
	a.mu.Lock()
	snap := telemetry.GatewaySnapshot{
		AccessSessions: a.accessSessions, EgressSessions: a.egressSessions,
		StateVersion: a.stateVersion.Load(), ControllerUp: a.controllerUp.Load(),
	}
	type peer struct {
		id string
		up bool
	}
	peers := make([]peer, 0, len(a.backbones))
	for id, b := range a.backbones {
		peers = append(peers, peer{id, b.up})
	}
	a.mu.Unlock()
	for _, p := range peers {
		bs := telemetry.BackboneSample{Peer: p.id, Up: p.up}
		if st, _, ok := a.mon.Stats(p.id); ok {
			bs.P50Micros, bs.P95Micros, bs.LossRatio, bs.Samples = st.P50Micros, st.P95Micros, st.LossRate, st.N
		}
		snap.Backbones = append(snap.Backbones, bs)
	}
	a.cfg.Metrics.SetSnapshot(snap)
}

func (a *Agent) setup() error {
	if err := tunnel.EnableIPForwarding(); err != nil {
		return err
	}
	// Anything a previous run that crashed left behind.
	clearRules(probeRulePref)
	clearRules(fwdRulePref)

	egc, err := tunnel.NewReal(tunnel.RealConfig{
		PrivateKey: a.cfg.Key.Private, ListenPort: a.cfg.ListenPort,
		InterfaceName: clientDevice, MTU: a.cfg.MTU, Admit: a.admit,
	})
	if err != nil {
		return err
	}
	a.egc = egc
	a.undo = append(a.undo, egc.Close)
	if err := addrUp(clientDevice, a.nodeIP, a.cfg.MTU); err != nil {
		return err
	}
	subnet := a.network.ClientSubnet.String()
	if err := ip("route", "replace", subnet, "dev", clientDevice); err != nil {
		return err
	}
	// Probe replies leave from the NodeIP straight back to the client.
	if err := flushTable(probeTable); err != nil {
		return err
	}
	if err := ip("route", "replace", subnet, "dev", clientDevice, "table", strconv.Itoa(probeTable)); err != nil {
		return err
	}
	probeRule := []string{"from", netip.PrefixFrom(a.nodeIP, 32).String(), "lookup", strconv.Itoa(probeTable), "pref", strconv.Itoa(probeRulePref)}
	if err := addRule(probeRule); err != nil {
		return err
	}
	a.undo = append(a.undo, func() { _ = delRule(probeRule); _ = flushTable(probeTable) })

	for _, dev := range []string{clientDevice, "egb+"} {
		for _, r := range forwardRules(dev) {
			if err := ensureIptables(r); err != nil {
				return err
			}
			a.undo = append(a.undo, func() { _ = deleteIptables(r) })
		}
	}
	if a.cfg.Roles.Has(control.RoleEgress) {
		r := natRule(a.network.ClientSubnet, a.cfg.Uplink)
		if err := ensureIptables(r); err != nil {
			return err
		}
		a.undo = append(a.undo, func() { _ = deleteIptables(r) })
	}

	echo, err := pathmon.ListenUDP(netip.AddrPortFrom(a.nodeIP, a.network.ProbePort))
	if err != nil {
		return err
	}
	a.undo = append(a.undo, func() { _ = echo.Close() })
	go func() { _ = pathmon.Echo(echo) }()

	probe, err := pathmon.ListenUDP(netip.AddrPortFrom(a.nodeIP, 0))
	if err != nil {
		return err
	}
	a.mon = pathmon.NewMonitor(probe, a.cfg.Probe)
	return nil
}

func (a *Agent) teardown() {
	a.mu.Lock()
	for id, b := range a.backbones {
		b.dev.Close()
		delete(a.backbones, id)
	}
	for _, n := range a.index {
		_ = flushTable(egressTableBase + n)
	}
	a.mu.Unlock()
	clearRules(fwdRulePref)
	for i := len(a.undo) - 1; i >= 0; i-- {
		a.undo[i]()
	}
	a.undo = nil
	a.log.Info("stopped; host configuration removed")
}

// indexLocked returns gateway id's n, giving it a new one on first use,
// and makes sure its table holds at least the blackhole.
func (a *Agent) indexLocked(id string) (int, error) {
	if n, ok := a.index[id]; ok {
		return n, nil
	}
	n := a.nextIndex
	a.nextIndex++
	a.index[id] = n
	table := strconv.Itoa(egressTableBase + n)
	if err := flushTable(egressTableBase + n); err != nil {
		return n, err
	}
	// Without a backbone device, traffic for this egress is dropped, not
	// sent out of this gateway's own uplink.
	if err := ip("route", "replace", "blackhole", "default", "metric", "4000", "table", table); err != nil {
		return n, err
	}
	return n, nil
}

func (a *Agent) apply(p Plan) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	began := a.cfg.Tracer.Now()
	var errs []error
	// vipErrs keeps each virtual IP's routing error for its session's span.
	vipErrs := make(map[netip.Addr]error)
	defer func() { a.traceMovesLocked(p, began, vipErrs) }()

	for id, b := range a.backbones {
		if _, ok := p.Backbones[id]; !ok {
			a.log.Info("backbone removed", "peer", id)
			b.dev.Close()
			delete(a.backbones, id)
		}
	}
	for _, id := range p.BackboneIDs() {
		if err := a.applyBackboneLocked(id, p.Backbones[id]); err != nil {
			errs = append(errs, fmt.Errorf("backbone to %s: %w", id, err))
		}
	}
	if err := a.setProbeTargetsLocked(); err != nil {
		errs = append(errs, err)
	}

	for key, vip := range a.peers {
		if want, ok := p.Peers[key]; ok && want == vip {
			continue
		}
		if k, err := tunnel.DecodeBase64(key); err == nil {
			if err := a.egc.RemovePeer(k); err != nil {
				errs = append(errs, err)
			}
		}
		delete(a.peers, key)
	}
	for key, vip := range p.Peers {
		if _, ok := a.peers[key]; ok {
			continue
		}
		k, err := tunnel.DecodeBase64(key)
		if err != nil {
			errs = append(errs, fmt.Errorf("client key %q: %w", key, err))
			continue
		}
		if err := a.egc.AddPeer(k, []netip.Prefix{netip.PrefixFrom(vip, 32)}, "", 0); err != nil {
			errs = append(errs, err)
			continue
		}
		a.peers[key] = vip
	}

	// Gate first: once this gateway acts on an epoch, older packets stop.
	for session, epoch := range p.Epochs {
		a.gate.Update(session, epoch)
	}
	a.updateFenceLocked(p.Epochs)
	a.accessSessions, a.egressSessions = p.AccessSessions, p.EgressSessions

	for vip, egress := range a.forward {
		if p.Forward[vip] == egress {
			continue
		}
		if err := delRule(ruleFrom(vip, egressTableBase+a.index[egress])); err != nil {
			errs = append(errs, err)
			vipErrs[vip] = err
		}
		delete(a.forward, vip)
	}
	for vip, egress := range p.Forward {
		if _, ok := a.forward[vip]; ok {
			continue
		}
		n, err := a.indexLocked(egress)
		if err != nil {
			errs = append(errs, err)
			vipErrs[vip] = err
			continue
		}
		if err := addRule(ruleFrom(vip, egressTableBase+n)); err != nil {
			errs = append(errs, err)
			vipErrs[vip] = err
			continue
		}
		a.forward[vip] = egress
	}

	for vip, access := range a.ret {
		if p.Return[vip] == access {
			continue
		}
		if err := ipIgnore("route", "del", netip.PrefixFrom(vip, 32).String()); err != nil {
			errs = append(errs, err)
			vipErrs[vip] = err
		}
		delete(a.ret, vip)
	}
	for vip, access := range p.Return {
		if _, ok := a.ret[vip]; ok {
			continue
		}
		b, ok := a.backbones[access]
		if !ok {
			continue
		}
		if err := ip("route", "replace", netip.PrefixFrom(vip, 32).String(), "dev", b.name); err != nil {
			errs = append(errs, err)
			vipErrs[vip] = err
			continue
		}
		a.log.Info("return route changed", "virtual_ip", vip.String(), "access", access)
		a.ret[vip] = access
	}
	return errors.Join(errs...)
}

// traceMovesLocked logs a migration.apply span for every session p moves
// to a newer epoch: this gateway has fenced the old epoch and set the
// session's forwarding and return routes for its new path. A session
// seen for the first time is not a move. When polls are far apart, a
// gateway can see a session jump several epochs; the span then belongs
// to the newest one.
func (a *Agent) traceMovesLocked(p Plan, began time.Time, vipErrs map[netip.Addr]error) {
	for id, now := range p.Sessions {
		was, seen := a.applied[id]
		a.applied[id] = now
		if !seen || now.Epoch <= was.Epoch {
			continue
		}
		forward, ret := a.forward[now.VirtualIP], a.ret[now.VirtualIP]
		a.cfg.Tracer.StartAt(telemetry.WithMigration(context.Background(), id, now.Epoch), "migration.apply", began,
			slog.String("access", now.Access), slog.String("egress", now.Egress),
			slog.String("from_access", was.Access), slog.String("from_egress", was.Egress),
			slog.Uint64("from_epoch", was.Epoch),
			slog.String("forward_to", forward), slog.String("return_via", ret),
		).End(vipErrs[now.VirtualIP])
	}
}

func (a *Agent) applyBackboneLocked(id string, want Backbone) error {
	b, ok := a.backbones[id]
	if !ok {
		n, err := a.indexLocked(id)
		if err != nil {
			return err
		}
		name := "egb" + strconv.Itoa(n)
		dev, err := tunnel.NewReal(tunnel.RealConfig{PrivateKey: a.cfg.Key.Private, InterfaceName: name, MTU: a.cfg.MTU})
		if err != nil {
			return err
		}
		if err := addrUp(name, a.nodeIP, a.cfg.MTU); err != nil {
			dev.Close()
			return err
		}
		if err := ip("route", "replace", "default", "dev", name, "table", strconv.Itoa(egressTableBase+n)); err != nil {
			dev.Close()
			return err
		}
		b = &backbone{dev: dev, name: name}
		a.backbones[id] = b
		port, _ := dev.ListenPort()
		a.log.Info("backbone created", "peer", id, "device", name, "port", port)
	}
	if b.set && b.want == want {
		return nil
	}
	// Only one side of a backbone initiates: the gateway with the lower
	// ID. Both learn each other's port at the same moment, so if both
	// initiated, their handshakes would cross, each would discard the
	// other's response, and their retries, on the same 5 s timer, would
	// keep crossing. The other side answers, and sends nothing of its own
	// accord; the initiator's keepalives keep the session up.
	initiator := a.cfg.ID < id
	keepalive := time.Duration(0)
	if initiator {
		keepalive = backboneKeepalive
	}
	// The initiator gets a fresh peer when the endpoint changes (the
	// other side just reported its port, or restarted on a new one):
	// wireguard-go handshakes at once only for a new peer.
	if b.set && (b.want.PublicKey != want.PublicKey || (initiator && b.want.Endpoint != want.Endpoint)) {
		if k, err := tunnel.DecodeBase64(b.want.PublicKey); err == nil {
			_ = b.dev.RemovePeer(k)
		}
		b.up = false
	}
	key, err := tunnel.DecodeBase64(want.PublicKey)
	if err != nil {
		return err
	}
	if err := b.dev.AddPeer(key, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, want.Endpoint, keepalive); err != nil {
		return err
	}
	if err := ip("route", "replace", netip.PrefixFrom(want.NodeIP, 32).String(), "dev", b.name, "src", a.nodeIP.String()); err != nil {
		return err
	}
	b.want, b.set = want, true
	a.log.Info("backbone peer set", "peer", id, "endpoint", want.Endpoint, "initiator", initiator)
	return nil
}

// setProbeTargetsLocked probes each backbone whose tunnel has completed a
// handshake. Probing one that has not would count every probe sent while
// the peers are still learning each other's ports as lost, and a link
// would look broken for a whole measurement window after start.
func (a *Agent) setProbeTargetsLocked() error {
	targets := make(map[string]netip.AddrPort, len(a.backbones))
	for id, b := range a.backbones {
		if !b.set {
			continue
		}
		key, err := tunnel.DecodeBase64(b.want.PublicKey)
		if err != nil {
			continue
		}
		if last, err := b.dev.LastHandshake(key); err == nil && !last.IsZero() {
			targets[id] = netip.AddrPortFrom(b.want.NodeIP, a.network.ProbePort)
			if !b.up {
				a.log.Info("backbone up", "peer", id)
				b.up = true
			}
		}
	}
	return a.mon.Set(targets)
}

func (a *Agent) reportLoop(ctx context.Context) {
	t := time.NewTicker(reportInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.mu.Lock()
		ids := slices.Collect(maps.Keys(a.backbones))
		if err := a.setProbeTargetsLocked(); err != nil {
			a.log.Warn("set probe targets failed", telemetry.Err(err))
		}
		a.mu.Unlock()
		rep := api.LinkReport{Links: make([]api.Link, 0, len(ids))}
		for _, id := range ids {
			if st, _, ok := a.mon.Stats(id); ok {
				rep.Links = append(rep.Links, api.Link{To: id, Stats: st})
			}
		}
		err := a.cfg.Controller.ReportLinks(ctx, a.cfg.ID, rep)
		a.noteController(err)
		if err == nil {
			a.cfg.Metrics.LinkReport(telemetry.ReportOK)
		} else {
			a.cfg.Metrics.LinkReport(telemetry.ReportError)
		}
		var se *api.StatusError
		if errors.As(err, &se) && se.Code == http.StatusNotFound {
			// The controller lost its state; register again.
			_, err = a.register(ctx)
		}
		if err != nil && ctx.Err() == nil {
			a.log.Warn("link report failed", telemetry.Err(err))
		}
		a.publish()
	}
}
