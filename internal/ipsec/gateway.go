package ipsec

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// DefaultGatewayInterfacePrefix names the XFRM interfaces a Gateway
// creates.
const DefaultGatewayInterfacePrefix = "egw"

// DefaultRulePriority is the priority of the rule that sends client
// traffic to a gateway's own routing table.
const DefaultRulePriority = 1000

// GatewayConfig configures a Gateway.
type GatewayConfig struct {
	// Name prefixes every connection and secret this gateway loads.
	// Default "egressa".
	Name string
	// LocalID is the identity clients see; BackboneID the one backbone
	// peers see. They must differ: when verifying a pre-shared key,
	// strongSwan tries every key that names either side of the exchange,
	// so with one identity for both roles a client holding the backbone
	// key (or a peer holding the client key) would authenticate. Default
	// BackboneID: LocalID + "-bb".
	LocalID    string
	BackboneID string
	// LocalAddr is the underlay address clients and peer gateways reach.
	LocalAddr netip.Addr

	// ClientPSK authenticates clients; BackbonePSK authenticates peer
	// gateways. They must differ, so a client can never pass as a peer.
	ClientPSK   string
	BackbonePSK string

	// ClientSubnet holds every client's virtual IP: the remote traffic
	// selector of the one responder connection all clients use.
	ClientSubnet netip.Prefix
	// Served is what clients may reach through this gateway (the
	// responder's local traffic selectors). Empty means every address of
	// ClientSubnet's family.
	Served []netip.Prefix
	// InnerAddr, if set, is this gateway's own address on the client XFRM
	// interface.
	InnerAddr  netip.Addr
	ClientIfID uint32

	// Table holds the Uplink routes. 0 (main) routes client traffic with
	// the gateway's own; any other table is consulted only for traffic
	// arriving from clients, through a rule at RulePriority.
	Table        int
	RulePriority int

	DPDDelay        time.Duration
	IKEProposals    []string
	ESPProposals    []string
	InterfacePrefix string // default "egw"
	PollInterval    time.Duration
	CleanupTimeout  time.Duration
}

func (cfg *GatewayConfig) setDefaults() {
	if cfg.Name == "" {
		cfg.Name = "egressa"
	}
	if cfg.BackboneID == "" && cfg.LocalID != "" {
		cfg.BackboneID = cfg.LocalID + "-bb"
	}
	if cfg.InterfacePrefix == "" {
		cfg.InterfacePrefix = DefaultGatewayInterfacePrefix
	}
	if cfg.RulePriority == 0 {
		cfg.RulePriority = DefaultRulePriority
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	if cfg.CleanupTimeout <= 0 {
		cfg.CleanupTimeout = DefaultCleanupTimeout
	}
}

func (cfg GatewayConfig) validate() error {
	if !nameRE.MatchString(cfg.Name) {
		return fmt.Errorf("ipsec: gateway name %q must match %s", cfg.Name, nameRE)
	}
	if !idRE.MatchString(cfg.LocalID) {
		return fmt.Errorf("ipsec: gateway LocalID %q must match %s", cfg.LocalID, idRE)
	}
	if !idRE.MatchString(cfg.BackboneID) {
		return fmt.Errorf("ipsec: gateway BackboneID %q must match %s", cfg.BackboneID, idRE)
	}
	if cfg.BackboneID == cfg.LocalID {
		return errors.New("ipsec: the gateway's BackboneID must differ from its LocalID, " +
			"or each role's pre-shared key would also authenticate the other role")
	}
	if err := checkAddr("gateway LocalAddr", cfg.LocalAddr); err != nil {
		return err
	}
	if err := validatePSK("gateway client", cfg.ClientPSK); err != nil {
		return err
	}
	if err := validatePSK("gateway backbone", cfg.BackbonePSK); err != nil {
		return err
	}
	if cfg.ClientPSK == cfg.BackbonePSK {
		return errors.New("ipsec: the backbone PSK must differ from the client PSK")
	}
	if !cfg.ClientSubnet.IsValid() {
		return errors.New("ipsec: gateway ClientSubnet is required")
	}
	f := familyOf(cfg.ClientSubnet.Addr())
	if err := checkPrefixes("gateway served", f, cfg.Served); err != nil {
		return err
	}
	if cfg.InnerAddr.IsValid() {
		if err := checkAddr("gateway InnerAddr", cfg.InnerAddr); err != nil {
			return err
		}
		if familyOf(cfg.InnerAddr) != f {
			return fmt.Errorf("ipsec: gateway InnerAddr %s is not in ClientSubnet's family", cfg.InnerAddr)
		}
	}
	if cfg.ClientIfID == 0 {
		return errors.New("ipsec: gateway ClientIfID must be non-zero")
	}
	if cfg.Table < 0 || cfg.RulePriority < 0 {
		return errors.New("ipsec: gateway table and rule priority must not be negative")
	}
	if !ifPrefixRE.MatchString(cfg.InterfacePrefix) {
		return fmt.Errorf("ipsec: interface prefix %q must match %s", cfg.InterfacePrefix, ifPrefixRE)
	}
	if cfg.DPDDelay < 0 {
		return errors.New("ipsec: gateway DPDDelay must not be negative")
	}
	return nil
}

// BackbonePeer is another gateway this one keeps a backbone SA with.
type BackbonePeer struct {
	// Name identifies the peer locally: the connection is "<gateway
	// name>-bb-<Name>", and every method naming a backbone peer takes it.
	// Empty means ID, which must then be usable in a connection name.
	Name string
	// ID is the peer gateway's backbone identity (its BackboneID).
	ID    string
	Addr  netip.Addr
	IfID  uint32
	Epoch uint64
	// LocalTS and RemoteTS bound what crosses the backbone; empty means
	// every address of ClientSubnet's family.
	LocalTS  []netip.Prefix
	RemoteTS []netip.Prefix
}

type backbonePeer struct {
	peer  BackbonePeer
	conn  Connection
	iface string
}

// Gateway is the IPsec gateway side: a single responder connection that
// accepts every client (remote identity %any) on one XFRM interface, plus
// one connection per backbone peer, each on its own interface. Of two
// peers, the one with the lexically smaller backbone identity initiates
// (start_action=start) and the other only responds, so they never race
// to create two IKE_SAs for one link.
//
// Clients and peers are kept apart by identity as well as by key: the
// client PSK is owned by LocalID alone and the backbone PSK by BackboneID
// and the peer, so each key is only ever a candidate for its own role.
type Gateway struct {
	cfg GatewayConfig
	ike IKE
	net Net

	mu         sync.Mutex
	started    bool
	closed     bool
	backbone   map[string]*backbonePeer // by BackbonePeer name
	pending    map[string]bool
	pendingIDs map[string]bool // backbone identities being added
	ifIDs      map[uint32]string

	routeMu sync.Mutex
	routes  *routeSet
	uplink  string // backbone peer the Uplink routes point at

	clientIface string
	clientRoute Route
	rule        *Rule
}

var errGatewayClosed = errors.New("ipsec: gateway is closed")

// NewGateway validates cfg. Nothing is touched until Start.
func NewGateway(cfg GatewayConfig, ike IKE, n Net) (*Gateway, error) {
	cfg.setDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	g := &Gateway{
		cfg:         cfg,
		ike:         ike,
		net:         n,
		backbone:    map[string]*backbonePeer{},
		pending:     map[string]bool{},
		pendingIDs:  map[string]bool{},
		ifIDs:       map[uint32]string{cfg.ClientIfID: "clients"},
		routes:      newRouteSet(n),
		clientIface: ifaceName(cfg.InterfacePrefix, cfg.ClientIfID),
	}
	g.clientRoute = Route{Dst: cfg.ClientSubnet.Masked(), Dev: g.clientIface}
	return g, nil
}

// ResponderName is the connection every client's IKE_SA belongs to.
func (g *Gateway) ResponderName() string { return g.cfg.Name + "-clients" }

func (g *Gateway) backboneName(name string) string { return g.cfg.Name + "-bb-" + name }

func (p BackbonePeer) name() string {
	if p.Name != "" {
		return p.Name
	}
	return p.ID
}

func (g *Gateway) family() Family { return familyOf(g.cfg.ClientSubnet.Addr()) }

func (g *Gateway) responder() Connection {
	served := g.cfg.Served
	if len(served) == 0 {
		served = []netip.Prefix{allAddresses(g.family())}
	}
	return Connection{
		Name:         g.ResponderName(),
		LocalAddr:    g.cfg.LocalAddr,
		LocalID:      g.cfg.LocalID,
		RemoteID:     AnyID,
		Auth:         AuthPSK,
		PSK:          g.cfg.ClientPSK,
		LocalTS:      served,
		RemoteTS:     []netip.Prefix{g.cfg.ClientSubnet.Masked()},
		IfID:         g.cfg.ClientIfID,
		IKEProposals: g.cfg.IKEProposals,
		ESPProposals: g.cfg.ESPProposals,
		DPDDelay:     g.cfg.DPDDelay,
		Start:        StartNone,
	}
}

func (g *Gateway) cleanupCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), g.cfg.CleanupTimeout)
}

// Start creates the client XFRM interface and its route, the rule for
// the gateway's table (if any), loads the client PSK (owned by LocalID
// alone, which every client exchange names) and the %any responder
// connection. On failure everything is undone.
func (g *Gateway) Start(ctx context.Context) error {
	g.mu.Lock()
	switch {
	case g.closed:
		g.mu.Unlock()
		return errGatewayClosed
	case g.started:
		g.mu.Unlock()
		return errors.New("ipsec: gateway already started")
	}
	g.started = true
	g.mu.Unlock()

	var undo []func(context.Context) error
	err := g.start(ctx, &undo)
	if err == nil {
		return nil
	}
	cctx, cancel := g.cleanupCtx(ctx)
	defer cancel()
	var undoErrs []error
	for i := len(undo) - 1; i >= 0; i-- {
		undoErrs = append(undoErrs, undo[i](cctx))
	}
	g.mu.Lock()
	g.started = false
	g.rule = nil
	g.mu.Unlock()
	if uerr := errors.Join(undoErrs...); uerr != nil {
		return fmt.Errorf("ipsec: start gateway: %w (rollback incomplete: %v)", err, uerr)
	}
	return fmt.Errorf("ipsec: start gateway: %w", err)
}

func (g *Gateway) start(ctx context.Context, undo *[]func(context.Context) error) error {
	iface := g.clientIface
	if err := g.net.AddXfrmInterface(iface, g.cfg.ClientIfID, ""); err != nil {
		return err
	}
	*undo = append(*undo, func(context.Context) error { return ignoreNotExist(g.net.DeleteLink(iface)) })
	if g.cfg.InnerAddr.IsValid() {
		if err := g.net.AddAddr(iface, hostPrefix(g.cfg.InnerAddr)); err != nil {
			return err
		}
	}
	if err := g.net.SetLinkUp(iface); err != nil {
		return err
	}
	// Replies to clients go into the tunnel; the route goes with the
	// interface when it is deleted.
	if err := g.net.RouteReplace(g.clientRoute); err != nil {
		return err
	}
	if g.cfg.Table != 0 && g.cfg.Table != MainTable {
		rule := Rule{Iif: iface, Table: g.cfg.Table, Priority: g.cfg.RulePriority, Family: g.family()}
		if err := g.net.RuleAdd(rule); err != nil {
			return err
		}
		*undo = append(*undo, func(context.Context) error { return ignoreNotExist(g.net.RuleDel(rule)) })
		g.mu.Lock()
		g.rule = &rule
		g.mu.Unlock()
	}
	conn := g.responder()
	secret := SharedSecret{ID: conn.Name, PSK: g.cfg.ClientPSK, Owners: []string{g.cfg.LocalID}}
	if err := g.ike.LoadShared(ctx, secret); err != nil {
		return err
	}
	*undo = append(*undo, func(cctx context.Context) error { return ignoreNotFound(g.ike.UnloadShared(cctx, secret.ID)) })
	return g.ike.LoadConn(ctx, conn)
}

func (g *Gateway) requireStarted() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case g.closed:
		return errGatewayClosed
	case !g.started:
		return errors.New("ipsec: gateway not started")
	}
	return nil
}

// Clients reports the IKE_SAs clients currently hold with this gateway.
func (g *Gateway) Clients(ctx context.Context) ([]IKESA, error) {
	if err := g.requireStarted(); err != nil {
		return nil, err
	}
	return g.ike.ListSAs(ctx, g.ResponderName())
}

// FenceClient tears down every IKE_SA held by the client with identity,
// by unique id, leaving every other client's SAs alone. It returns how
// many it tore down.
func (g *Gateway) FenceClient(ctx context.Context, identity string) (int, error) {
	if !idRE.MatchString(identity) {
		return 0, fmt.Errorf("ipsec: client identity %q must match %s", identity, idRE)
	}
	sas, err := g.Clients(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	var errs []error
	for _, sa := range sas {
		if sa.RemoteID != identity {
			continue
		}
		if err := ignoreNotFound(g.ike.TerminateIKEByID(ctx, sa.UniqueID)); err != nil {
			errs = append(errs, err)
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}

func (g *Gateway) backboneConnection(p BackbonePeer) Connection {
	all := []netip.Prefix{allAddresses(g.family())}
	local, remote := p.LocalTS, p.RemoteTS
	if len(local) == 0 {
		local = all
	}
	if len(remote) == 0 {
		remote = all
	}
	start := StartNone
	if g.cfg.BackboneID < p.ID {
		start = StartStart
	}
	return Connection{
		Name:         g.backboneName(p.name()),
		Epoch:        p.Epoch,
		LocalAddr:    g.cfg.LocalAddr,
		RemoteAddr:   p.Addr,
		LocalID:      g.cfg.BackboneID,
		RemoteID:     p.ID,
		Auth:         AuthPSK,
		PSK:          g.cfg.BackbonePSK,
		LocalTS:      local,
		RemoteTS:     remote,
		IfID:         p.IfID,
		IKEProposals: g.cfg.IKEProposals,
		ESPProposals: g.cfg.ESPProposals,
		DPDDelay:     g.cfg.DPDDelay,
		Start:        start,
	}
}

// AddBackbone loads the backbone connection to peer p on its own XFRM
// interface. If this gateway's identity is the smaller one it initiates
// (start_action=start, so charon brings the SA up on load and the call
// returns without waiting; see WaitBackbone); otherwise it waits for the
// peer to. On failure everything is undone.
func (g *Gateway) AddBackbone(ctx context.Context, p BackbonePeer) error {
	if err := g.requireStarted(); err != nil {
		return err
	}
	if p.ID == g.cfg.BackboneID || p.ID == g.cfg.LocalID {
		return fmt.Errorf("ipsec: backbone peer %s is this gateway itself", p.ID)
	}
	if err := checkAddr("backbone peer "+p.ID, p.Addr); err != nil {
		return err
	}
	if err := checkSameFamily("backbone peer "+p.ID, g.cfg.LocalAddr, p.Addr); err != nil {
		return err
	}
	f := g.family()
	if err := checkPrefixes("backbone traffic selector", f, append(append([]netip.Prefix(nil), p.LocalTS...), p.RemoteTS...)); err != nil {
		return err
	}
	conn := g.backboneConnection(p)
	if err := conn.Validate(); err != nil {
		return err
	}

	name := p.name()
	g.mu.Lock()
	switch {
	case g.closed:
		g.mu.Unlock()
		return errGatewayClosed
	case g.backbone[name] != nil || g.pending[name] || g.pendingIDs[p.ID] || g.hasBackboneID(p.ID):
		g.mu.Unlock()
		return fmt.Errorf("ipsec: backbone peer %s (%s) is already added or being added: %w", name, p.ID, ErrExist)
	case g.ifIDs[p.IfID] != "":
		other := g.ifIDs[p.IfID]
		g.mu.Unlock()
		return fmt.Errorf("ipsec: if_id %d of backbone peer %s is already used by %s: %w", p.IfID, name, other, ErrExist)
	}
	g.pending[name] = true
	g.pendingIDs[p.ID] = true
	g.ifIDs[p.IfID] = name
	g.mu.Unlock()

	iface := ifaceName(g.cfg.InterfacePrefix, p.IfID)
	var undo []func(context.Context) error
	err := g.addBackbone(ctx, conn, iface, &undo)

	g.mu.Lock()
	delete(g.pending, name)
	delete(g.pendingIDs, p.ID)
	if err == nil && g.closed {
		err = errGatewayClosed
	}
	if err == nil {
		g.backbone[name] = &backbonePeer{peer: p, conn: conn, iface: iface}
		g.mu.Unlock()
		return nil
	}
	delete(g.ifIDs, p.IfID)
	g.mu.Unlock()

	cctx, cancel := g.cleanupCtx(ctx)
	defer cancel()
	var undoErrs []error
	for i := len(undo) - 1; i >= 0; i-- {
		undoErrs = append(undoErrs, undo[i](cctx))
	}
	if uerr := errors.Join(undoErrs...); uerr != nil {
		return fmt.Errorf("ipsec: add backbone peer %s: %w (rollback incomplete: %v)", name, err, uerr)
	}
	return fmt.Errorf("ipsec: add backbone peer %s: %w", name, err)
}

func (g *Gateway) addBackbone(ctx context.Context, conn Connection, iface string, undo *[]func(context.Context) error) error {
	if err := g.net.AddXfrmInterface(iface, conn.IfID, ""); err != nil {
		return err
	}
	*undo = append(*undo, func(context.Context) error { return ignoreNotExist(g.net.DeleteLink(iface)) })
	if err := g.net.SetLinkUp(iface); err != nil {
		return err
	}
	secret := SharedSecret{ID: conn.Name, PSK: conn.PSK, Owners: []string{conn.LocalID, conn.RemoteID}}
	if err := g.ike.LoadShared(ctx, secret); err != nil {
		return err
	}
	*undo = append(*undo, func(cctx context.Context) error { return ignoreNotFound(g.ike.UnloadShared(cctx, secret.ID)) })
	if err := g.ike.LoadConn(ctx, conn); err != nil {
		return err
	}
	*undo = append(*undo, func(cctx context.Context) error { return ignoreNotFound(g.ike.UnloadConn(cctx, conn.Name)) })
	// With start_action=start, loading the connection already started an
	// initiation; make sure a failed add does not leave it running.
	*undo = append(*undo, func(cctx context.Context) error { return ignoreNotFound(g.ike.TerminateIKE(cctx, conn.Name)) })
	return ctx.Err()
}

// hasBackboneID reports whether a backbone peer with identity id exists.
// g.mu must be held.
func (g *Gateway) hasBackboneID(id string) bool {
	for _, p := range g.backbone {
		if p.peer.ID == id {
			return true
		}
	}
	return false
}

func (g *Gateway) peer(name string) (*backbonePeer, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, errGatewayClosed
	}
	p := g.backbone[name]
	if p == nil {
		return nil, fmt.Errorf("ipsec: no backbone peer %s: %w", name, ErrNotFound)
	}
	return p, nil
}

// WaitBackbone blocks until the backbone SA with peer name is warm.
func (g *Gateway) WaitBackbone(ctx context.Context, name string) (IKESA, error) {
	p, err := g.peer(name)
	if err != nil {
		return IKESA{}, err
	}
	return WaitWarm(ctx, g.ike, p.conn.Name, g.cfg.PollInterval)
}

// FenceBackboneBelow tears down the backbone CHILD_SAs with peer name whose
// epoch is lower than epoch.
func (g *Gateway) FenceBackboneBelow(ctx context.Context, name string, epoch uint64) error {
	p, err := g.peer(name)
	if err != nil {
		return err
	}
	return fenceBelow(ctx, g.ike, p.conn.Name, epoch)
}

// Uplink points client traffic for prefixes at backbone peer name's XFRM
// interface, in the gateway's table, with the same in-place replace,
// undo-on-failure and withdrawal as Client.Promote. A /0 is accepted only
// in a table of its own: in the main table it would hijack the gateway's
// own default route.
func (g *Gateway) Uplink(ctx context.Context, name string, prefixes ...netip.Prefix) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := g.peer(name)
	if err != nil {
		return err
	}
	if len(prefixes) == 0 {
		return errors.New("ipsec: Uplink needs at least one prefix")
	}
	if err := checkPrefixes("uplink", g.family(), prefixes); err != nil {
		return err
	}
	ownTable := g.cfg.Table != 0 && g.cfg.Table != MainTable
	want := make([]Route, 0, len(prefixes))
	seen := map[netip.Prefix]bool{}
	for _, pf := range prefixes {
		pf = pf.Masked()
		if pf.Bits() == 0 && !ownTable {
			return fmt.Errorf("ipsec: refusing to route %s in the main table: it would replace the gateway's own default route", pf)
		}
		if seen[pf] {
			continue
		}
		seen[pf] = true
		want = append(want, Route{Dst: pf, Dev: p.iface, Table: g.cfg.Table})
	}
	g.routeMu.Lock()
	defer g.routeMu.Unlock()
	if err := g.routes.apply(want); err != nil {
		return fmt.Errorf("ipsec: uplink via %s: %w", name, err)
	}
	g.uplink = name
	return nil
}

// UplinkRoutes returns the Uplink routes installed.
func (g *Gateway) UplinkRoutes() []Route {
	g.routeMu.Lock()
	defer g.routeMu.Unlock()
	return g.routes.routes()
}

// RemoveBackbone tears down the backbone with peer name. The peer the
// Uplink routes point at cannot be removed.
func (g *Gateway) RemoveBackbone(ctx context.Context, name string) error {
	g.routeMu.Lock()
	inUse := g.uplink == name && len(g.routes.installed) > 0
	g.routeMu.Unlock()
	if inUse {
		return fmt.Errorf("ipsec: backbone peer %s carries the uplink routes; move them first", name)
	}
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return errGatewayClosed
	}
	p := g.backbone[name]
	if p == nil {
		g.mu.Unlock()
		return fmt.Errorf("ipsec: no backbone peer %s: %w", name, ErrNotFound)
	}
	delete(g.backbone, name)
	g.pending[name] = true
	g.mu.Unlock()

	err := g.tearDownBackbone(ctx, p)

	g.mu.Lock()
	delete(g.pending, name)
	delete(g.ifIDs, p.peer.IfID)
	g.mu.Unlock()
	return err
}

func (g *Gateway) tearDownBackbone(ctx context.Context, p *backbonePeer) error {
	cctx, cancel := g.cleanupCtx(ctx)
	defer cancel()
	err := errors.Join(
		ignoreNotFound(g.ike.TerminateIKE(cctx, p.conn.Name)),
		ignoreNotFound(g.ike.UnloadConn(cctx, p.conn.Name)),
		ignoreNotFound(g.ike.UnloadShared(cctx, p.conn.Name)),
		ignoreNotExist(g.net.DeleteLink(p.iface)),
	)
	if err != nil {
		return fmt.Errorf("ipsec: remove backbone peer %s: %w", p.peer.ID, err)
	}
	return nil
}

// Close withdraws the Uplink routes, tears down every backbone and every
// client SA, and removes what Start created.
func (g *Gateway) Close(ctx context.Context) error {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return nil
	}
	g.closed = true
	started := g.started
	peers := make([]*backbonePeer, 0, len(g.backbone))
	for _, p := range g.backbone {
		peers = append(peers, p)
	}
	g.backbone = map[string]*backbonePeer{}
	rule := g.rule
	g.mu.Unlock()

	var errs []error
	g.routeMu.Lock()
	errs = append(errs, g.routes.clear())
	g.uplink = ""
	g.routeMu.Unlock()
	for _, p := range peers {
		errs = append(errs, g.tearDownBackbone(ctx, p))
	}
	if started {
		cctx, cancel := g.cleanupCtx(ctx)
		defer cancel()
		name := g.ResponderName()
		errs = append(errs,
			ignoreNotFound(g.ike.TerminateIKE(cctx, name)),
			ignoreNotFound(g.ike.UnloadConn(cctx, name)),
			ignoreNotFound(g.ike.UnloadShared(cctx, name)),
		)
		if rule != nil {
			errs = append(errs, ignoreNotExist(g.net.RuleDel(*rule)))
		}
		errs = append(errs, ignoreNotExist(g.net.DeleteLink(g.clientIface)))
	}
	return errors.Join(errs...)
}
