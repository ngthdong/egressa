package ipsec

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DefaultCleanupTimeout bounds rollback and teardown. Cleanup runs on a
// context detached from the caller's, so a cancelled Add still undoes
// everything it did, but it must not hang on a dead peer forever.
const DefaultCleanupTimeout = 10 * time.Second

// DefaultInterfacePrefix names the XFRM interfaces a Client creates.
const DefaultInterfacePrefix = "egx"

var ifPrefixRE = regexp.MustCompile(`^[a-z][a-z0-9]{0,4}$`)

// ClientConfig configures a Client.
type ClientConfig struct {
	// Name prefixes every connection and secret this client loads, so
	// several clients can share one charon. Default "egressa".
	Name string
	// LocalID is this client's IKE identity; PSK its pre-shared key.
	LocalID string
	PSK     string
	// VirtualIP is the client's address inside every tunnel: the local
	// traffic selector of each CHILD_SA and the source of each tunnel
	// route.
	VirtualIP netip.Addr
	// LocalAddr optionally pins the underlay address IKE uses.
	LocalAddr netip.Addr

	// FullTunnel routes all traffic through the active gateway with the
	// two halves of the address space (0.0.0.0/1 and 128.0.0.0/1, or ::/1
	// and 8000::/1), more specific than the default route, which is never
	// modified. Every gateway and every controller then gets a host bypass
	// route through the underlay, so IKE and control traffic never loops
	// into a tunnel.
	FullTunnel bool
	// Controllers are control-plane addresses kept off the tunnels.
	Controllers []netip.Addr

	// Table is the routing table for tunnel and bypass routes; 0 is the
	// main table. A table other than main is only consulted if the caller
	// adds policy rules for it.
	Table int
	// DPDDelay enables dead peer detection with dpd_action=clear, so a
	// dead gateway's SA disappears and WaitDown returns.
	DPDDelay     time.Duration
	IKEProposals []string
	ESPProposals []string
	// InterfacePrefix names XFRM interfaces "<prefix><if_id>"; at most 5
	// lowercase characters. Default "egx".
	InterfacePrefix string
	// Underlay optionally binds the XFRM interfaces to a lower device.
	Underlay string

	// PollInterval is the fallback re-query period of waits; default
	// DefaultPollInterval. CleanupTimeout bounds rollback and teardown;
	// default DefaultCleanupTimeout.
	PollInterval   time.Duration
	CleanupTimeout time.Duration
}

func (cfg *ClientConfig) setDefaults() {
	if cfg.Name == "" {
		cfg.Name = "egressa"
	}
	if cfg.InterfacePrefix == "" {
		cfg.InterfacePrefix = DefaultInterfacePrefix
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = DefaultPollInterval
	}
	if cfg.CleanupTimeout <= 0 {
		cfg.CleanupTimeout = DefaultCleanupTimeout
	}
}

func (cfg ClientConfig) validate() error {
	if !nameRE.MatchString(cfg.Name) {
		return fmt.Errorf("ipsec: client name %q must match %s", cfg.Name, nameRE)
	}
	if !idRE.MatchString(cfg.LocalID) {
		return fmt.Errorf("ipsec: client LocalID %q must match %s", cfg.LocalID, idRE)
	}
	if err := validatePSK("client", cfg.PSK); err != nil {
		return err
	}
	if err := checkAddr("client VirtualIP", cfg.VirtualIP); err != nil {
		return err
	}
	if cfg.LocalAddr.IsValid() {
		if err := checkAddr("client LocalAddr", cfg.LocalAddr); err != nil {
			return err
		}
	}
	for _, a := range cfg.Controllers {
		if err := checkAddr("controller", a); err != nil {
			return err
		}
		if err := checkSameFamily("controller", cfg.LocalAddr, a); err != nil {
			return err
		}
	}
	if cfg.Table < 0 {
		return fmt.Errorf("ipsec: client routing table %d is negative", cfg.Table)
	}
	if !ifPrefixRE.MatchString(cfg.InterfacePrefix) {
		return fmt.Errorf("ipsec: interface prefix %q must match %s", cfg.InterfacePrefix, ifPrefixRE)
	}
	if cfg.DPDDelay < 0 {
		return fmt.Errorf("ipsec: client DPDDelay must not be negative")
	}
	return nil
}

// Peer is one gateway a Client keeps an SA with.
type Peer struct {
	// Name identifies the gateway; its IKE connection is "<client
	// name>-<Name>".
	Name string
	Addr netip.Addr // the gateway's underlay address
	ID   string     // the gateway's IKE identity
	// IfID binds the CHILD_SA to this peer's own XFRM interface. Every
	// peer of a client needs a distinct IfID.
	IfID  uint32
	Epoch uint64
	// Prefixes the gateway carries for this client: the CHILD_SA's remote
	// traffic selectors. Empty means every address of the VirtualIP's
	// family.
	Prefixes []netip.Prefix
}

type clientPeer struct {
	peer  Peer
	conn  Connection
	iface string
}

// Client is the IPsec client side: one route-based CHILD_SA per gateway,
// each bound by if_id to its own XFRM interface. A peer that is up but
// that no route points at is a warm standby; Promote moves the routes.
// CHILD_SAs are named by epoch (ChildName) so FenceBelow can tear down
// the ones a newer epoch superseded.
//
// The mutex is never held while IKE negotiates: Add records the peer as
// pending, releases the lock, and negotiates.
type Client struct {
	cfg ClientConfig
	ike IKE
	net Net

	mu      sync.Mutex
	peers   map[string]*clientPeer
	pending map[string]bool // Add or Remove in flight, by peer name
	ifIDs   map[uint32]string
	active  string
	closed  bool

	routeMu sync.Mutex // serializes route changes
	routes  *routeSet

	bypassMu sync.Mutex
	bypass   map[netip.Addr]*bypassRoute
}

type bypassRoute struct {
	route Route
	owned bool // created by this client; only then is it deleted
	refs  int
}

// NewClient validates cfg and, in full-tunnel mode, installs the bypass
// routes for the controllers.
func NewClient(cfg ClientConfig, ike IKE, n Net) (*Client, error) {
	cfg.setDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	c := &Client{
		cfg:     cfg,
		ike:     ike,
		net:     n,
		peers:   map[string]*clientPeer{},
		pending: map[string]bool{},
		ifIDs:   map[uint32]string{},
		routes:  newRouteSet(n),
		bypass:  map[netip.Addr]*bypassRoute{},
	}
	if cfg.FullTunnel {
		for i, a := range cfg.Controllers {
			if err := c.acquireBypass(a); err != nil {
				for _, done := range cfg.Controllers[:i] {
					_ = c.releaseBypass(done)
				}
				return nil, fmt.Errorf("ipsec: bypass route for controller %s: %w", a, err)
			}
		}
	}
	return c, nil
}

func (c *Client) connName(peer string) string { return c.cfg.Name + "-" + peer }

func (c *Client) connection(p Peer) Connection {
	remote := p.Prefixes
	if len(remote) == 0 {
		remote = []netip.Prefix{allAddresses(familyOf(c.cfg.VirtualIP))}
	}
	return Connection{
		Name:         c.connName(p.Name),
		Epoch:        p.Epoch,
		LocalAddr:    c.cfg.LocalAddr,
		RemoteAddr:   p.Addr,
		LocalID:      c.cfg.LocalID,
		RemoteID:     p.ID,
		Auth:         AuthPSK,
		PSK:          c.cfg.PSK,
		LocalTS:      []netip.Prefix{hostPrefix(c.cfg.VirtualIP)},
		RemoteTS:     remote,
		IfID:         p.IfID,
		IKEProposals: c.cfg.IKEProposals,
		ESPProposals: c.cfg.ESPProposals,
		DPDDelay:     c.cfg.DPDDelay,
		Start:        StartNone,
	}
}

func (c *Client) validatePeer(p Peer) (Connection, error) {
	if err := checkAddr("gateway "+p.Name, p.Addr); err != nil {
		return Connection{}, err
	}
	if err := checkSameFamily("gateway "+p.Name, c.cfg.LocalAddr, p.Addr); err != nil {
		return Connection{}, err
	}
	if err := checkPrefixes("gateway "+p.Name+" prefix", familyOf(c.cfg.VirtualIP), p.Prefixes); err != nil {
		return Connection{}, err
	}
	conn := c.connection(p)
	if err := conn.Validate(); err != nil {
		return Connection{}, err
	}
	return conn, nil
}

// cleanupCtx is detached from the caller's context, so cleanup still runs
// when the caller gave up, but it is bounded.
func (c *Client) cleanupCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), c.cfg.CleanupTimeout)
}

// Add brings up a warm standby SA with gateway p: its XFRM interface,
// (in full-tunnel mode) a bypass route to it, its PSK and connection, and
// an established CHILD_SA. No route is pointed at it; see Promote.
//
// If any step fails, or ctx ends, everything already done is undone, on a
// context detached from ctx, including terminating an IKE_SA that the
// initiate may have left behind. Adding a peer whose name or if_id is
// already in use, or already being added, fails at once.
func (c *Client) Add(ctx context.Context, p Peer) error {
	conn, err := c.validatePeer(p)
	if err != nil {
		return err
	}
	c.mu.Lock()
	switch {
	case c.closed:
		c.mu.Unlock()
		return errClientClosed
	case c.peers[p.Name] != nil || c.pending[p.Name]:
		c.mu.Unlock()
		return fmt.Errorf("ipsec: gateway %s is already added or being added: %w", p.Name, ErrExist)
	case c.ifIDs[p.IfID] != "":
		other := c.ifIDs[p.IfID]
		c.mu.Unlock()
		return fmt.Errorf("ipsec: if_id %d of gateway %s is already used by gateway %s: %w", p.IfID, p.Name, other, ErrExist)
	}
	c.pending[p.Name] = true
	c.ifIDs[p.IfID] = p.Name
	c.mu.Unlock()

	iface := ifaceName(c.cfg.InterfacePrefix, p.IfID)
	var undo []func(context.Context) error
	err = c.bringUp(ctx, p, conn, iface, &undo)

	c.mu.Lock()
	delete(c.pending, p.Name)
	if err == nil && c.closed {
		err = errClientClosed
	}
	if err == nil {
		c.peers[p.Name] = &clientPeer{peer: p, conn: conn, iface: iface}
		c.mu.Unlock()
		return nil
	}
	delete(c.ifIDs, p.IfID)
	c.mu.Unlock()

	cctx, cancel := c.cleanupCtx(ctx)
	defer cancel()
	var undoErrs []error
	for i := len(undo) - 1; i >= 0; i-- {
		undoErrs = append(undoErrs, undo[i](cctx))
	}
	if uerr := errors.Join(undoErrs...); uerr != nil {
		return fmt.Errorf("ipsec: add gateway %s: %w (rollback incomplete: %v)", p.Name, err, uerr)
	}
	return fmt.Errorf("ipsec: add gateway %s: %w", p.Name, err)
}

var errClientClosed = errors.New("ipsec: client is closed")

func (c *Client) bringUp(ctx context.Context, p Peer, conn Connection, iface string, undo *[]func(context.Context) error) error {
	if err := c.net.AddXfrmInterface(iface, p.IfID, c.cfg.Underlay); err != nil {
		return err
	}
	*undo = append(*undo, func(context.Context) error { return ignoreNotExist(c.net.DeleteLink(iface)) })
	if err := c.net.AddAddr(iface, hostPrefix(c.cfg.VirtualIP)); err != nil {
		return err
	}
	if err := c.net.SetLinkUp(iface); err != nil {
		return err
	}
	if c.cfg.FullTunnel {
		if err := c.acquireBypass(p.Addr); err != nil {
			return err
		}
		*undo = append(*undo, func(context.Context) error { return c.releaseBypass(p.Addr) })
	}
	secret := SharedSecret{ID: conn.Name, PSK: conn.PSK, Owners: []string{conn.LocalID, conn.RemoteID}}
	if err := c.ike.LoadShared(ctx, secret); err != nil {
		return err
	}
	*undo = append(*undo, func(cctx context.Context) error { return ignoreNotFound(c.ike.UnloadShared(cctx, secret.ID)) })
	if err := c.ike.LoadConn(ctx, conn); err != nil {
		return err
	}
	*undo = append(*undo, func(cctx context.Context) error { return ignoreNotFound(c.ike.UnloadConn(cctx, conn.Name)) })
	// Registered before initiating: a failed, timed-out or cancelled
	// initiate can still leave a (half-)established IKE_SA behind.
	*undo = append(*undo, func(cctx context.Context) error { return ignoreNotFound(c.ike.TerminateIKE(cctx, conn.Name)) })
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.ike.Initiate(ctx, conn.Name, ChildName(conn.Name, conn.Epoch))
}

// acquireBypass makes sure a host route to dst goes through the underlay,
// counting references so a destination shared by several users is kept
// until the last one releases it. A route that already existed is used
// but never owned, so it is never deleted.
func (c *Client) acquireBypass(dst netip.Addr) error {
	c.bypassMu.Lock()
	defer c.bypassMu.Unlock()
	if b := c.bypass[dst]; b != nil {
		b.refs++
		return nil
	}
	r, err := c.underlayRoute(dst)
	if err != nil {
		return err
	}
	owned := true
	if err := c.net.RouteAdd(r); err != nil {
		if !errors.Is(err, ErrExist) {
			return err
		}
		owned = false
	}
	c.bypass[dst] = &bypassRoute{route: r, owned: owned, refs: 1}
	return nil
}

func (c *Client) releaseBypass(dst netip.Addr) error {
	c.bypassMu.Lock()
	defer c.bypassMu.Unlock()
	b := c.bypass[dst]
	if b == nil {
		return nil
	}
	b.refs--
	if b.refs > 0 {
		return nil
	}
	delete(c.bypass, dst)
	if !b.owned {
		return nil
	}
	return ignoreNotExist(c.net.RouteDel(b.route))
}

// underlayRoute resolves the host route to dst through the underlay. Once
// the full-tunnel halves are installed, an ordinary lookup for a gateway
// added later would answer with one of our own tunnel interfaces; the
// path the halves overrode is then the main table's default route, read
// (never changed) directly.
func (c *Client) underlayRoute(dst netip.Addr) (Route, error) {
	r, err := c.net.RouteGet(dst)
	if err != nil {
		return Route{}, err
	}
	if c.isOurInterface(r.Dev) {
		def, err := c.net.DefaultRoute(familyOf(dst))
		if err != nil {
			return Route{}, fmt.Errorf("ipsec: %s resolves into a tunnel and there is no default route to bypass it through: %w", dst, err)
		}
		r = def
	}
	return Route{Dst: hostPrefix(dst), Gw: r.Gw, Dev: r.Dev, Table: c.cfg.Table}, nil
}

func (c *Client) isOurInterface(dev string) bool {
	if dev == "" || !strings.HasPrefix(dev, c.cfg.InterfacePrefix) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for ifID := range c.ifIDs {
		if ifaceName(c.cfg.InterfacePrefix, ifID) == dev {
			return true
		}
	}
	return false
}

func (c *Client) peer(name string) (*clientPeer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errClientClosed
	}
	p := c.peers[name]
	if p == nil {
		return nil, fmt.Errorf("ipsec: no gateway %s: %w", name, ErrNotFound)
	}
	return p, nil
}

// Promote points prefixes at gateway name's XFRM interface, replacing each
// route in place. In full-tunnel mode prefixes must be empty: the two
// halves of the address space are used. If a replace fails midway, every
// prefix already moved is put back; prefixes routed before but absent now
// are withdrawn. A /0 prefix is refused: the default route is never
// touched.
func (c *Client) Promote(ctx context.Context, name string, prefixes ...netip.Prefix) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, err := c.peer(name)
	if err != nil {
		return err
	}
	f := familyOf(c.cfg.VirtualIP)
	if c.cfg.FullTunnel {
		if len(prefixes) != 0 {
			return fmt.Errorf("ipsec: full-tunnel client routes everything; Promote takes no prefixes")
		}
		prefixes = fullTunnelPrefixes(f)
	} else if len(prefixes) == 0 {
		return fmt.Errorf("ipsec: Promote of a split-tunnel client needs at least one prefix")
	}
	if err := checkPrefixes("promoted", f, prefixes); err != nil {
		return err
	}
	want := make([]Route, 0, len(prefixes))
	seen := map[netip.Prefix]bool{}
	for _, pf := range prefixes {
		pf = pf.Masked()
		if pf.Bits() == 0 {
			return fmt.Errorf("ipsec: refusing to route %s: the default route is never touched (use FullTunnel)", pf)
		}
		if seen[pf] {
			continue
		}
		seen[pf] = true
		want = append(want, Route{Dst: pf, Dev: p.iface, Src: c.cfg.VirtualIP, Table: c.cfg.Table})
	}

	c.routeMu.Lock()
	defer c.routeMu.Unlock()
	if err := c.routes.apply(want); err != nil {
		return fmt.Errorf("ipsec: promote %s: %w", name, err)
	}
	c.mu.Lock()
	c.active = name
	c.mu.Unlock()
	return nil
}

// Routes returns the tunnel routes this client has installed.
func (c *Client) Routes() []Route {
	c.routeMu.Lock()
	defer c.routeMu.Unlock()
	return c.routes.routes()
}

// Active returns the gateway the routes point at, if any.
func (c *Client) Active() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

// Peers returns the names of the gateways added.
func (c *Client) Peers() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.peers))
	for n := range c.peers {
		out = append(out, n)
	}
	return out
}

// Remove tears down gateway name: its SAs, connection, secret, bypass
// route and XFRM interface. The active gateway cannot be removed; promote
// another first, so traffic is never left without a tunnel.
func (c *Client) Remove(ctx context.Context, name string) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errClientClosed
	}
	p := c.peers[name]
	if p == nil {
		c.mu.Unlock()
		return fmt.Errorf("ipsec: no gateway %s: %w", name, ErrNotFound)
	}
	if c.active == name {
		c.mu.Unlock()
		return fmt.Errorf("ipsec: gateway %s carries the routes; promote another gateway before removing it", name)
	}
	delete(c.peers, name)
	c.pending[name] = true
	c.mu.Unlock()

	err := c.tearDown(ctx, p)

	c.mu.Lock()
	delete(c.pending, name)
	delete(c.ifIDs, p.peer.IfID)
	c.mu.Unlock()
	return err
}

func (c *Client) tearDown(ctx context.Context, p *clientPeer) error {
	cctx, cancel := c.cleanupCtx(ctx)
	defer cancel()
	errs := []error{
		ignoreNotFound(c.ike.TerminateIKE(cctx, p.conn.Name)),
		ignoreNotFound(c.ike.UnloadConn(cctx, p.conn.Name)),
		ignoreNotFound(c.ike.UnloadShared(cctx, p.conn.Name)),
	}
	if c.cfg.FullTunnel {
		errs = append(errs, c.releaseBypass(p.peer.Addr))
	}
	errs = append(errs, ignoreNotExist(c.net.DeleteLink(p.iface)))
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("ipsec: remove gateway %s: %w", p.peer.Name, err)
	}
	return nil
}

// FenceBelow tears down every CHILD_SA of gateway name whose epoch is
// lower than epoch: once ownership has moved on, traffic must not keep
// flowing over an SA of an older generation.
func (c *Client) FenceBelow(ctx context.Context, name string, epoch uint64) error {
	p, err := c.peer(name)
	if err != nil {
		return err
	}
	return fenceBelow(ctx, c.ike, p.conn.Name, epoch)
}

func fenceBelow(ctx context.Context, ike IKE, conn string, epoch uint64) error {
	sas, err := ike.ListSAs(ctx, conn)
	if err != nil {
		return err
	}
	var errs []error
	for _, sa := range sas {
		for _, child := range sa.Children {
			owner, e, ok := ParseChildName(child.Name)
			if !ok || owner != conn || e >= epoch {
				continue
			}
			errs = append(errs, ignoreNotFound(ike.TerminateChild(ctx, child.UniqueID)))
		}
	}
	return errors.Join(errs...)
}

// Advance moves gateway name to a new, higher epoch: it reloads the
// connection so its CHILD_SA carries the new epoch's name, brings that
// CHILD_SA up on the existing IKE_SA, and then fences the older ones. If
// the new CHILD_SA cannot be established, the old configuration is put
// back and the old CHILD_SA keeps carrying traffic.
func (c *Client) Advance(ctx context.Context, name string, epoch uint64) error {
	p, err := c.peer(name)
	if err != nil {
		return err
	}
	if epoch <= p.conn.Epoch {
		return fmt.Errorf("ipsec: advance %s to epoch %d: it is already at epoch %d", name, epoch, p.conn.Epoch)
	}
	next := p.conn
	next.Epoch = epoch
	if err := c.ike.LoadConn(ctx, next); err != nil {
		return err
	}
	if err := c.ike.Initiate(ctx, next.Name, ChildName(next.Name, epoch)); err != nil {
		cctx, cancel := c.cleanupCtx(ctx)
		defer cancel()
		if rerr := c.ike.LoadConn(cctx, p.conn); rerr != nil {
			return fmt.Errorf("ipsec: advance %s: %w (restoring the old connection failed: %v)", name, err, rerr)
		}
		return fmt.Errorf("ipsec: advance %s: %w", name, err)
	}
	c.mu.Lock()
	if cur := c.peers[name]; cur != nil {
		cur.conn = next
		cur.peer.Epoch = epoch
	}
	c.mu.Unlock()
	return fenceBelow(ctx, c.ike, next.Name, epoch)
}

// Warm reports whether gateway name currently has a warm SA.
func (c *Client) Warm(ctx context.Context, name string) (bool, error) {
	p, err := c.peer(name)
	if err != nil {
		return false, err
	}
	return IsWarm(ctx, c.ike, p.conn.Name)
}

// WaitWarm blocks until gateway name has a warm SA.
func (c *Client) WaitWarm(ctx context.Context, name string) (IKESA, error) {
	p, err := c.peer(name)
	if err != nil {
		return IKESA{}, err
	}
	return WaitWarm(ctx, c.ike, p.conn.Name, c.cfg.PollInterval)
}

// WaitDown blocks until gateway name has no established IKE_SA, which is
// how a dead gateway shows up once DPD (DPDDelay) has cleared it.
func (c *Client) WaitDown(ctx context.Context, name string) error {
	p, err := c.peer(name)
	if err != nil {
		return err
	}
	return WaitDown(ctx, c.ike, p.conn.Name, c.cfg.PollInterval)
}

// Close withdraws every route this client installed, tears down every
// gateway, and removes the bypass routes it created (only those). An Add
// still negotiating when Close runs rolls itself back when it finishes.
func (c *Client) Close(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	peers := make([]*clientPeer, 0, len(c.peers))
	for _, p := range c.peers {
		peers = append(peers, p)
	}
	c.peers = map[string]*clientPeer{}
	c.active = ""
	c.mu.Unlock()

	var errs []error
	c.routeMu.Lock()
	errs = append(errs, c.routes.clear())
	c.routeMu.Unlock()
	for _, p := range peers {
		errs = append(errs, c.tearDown(ctx, p))
		c.mu.Lock()
		delete(c.ifIDs, p.peer.IfID)
		c.mu.Unlock()
	}
	if c.cfg.FullTunnel {
		for _, a := range c.cfg.Controllers {
			errs = append(errs, c.releaseBypass(a))
		}
	}
	return errors.Join(errs...)
}
