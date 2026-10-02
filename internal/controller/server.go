// Package controller is the control plane: the one writer of gateway
// membership and of every session's ownership record (which access and
// egress gateway carry it, at which epoch). Gateways and clients reach it
// over the HTTP API in internal/api.
package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/control"
	"github.com/ngthdong/egressa/internal/telemetry"
)

const (
	gatewayKeyPrefix = "/egressa/gw/"
	clientKeyPrefix  = "/egressa/client/"

	// DefaultAliveAfter is how long a gateway may go without reporting
	// before it is marked not alive.
	DefaultAliveAfter = 10 * time.Second
	maxWait           = 60 * time.Second
)

var gatewayIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Config configures a Server.
type Config struct {
	Store control.KVStore
	// GatewayToken authorizes gateways; ClientToken authorizes opening a
	// session. Empty disables that check (for local testing only).
	GatewayToken string
	ClientToken  string
	Network      api.Network
	// Policy, if set, is stored as the current policy on start.
	Policy     *control.PolicyDocument
	AliveAfter time.Duration
	// Logger receives the controller's logs; nil means slog.Default().
	Logger *slog.Logger
	// Metrics, if set, receives the controller's metrics.
	Metrics *telemetry.ControllerMetrics
}

type clientRecord struct {
	ID         string     `json:"id"`
	PublicKey  string     `json:"public_key"`
	VirtualIP  netip.Addr `json:"virtual_ip"`
	SecretHash string     `json:"secret_hash"`
}

type linkEntry struct {
	link     api.Link
	received time.Time
}

// Server serves the controller's HTTP API.
type Server struct {
	cfg       Config
	log       *slog.Logger
	ownership *control.OwnershipService
	policy    *control.PolicyService
	now       func() time.Time

	// mu serializes every write, so allocations never race, and guards
	// the fields below.
	mu       sync.Mutex
	version  uint64
	changed  chan struct{}
	links    map[string]map[string]linkEntry
	lastSeen map[string]time.Time
	alive    map[string]bool
}

// New returns a Server over cfg.Store.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.Store == nil {
		return nil, errors.New("controller: a store is required")
	}
	n := cfg.Network
	if !n.ClientSubnet.IsValid() || !n.NodeSubnet.IsValid() || n.ProbePort == 0 {
		return nil, errors.New("controller: Network needs a client subnet, a node subnet and a probe port")
	}
	if !n.ClientSubnet.Addr().Is4() || !n.NodeSubnet.Addr().Is4() || n.ClientSubnet.Overlaps(n.NodeSubnet) {
		return nil, errors.New("controller: the client and node subnets must be disjoint IPv4 prefixes")
	}
	cfg.Network.ClientSubnet = n.ClientSubnet.Masked()
	cfg.Network.NodeSubnet = n.NodeSubnet.Masked()
	if cfg.AliveAfter <= 0 {
		cfg.AliveAfter = DefaultAliveAfter
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Server{
		cfg:       cfg,
		log:       cfg.Logger,
		ownership: control.NewOwnershipService(cfg.Store),
		policy:    control.NewPolicyService(cfg.Store),
		now:       time.Now,
		version:   1,
		changed:   make(chan struct{}),
		links:     make(map[string]map[string]linkEntry),
		lastSeen:  make(map[string]time.Time),
		alive:     make(map[string]bool),
	}
	if cfg.Policy != nil {
		if err := s.policy.Set(ctx, *cfg.Policy); err != nil {
			return nil, fmt.Errorf("controller: store policy: %w", err)
		}
	}
	return s, nil
}

// Run marks gateways not alive once they stop reporting, and refreshes
// the metrics, every second until ctx ends.
func (s *Server) Run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	s.publish(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweep()
			s.publish(ctx)
		}
	}
}

// publish hands the controller's numbers to the metrics.
func (s *Server) publish(ctx context.Context) {
	if s.cfg.Metrics == nil {
		return
	}
	gws, err := s.gateways(ctx)
	if err != nil {
		return
	}
	raw, err := s.cfg.Store.List(ctx, clientKeyPrefix)
	if err != nil {
		return
	}
	snap := telemetry.ControllerSnapshot{Sessions: len(raw)}
	s.mu.Lock()
	for _, g := range gws {
		if s.alive[g.ID] {
			snap.GatewaysAlive++
		} else {
			snap.GatewaysDown++
		}
	}
	snap.StateVersion = s.version
	s.mu.Unlock()
	s.cfg.Metrics.SetSnapshot(snap)
}

func (s *Server) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, alive := range s.alive {
		if alive && now.Sub(s.lastSeen[id]) > s.cfg.AliveAfter {
			s.alive[id] = false
			s.log.Warn("gateway stopped reporting", "gateway", id)
			s.bumpLocked()
		}
	}
}

// bumpLocked records a change and wakes every long poll.
func (s *Server) bumpLocked() {
	s.version++
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *Server) seenLocked(id string) {
	s.lastSeen[id] = s.now()
	if !s.alive[id] {
		s.alive[id] = true
		s.bumpLocked()
	}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("PUT /v1/gateways/{id}", s.gatewayAuth(s.registerGateway))
	mux.HandleFunc("POST /v1/gateways/{id}/links", s.gatewayAuth(s.reportLinks))
	mux.HandleFunc("GET /v1/gateway-state", s.gatewayAuth(s.gatewayState))
	mux.HandleFunc("POST /v1/sessions", s.createSession)
	mux.HandleFunc("GET /v1/sessions/{id}/state", s.sessionAuth(s.clientState))
	mux.HandleFunc("POST /v1/sessions/{id}/migrate", s.sessionAuth(s.migrate))
	// The two state routes are long polls: counted, not timed.
	return s.cfg.Metrics.Middleware(mux, "GET /v1/gateway-state", "GET /v1/sessions/{id}/state")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, format string, args ...any) {
	writeJSON(w, code, api.Error{Error: fmt.Sprintf(format, args...)})
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if v, ok := strings.CutPrefix(h, "Bearer "); ok {
		return v
	}
	return ""
}

func tokenOK(want, got string) bool {
	if want == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(got)) == 1
}

func (s *Server) gatewayAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tokenOK(s.cfg.GatewayToken, bearer(r)) {
			writeErr(w, http.StatusUnauthorized, "bad gateway token")
			return
		}
		h(w, r)
	}
}

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func (s *Server) sessionAuth(h func(http.ResponseWriter, *http.Request, clientRecord)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec, found, err := s.clientByID(r.Context(), r.PathValue("id"))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		if !found || subtle.ConstantTimeCompare([]byte(rec.SecretHash), []byte(hashSecret(bearer(r)))) != 1 {
			// The same answer for an unknown session and a wrong
			// secret, so session IDs cannot be probed for.
			writeErr(w, http.StatusUnauthorized, "unknown session or bad session secret")
			return
		}
		h(w, r, rec)
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad request body: %v", err)
		return false
	}
	return true
}

func parsePublicKey(s string) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return fmt.Errorf("public key %q is not 32 bytes of base64", s)
	}
	return nil
}

// --- store access ---

func (s *Server) gateways(ctx context.Context) ([]api.Gateway, error) {
	raw, err := s.cfg.Store.List(ctx, gatewayKeyPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]api.Gateway, 0, len(raw))
	for _, data := range raw {
		var g api.Gateway
		if err := json.Unmarshal(data, &g); err != nil {
			return nil, fmt.Errorf("controller: decode gateway: %w", err)
		}
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b api.Gateway) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

func (s *Server) clients(ctx context.Context) ([]clientRecord, error) {
	raw, err := s.cfg.Store.List(ctx, clientKeyPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]clientRecord, 0, len(raw))
	for _, data := range raw {
		var c clientRecord
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("controller: decode client: %w", err)
		}
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b clientRecord) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

func (s *Server) clientByID(ctx context.Context, id string) (clientRecord, bool, error) {
	data, found, err := s.cfg.Store.Get(ctx, clientKeyPrefix+id)
	if err != nil || !found {
		return clientRecord{}, false, err
	}
	var c clientRecord
	if err := json.Unmarshal(data, &c); err != nil {
		return clientRecord{}, false, fmt.Errorf("controller: decode client: %w", err)
	}
	return c, true, nil
}

func (s *Server) put(ctx context.Context, key string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.cfg.Store.Put(ctx, key, data)
}

func (s *Server) session(ctx context.Context, c clientRecord) (api.Session, error) {
	own, found, err := s.ownership.Get(ctx, c.ID)
	if err != nil {
		return api.Session{}, err
	}
	if !found {
		return api.Session{}, fmt.Errorf("controller: session %s has no ownership record", c.ID)
	}
	return api.Session{
		ID: c.ID, PublicKey: c.PublicKey, VirtualIP: c.VirtualIP,
		Access: own.Access, Egress: own.Egress, Epoch: own.Epoch,
	}, nil
}

// allocate returns the lowest address in p, from its third, that used
// does not contain.
func allocate(p netip.Prefix, used map[netip.Addr]bool) (netip.Addr, error) {
	a := p.Addr().Next().Next()
	for ; p.Contains(a); a = a.Next() {
		if !used[a] && p.Contains(a.Next()) { // never the last (broadcast) address
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("controller: %s is full", p)
}

// --- gateways ---

func (s *Server) registerGateway(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !gatewayIDRE.MatchString(id) {
		writeErr(w, http.StatusBadRequest, "gateway id %q must match %s", id, gatewayIDRE)
		return
	}
	var req api.RegisterGatewayRequest
	if !decode(w, r, &req) {
		return
	}
	if _, err := netip.ParseAddrPort(req.Endpoint); err != nil {
		writeErr(w, http.StatusBadRequest, "endpoint %q must be ip:port", req.Endpoint)
		return
	}
	if err := parsePublicKey(req.PublicKey); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	if !req.Roles.Has(control.RoleAccess) && !req.Roles.Has(control.RoleEgress) {
		writeErr(w, http.StatusBadRequest, "a gateway needs the access or the egress role")
		return
	}

	ctx := r.Context()
	s.mu.Lock()
	defer s.mu.Unlock()
	gws, err := s.gateways(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	g, existed := api.FindGateway(gws, id)
	if !existed {
		used := make(map[netip.Addr]bool)
		for _, o := range gws {
			used[o.NodeIP] = true
		}
		if g.NodeIP, err = allocate(s.cfg.Network.NodeSubnet, used); err != nil {
			writeErr(w, http.StatusServiceUnavailable, "%v", err)
			return
		}
	}
	next := api.Gateway{
		ID: id, Roles: req.Roles, Endpoint: req.Endpoint, PublicKey: req.PublicKey,
		NodeIP: g.NodeIP, BackbonePorts: req.BackbonePorts,
	}
	if !existed || !gatewayEqual(g, next) {
		if err := s.put(ctx, gatewayKeyPrefix+id, next); err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		if !existed {
			s.log.Info("gateway joined", "gateway", id, "roles", req.Roles.String(), "endpoint", req.Endpoint, "node_ip", g.NodeIP.String())
		}
		s.bumpLocked()
	}
	s.seenLocked(id)
	writeJSON(w, http.StatusOK, api.RegisterGatewayResponse{NodeIP: g.NodeIP, Network: s.cfg.Network})
}

func gatewayEqual(a, b api.Gateway) bool {
	a.Alive, b.Alive = false, false
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}

func (s *Server) reportLinks(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var rep api.LinkReport
	if !decode(w, r, &rep) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, found, err := s.cfg.Store.Get(r.Context(), gatewayKeyPrefix+id); err != nil || !found {
		writeErr(w, http.StatusNotFound, "gateway %s is not registered", id)
		return
	}
	now := s.now()
	m := make(map[string]linkEntry, len(rep.Links))
	for _, l := range rep.Links {
		l.From = id
		m[l.To] = linkEntry{link: l, received: now}
	}
	s.links[id] = m
	s.seenLocked(id)
	w.WriteHeader(http.StatusNoContent)
}

// waitVersion blocks until the version is above after, wait passes, or
// the request ends.
func (s *Server) waitVersion(r *http.Request) {
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	waitMS, _ := strconv.ParseInt(r.URL.Query().Get("wait"), 10, 64)
	wait := min(time.Duration(waitMS)*time.Millisecond, maxWait)
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		s.mu.Lock()
		v, ch := s.version, s.changed
		s.mu.Unlock()
		if v > after {
			return
		}
		select {
		case <-ch:
		case <-timer.C:
			return
		case <-r.Context().Done():
			return
		}
	}
}

// snapshot reads the version first: a write that lands while the store is
// being read bumps it again, so the reader polls once more rather than
// missing the write.
func (s *Server) snapshot(ctx context.Context) (uint64, []api.Gateway, error) {
	s.mu.Lock()
	v := s.version
	s.mu.Unlock()
	gws, err := s.gateways(ctx)
	if err != nil {
		return 0, nil, err
	}
	s.mu.Lock()
	for i := range gws {
		gws[i].Alive = s.alive[gws[i].ID]
	}
	s.mu.Unlock()
	return v, gws, nil
}

func (s *Server) gatewayState(w http.ResponseWriter, r *http.Request) {
	s.waitVersion(r)
	ctx := r.Context()
	v, gws, err := s.snapshot(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	cs, err := s.clients(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	st := api.GatewayState{Version: v, Network: s.cfg.Network, Gateways: gws, Sessions: make([]api.Session, 0, len(cs))}
	for _, c := range cs {
		sess, err := s.session(ctx, c)
		if err != nil {
			s.log.Warn("session left out of the gateway state", telemetry.Err(err))
			continue
		}
		st.Sessions = append(st.Sessions, sess)
	}
	writeJSON(w, http.StatusOK, st)
}

// --- sessions ---

func randomSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomSessionID() (string, error) {
	b := make([]byte, 8)
	for {
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		// The data plane carries the ID as a uint64; zero means "none".
		if v := binary.BigEndian.Uint64(b); v != 0 {
			return strconv.FormatUint(v, 10), nil
		}
	}
}

// pickPath chooses a new session's first path: egress as asked (or the
// first live egress), and that same gateway as access when it can be one.
func pickPath(gws []api.Gateway, alive map[string]bool, egress string) (access, eg string, err error) {
	usable := func(g api.Gateway, role control.GatewayRole) bool { return g.Roles.Has(role) && alive[g.ID] }
	if egress != "" {
		g, ok := api.FindGateway(gws, egress)
		if !ok || !g.Roles.Has(control.RoleEgress) {
			return "", "", fmt.Errorf("no egress gateway %q", egress)
		}
		eg = g.ID
	} else {
		for _, g := range gws {
			if usable(g, control.RoleEgress) {
				eg = g.ID
				break
			}
		}
	}
	if eg == "" {
		return "", "", errors.New("no live egress gateway")
	}
	if g, _ := api.FindGateway(gws, eg); g.Roles.Has(control.RoleAccess) {
		return eg, eg, nil
	}
	for _, g := range gws {
		if usable(g, control.RoleAccess) {
			return g.ID, eg, nil
		}
	}
	return "", "", errors.New("no live access gateway")
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request) {
	if !tokenOK(s.cfg.ClientToken, bearer(r)) {
		writeErr(w, http.StatusUnauthorized, "bad client token")
		return
	}
	var req api.CreateSessionRequest
	if !decode(w, r, &req) {
		return
	}
	if err := parsePublicKey(req.PublicKey); err != nil {
		writeErr(w, http.StatusBadRequest, "%v", err)
		return
	}
	ctx := r.Context()
	s.mu.Lock()
	defer s.mu.Unlock()
	cs, err := s.clients(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	// A key already holding a session gets it back only with its secret,
	// so knowing someone's public key is not enough to take it over.
	if i := slices.IndexFunc(cs, func(c clientRecord) bool { return c.PublicKey == req.PublicKey }); i >= 0 {
		secret := req.Secret
		if subtle.ConstantTimeCompare([]byte(cs[i].SecretHash), []byte(hashSecret(secret))) != 1 {
			writeErr(w, http.StatusConflict, "this public key already has a session; send its secret to reopen it")
			return
		}
		sess, err := s.session(ctx, cs[i])
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "%v", err)
			return
		}
		writeJSON(w, http.StatusOK, api.CreateSessionResponse{Session: sess, Secret: secret, Network: s.cfg.Network})
		return
	}

	gws, err := s.gateways(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	access, egress, err := pickPath(gws, s.alive, req.Egress)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "%v", err)
		return
	}
	used := make(map[netip.Addr]bool, len(cs))
	for _, c := range cs {
		used[c.VirtualIP] = true
	}
	vip, err := allocate(s.cfg.Network.ClientSubnet, used)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "%v", err)
		return
	}
	id, err := randomSessionID()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	secret, err := randomSecret()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	own := control.OwnershipRecord{Session: id, Access: access, Egress: egress, Epoch: 1}
	if _, err := s.ownership.SetIfNewer(ctx, own); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	rec := clientRecord{ID: id, PublicKey: req.PublicKey, VirtualIP: vip, SecretHash: hashSecret(secret)}
	if err := s.put(ctx, clientKeyPrefix+id, rec); err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	s.bumpLocked()
	s.log.InfoContext(telemetry.WithSession(ctx, id), "session opened", "virtual_ip", vip.String(), "access", access, "egress", egress)
	sess := api.Session{ID: id, PublicKey: req.PublicKey, VirtualIP: vip, Access: access, Egress: egress, Epoch: 1}
	writeJSON(w, http.StatusOK, api.CreateSessionResponse{Session: sess, Secret: secret, Network: s.cfg.Network})
}

func (s *Server) clientState(w http.ResponseWriter, r *http.Request, c clientRecord) {
	s.waitVersion(r)
	ctx := r.Context()
	v, gws, err := s.snapshot(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	sess, err := s.session(ctx, c)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	pol, err := s.policy.Get(ctx)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	st := api.ClientState{Version: v, Network: s.cfg.Network, Session: sess, Gateways: gws, Policy: pol}
	// Gateways no longer registered never appear; their links are dropped too.
	s.mu.Lock()
	now := s.now()
	for _, g := range gws {
		for _, e := range s.links[g.ID] {
			l := e.link
			l.Staleness = now.Sub(e.received)
			st.Links = append(st.Links, l)
		}
	}
	s.mu.Unlock()
	slices.SortFunc(st.Links, func(a, b api.Link) int {
		return strings.Compare(a.From+"\x00"+a.To, b.From+"\x00"+b.To)
	})
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) migrate(w http.ResponseWriter, r *http.Request, c clientRecord) {
	var req api.MigrateRequest
	if !decode(w, r, &req) {
		s.cfg.Metrics.Migration(telemetry.MigrationRejected)
		return
	}
	ctx := r.Context()
	s.mu.Lock()
	defer s.mu.Unlock()
	gws, err := s.gateways(ctx)
	if err != nil {
		s.cfg.Metrics.Migration(telemetry.MigrationError)
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if g, ok := api.FindGateway(gws, req.Access); !ok || !g.Roles.Has(control.RoleAccess) {
		s.cfg.Metrics.Migration(telemetry.MigrationRejected)
		writeErr(w, http.StatusBadRequest, "no access gateway %q", req.Access)
		return
	}
	if g, ok := api.FindGateway(gws, req.Egress); !ok || !g.Roles.Has(control.RoleEgress) {
		s.cfg.Metrics.Migration(telemetry.MigrationRejected)
		writeErr(w, http.StatusBadRequest, "no egress gateway %q", req.Egress)
		return
	}
	cur, err := s.session(ctx, c)
	if err != nil {
		s.cfg.Metrics.Migration(telemetry.MigrationError)
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	conflict := func(sess api.Session) {
		s.cfg.Metrics.Migration(telemetry.MigrationConflict)
		writeJSON(w, http.StatusConflict, api.Error{Error: "the session is at another epoch", Session: &sess})
	}
	if req.Epoch != cur.Epoch {
		conflict(cur)
		return
	}
	next := control.OwnershipRecord{Session: c.ID, Access: req.Access, Egress: req.Egress, Epoch: cur.Epoch + 1}
	applied, err := s.ownership.SetIfNewer(ctx, next)
	if err != nil {
		s.cfg.Metrics.Migration(telemetry.MigrationError)
		writeErr(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if !applied {
		// Another controller sharing the store got there first.
		if now, err := s.session(ctx, c); err == nil {
			conflict(now)
			return
		}
		s.cfg.Metrics.Migration(telemetry.MigrationConflict)
		writeErr(w, http.StatusConflict, "the session moved concurrently")
		return
	}
	s.bumpLocked()
	s.cfg.Metrics.Migration(telemetry.MigrationCommitted)
	s.log.InfoContext(telemetry.WithMigration(ctx, c.ID, next.Epoch), "session migrated",
		"access", next.Access, "egress", next.Egress, "from_access", cur.Access, "from_egress", cur.Egress)
	cur.Access, cur.Egress, cur.Epoch = next.Access, next.Egress, next.Epoch
	writeJSON(w, http.StatusOK, cur)
}
