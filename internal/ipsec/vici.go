package ipsec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/strongswan/govici/vici"
)

// DefaultViciSocket is where charon listens for vici by default.
const DefaultViciSocket = "/var/run/charon.vici"

const (
	// terminateGrace is how long a forced terminate waits for the peer to
	// acknowledge the DELETE before charon destroys the SA anyway.
	terminateGrace = 2 * time.Second
	// eventBuffer is the per-subscriber channel depth.
	eventBuffer = 64
)

// ViciIKE implements IKE over charon's vici socket using govici.
//
// govici serializes commands per session and holds that session for the
// whole of a command, so a slow initiate on a shared session would block
// every other caller. Quick commands (load, unload, list) therefore share
// one session, while initiate and terminate, which can take as long as an
// IKE exchange with retransmits, each get a short-lived session of their
// own. Events use a third, dedicated session.
type ViciIKE struct {
	socket string
	dialer func(ctx context.Context, network, addr string) (net.Conn, error)
	retry  time.Duration

	mu  sync.Mutex // guards cmd, held for a whole command or stream
	cmd *vici.Session

	evMu   sync.Mutex
	subs   map[*subscriber]struct{}
	evStop chan struct{} // closed by Close; nil until events start
	evDone chan struct{}
	closed bool
}

var _ IKE = (*ViciIKE)(nil)

// ViciOption configures a ViciIKE.
type ViciOption func(*ViciIKE)

// WithViciSocket sets the vici unix socket path.
func WithViciSocket(path string) ViciOption {
	return func(v *ViciIKE) { v.socket = path }
}

// WithViciDialer replaces how the socket is dialed, for example to reach
// a charon in another mount or network namespace.
func WithViciDialer(dial func(ctx context.Context, network, addr string) (net.Conn, error)) ViciOption {
	return func(v *ViciIKE) { v.dialer = dial }
}

// WithViciReconnect sets the delay between attempts to re-establish the
// event session after charon goes away.
func WithViciReconnect(d time.Duration) ViciOption {
	return func(v *ViciIKE) { v.retry = d }
}

// NewViciIKE connects to charon. It fails if charon is not reachable, so a
// misconfigured socket path is reported at start-up rather than at the
// first command.
func NewViciIKE(ctx context.Context, opts ...ViciOption) (*ViciIKE, error) {
	v := &ViciIKE{
		socket: DefaultViciSocket,
		dialer: (&net.Dialer{}).DialContext,
		retry:  time.Second,
		subs:   map[*subscriber]struct{}{},
	}
	for _, o := range opts {
		o(v)
	}
	s, err := v.dial(ctx)
	if err != nil {
		return nil, err
	}
	v.cmd = s
	return v, nil
}

// Close closes every session and ends every subscription.
func (v *ViciIKE) Close() error {
	v.evMu.Lock()
	if v.closed {
		v.evMu.Unlock()
		return nil
	}
	v.closed = true
	stop, done := v.evStop, v.evDone
	v.evMu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.cmd != nil {
		err := v.cmd.Close()
		v.cmd = nil
		return err
	}
	return nil
}

func (v *ViciIKE) dial(ctx context.Context) (*vici.Session, error) {
	s, err := vici.NewSession(
		vici.WithAddr("unix", v.socket),
		vici.WithDialContext(func(_ context.Context, network, addr string) (net.Conn, error) {
			// govici dials with context.Background; honour the caller's.
			return v.dialer(ctx, network, addr)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("ipsec: connect to charon at %s: %w", v.socket, err)
	}
	return s, nil
}

// session returns the shared command session, reconnecting if a previous
// transport failure dropped it. v.mu must be held.
func (v *ViciIKE) session(ctx context.Context) (*vici.Session, error) {
	if v.cmd == nil {
		s, err := v.dial(ctx)
		if err != nil {
			return nil, err
		}
		v.cmd = s
	}
	return v.cmd, nil
}

// drop discards the shared session after a transport failure, so the next
// command reconnects. v.mu must be held.
func (v *ViciIKE) drop() {
	if v.cmd != nil {
		_ = v.cmd.Close()
		v.cmd = nil
	}
}

// call runs a quick command on the shared session.
func (v *ViciIKE) call(ctx context.Context, cmd string, in *vici.Message) (*vici.Message, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	s, err := v.session(ctx)
	if err != nil {
		return nil, err
	}
	resp, err := s.Call(ctx, cmd, in)
	if err != nil {
		if resp == nil {
			v.drop()
			return nil, fmt.Errorf("ipsec: vici %s: %w", cmd, err)
		}
		return resp, commandError(cmd, resp)
	}
	return resp, nil
}

// stream runs a streaming command on the shared session and collects the
// streamed event messages. govici releases its own lock before the stream
// is iterated, so v.mu is held across the whole iteration instead.
func (v *ViciIKE) stream(ctx context.Context, cmd, event string, in *vici.Message) ([]*vici.Message, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	s, err := v.session(ctx)
	if err != nil {
		return nil, err
	}
	var out []*vici.Message
	for m, err := range s.CallStreaming(ctx, cmd, event, in) {
		if err != nil {
			if m == nil {
				v.drop()
				return nil, fmt.Errorf("ipsec: vici %s: %w", cmd, err)
			}
			return nil, commandError(cmd, m)
		}
		out = append(out, m)
	}
	return out, nil
}

// oneShot runs fn on a session of its own, for commands that can block
// for as long as an IKE exchange.
func (v *ViciIKE) oneShot(ctx context.Context, fn func(*vici.Session) error) error {
	s, err := v.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	return fn(s)
}

func commandError(cmd string, resp *vici.Message) error {
	msg := str(resp, "errmsg")
	if msg == "" {
		msg = "command failed"
	}
	if strings.Contains(msg, "not found") {
		return fmt.Errorf("ipsec: vici %s: %w: %s", cmd, ErrNotFound, msg)
	}
	return fmt.Errorf("ipsec: vici %s: %s", cmd, msg)
}

func (v *ViciIKE) LoadConn(ctx context.Context, c Connection) error {
	if err := c.Validate(); err != nil {
		return err
	}
	msg, err := connMessage(c)
	if err != nil {
		return err
	}
	_, err = v.call(ctx, "load-conn", msg)
	return err
}

func (v *ViciIKE) UnloadConn(ctx context.Context, name string) error {
	_, err := v.call(ctx, "unload-conn", newMsg("name", name))
	return err
}

func (v *ViciIKE) LoadShared(ctx context.Context, s SharedSecret) error {
	if err := s.Validate(); err != nil {
		return err
	}
	msg := newMsg(
		"id", s.ID,
		"type", "IKE",
		// load-shared takes the raw secret: unlike a swanctl.conf
		// "secret =" line there is no 0x/0s prefix interpretation, so
		// the PSK goes over verbatim and never touches the disk.
		"data", s.PSK,
		"owners", append([]string(nil), s.Owners...),
	)
	_, err := v.call(ctx, "load-shared", msg)
	return err
}

func (v *ViciIKE) UnloadShared(ctx context.Context, id string) error {
	_, err := v.call(ctx, "unload-shared", newMsg("id", id))
	return err
}

func (v *ViciIKE) Initiate(ctx context.Context, ike, child string) error {
	msg := newMsg(
		"child", child,
		"ike", ike,
		"timeout", timeoutMS(ctx, 0),
		// control-log events at level 1 carry the notify errors (for
		// example AUTHENTICATION_FAILED) that say why a failure happened.
		"loglevel", "1",
	)
	return v.oneShot(ctx, func(s *vici.Session) error {
		var logs []string
		for m, err := range s.CallStreaming(ctx, "initiate", "control-log", msg) {
			if m != nil {
				if line := str(m, "msg"); line != "" {
					logs = append(logs, line)
				}
			}
			if err == nil {
				continue
			}
			if m == nil {
				return fmt.Errorf("ipsec: vici initiate %s/%s: %w", ike, child, err)
			}
			reason := str(m, "errmsg")
			if authFailed(logs) {
				return fmt.Errorf("ipsec: initiate %s/%s: %w: %s", ike, child, ErrAuthFailed, reason)
			}
			return fmt.Errorf("ipsec: initiate %s/%s: %s%s", ike, child, reason, lastLog(logs))
		}
		return nil
	})
}

func authFailed(logs []string) bool {
	for _, l := range logs {
		if strings.Contains(l, "AUTHENTICATION_FAILED") ||
			(strings.Contains(l, "authentication of") && strings.Contains(l, "failed")) ||
			strings.Contains(l, "MAC mismatched") {
			return true
		}
	}
	return false
}

func lastLog(logs []string) string {
	if len(logs) == 0 {
		return ""
	}
	return " (last log: " + logs[len(logs)-1] + ")"
}

func (v *ViciIKE) TerminateIKE(ctx context.Context, ike string) error {
	return v.terminate(ctx, "ike", ike)
}

func (v *ViciIKE) TerminateIKEByID(ctx context.Context, uniqueID uint64) error {
	return v.terminate(ctx, "ike-id", strconv.FormatUint(uniqueID, 10))
}

func (v *ViciIKE) TerminateChild(ctx context.Context, uniqueID uint64) error {
	return v.terminate(ctx, "child-id", strconv.FormatUint(uniqueID, 10))
}

func (v *ViciIKE) terminate(ctx context.Context, selector, value string) error {
	msg := newMsg(
		selector, value,
		// force: tear the SA down even if the peer never answers the
		// DELETE, after waiting at most the timeout for it to.
		"force", "yes",
		"timeout", timeoutMS(ctx, terminateGrace),
	)
	return v.oneShot(ctx, func(s *vici.Session) error {
		resp, err := s.Call(ctx, "terminate", msg)
		if err == nil {
			return nil
		}
		if resp == nil {
			return fmt.Errorf("ipsec: vici terminate %s=%s: %w", selector, value, err)
		}
		if strings.Contains(str(resp, "errmsg"), "no matching SAs") {
			return fmt.Errorf("ipsec: vici terminate %s=%s: %w", selector, value, ErrNotFound)
		}
		return commandError("terminate", resp)
	})
}

// timeoutMS renders how long a blocking command may take, in
// milliseconds, from ctx's deadline. Without a deadline it is fallback;
// a fallback of 0 tells charon to wait until the operation completes.
func timeoutMS(ctx context.Context, fallback time.Duration) string {
	d := fallback
	if dl, ok := ctx.Deadline(); ok {
		left := time.Until(dl)
		if left < time.Millisecond {
			left = time.Millisecond
		}
		if d == 0 || left < d {
			d = left
		}
	}
	return strconv.FormatInt(d.Milliseconds(), 10)
}

func (v *ViciIKE) ListSAs(ctx context.Context, ike string) ([]IKESA, error) {
	// noblock: answer from the current state even while another thread
	// holds an IKE_SA, rather than waiting for it.
	msg := newMsg("noblock", "yes")
	if ike != "" {
		mustSet(msg, "ike", ike)
	}
	msgs, err := v.stream(ctx, "list-sas", "list-sa", msg)
	if err != nil {
		return nil, err
	}
	var sas []IKESA
	for _, m := range msgs {
		sas = append(sas, parseIKESAs(m)...)
	}
	return sas, nil
}

// connMessage builds the load-conn message for c. Keys and nesting follow
// swanctl.conf (see Render), with the multi-value options sent as vici
// lists, which is the form charon's load-conn parser expects for them.
func connMessage(c Connection) (*vici.Message, error) {
	if c.Auth != AuthPSK {
		return nil, fmt.Errorf(
			"ipsec: connection %s: only PSK authentication can be loaded over vici "+
				"(load-conn needs public key data, not the file names Connection holds)", c.Name)
	}
	ike := c.IKEProposals
	if len(ike) == 0 {
		ike = DefaultIKEProposals
	}
	esp := c.ESPProposals
	if len(esp) == 0 {
		esp = DefaultESPProposals
	}
	start := c.Start
	if start == "" {
		start = StartNone
	}
	remote := AnyID
	if c.RemoteAddr.IsValid() {
		remote = c.RemoteAddr.String()
	}

	child := newMsg(
		"local_ts", prefixList(c.LocalTS),
		"remote_ts", prefixList(c.RemoteTS),
		"esp_proposals", append([]string(nil), esp...),
		"mode", "tunnel",
		"if_id_in", strconv.FormatUint(uint64(c.IfID), 10),
		"if_id_out", strconv.FormatUint(uint64(c.IfID), 10),
		"start_action", string(start),
	)
	if c.DPDDelay > 0 {
		// A dead peer must disappear from the SA list so the caller sees
		// it, instead of charon silently retrying it behind its back.
		mustSet(child, "dpd_action", "clear")
	}

	conn := newMsg("version", "2")
	if c.LocalAddr.IsValid() {
		mustSet(conn, "local_addrs", []string{c.LocalAddr.String()})
	}
	mustSet(conn, "remote_addrs", []string{remote})
	mustSet(conn, "proposals", append([]string(nil), ike...))
	if c.DPDDelay > 0 {
		mustSet(conn, "dpd_delay", strconv.FormatInt(ceilSeconds(c.DPDDelay), 10)+"s")
	}
	mustSet(conn, "local", newMsg("auth", string(c.Auth), "id", c.LocalID))
	mustSet(conn, "remote", newMsg("auth", string(c.Auth), "id", c.RemoteID))
	mustSet(conn, "children", newMsg(ChildName(c.Name, c.Epoch), child))
	return newMsg(c.Name, conn), nil
}

// newMsg builds a message from key, value pairs of the types connMessage
// uses (string, []string, *vici.Message), all of which Set accepts.
func newMsg(kv ...any) *vici.Message {
	m := vici.NewMessage()
	for i := 0; i+1 < len(kv); i += 2 {
		mustSet(m, kv[i].(string), kv[i+1])
	}
	return m
}

func mustSet(m *vici.Message, k string, v any) {
	if err := m.Set(k, v); err != nil {
		panic(fmt.Sprintf("ipsec: vici message key %q: %v", k, err)) // only on a programming error
	}
}

func prefixList(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Masked().String()
	}
	return out
}

// parseIKESAs reads every IKE_SA section of a list-sa or updown message.
// Each IKE_SA is a section keyed by its connection name; other top-level
// keys (such as "up" in an updown event) are skipped.
func parseIKESAs(m *vici.Message) []IKESA {
	var out []IKESA
	for _, k := range m.Keys() {
		sec, ok := m.Get(k).(*vici.Message)
		if !ok {
			continue
		}
		out = append(out, parseIKESA(k, sec))
	}
	return out
}

func parseIKESA(name string, m *vici.Message) IKESA {
	sa := IKESA{
		Name:           name,
		UniqueID:       num(m, "uniqueid", 10),
		State:          str(m, "state"),
		LocalHost:      str(m, "local-host"),
		RemoteHost:     str(m, "remote-host"),
		LocalID:        str(m, "local-id"),
		RemoteID:       str(m, "remote-id"),
		Initiator:      str(m, "initiator") == "yes",
		EncrAlg:        str(m, "encr-alg"),
		PRFAlg:         str(m, "prf-alg"),
		DHGroup:        str(m, "dh-group"),
		EstablishedFor: seconds(m, "established"),
	}
	if children, ok := m.Get("child-sas").(*vici.Message); ok {
		for _, k := range children.Keys() {
			if c, ok := children.Get(k).(*vici.Message); ok {
				sa.Children = append(sa.Children, parseChildSA(k, c))
			}
		}
	}
	return sa
}

func parseChildSA(key string, m *vici.Message) ChildSA {
	name := str(m, "name")
	if name == "" {
		// Older daemons key the section by name only; newer ones use
		// "<name>-<uniqueid>" and carry the bare name inside.
		name = key
	}
	return ChildSA{
		Name:         name,
		UniqueID:     num(m, "uniqueid", 10),
		State:        str(m, "state"),
		Mode:         str(m, "mode"),
		Protocol:     str(m, "protocol"),
		SPIIn:        str(m, "spi-in"),
		SPIOut:       str(m, "spi-out"),
		IfIDIn:       uint32(num(m, "if-id-in", 16)),
		IfIDOut:      uint32(num(m, "if-id-out", 16)),
		EncrAlg:      str(m, "encr-alg"),
		BytesIn:      num(m, "bytes-in", 10),
		PacketsIn:    num(m, "packets-in", 10),
		BytesOut:     num(m, "bytes-out", 10),
		PacketsOut:   num(m, "packets-out", 10),
		InstalledFor: seconds(m, "install-time"),
		LocalTS:      list(m, "local-ts"),
		RemoteTS:     list(m, "remote-ts"),
	}
}

// parseEvent turns an ike-updown or child-updown message into an Event.
// The message carries "up = yes" when the SA came up (and no "up" key
// when it went down) next to one section for the IKE_SA.
func parseEvent(name string, m *vici.Message) (Event, bool) {
	var kind EventKind
	switch name {
	case "ike-updown":
		kind = EventIKEUpDown
	case "child-updown":
		kind = EventChildUpDown
	default:
		return Event{}, false
	}
	sas := parseIKESAs(m)
	if len(sas) == 0 {
		return Event{}, false
	}
	return Event{Kind: kind, Up: str(m, "up") == "yes", IKE: sas[0]}, true
}

func str(m *vici.Message, k string) string {
	s, _ := m.Get(k).(string)
	return s
}

func list(m *vici.Message, k string) []string {
	l, _ := m.Get(k).([]string)
	return append([]string(nil), l...)
}

func num(m *vici.Message, k string, base int) uint64 {
	n, _ := strconv.ParseUint(str(m, k), base, 64)
	return n
}

func seconds(m *vici.Message, k string) time.Duration {
	return time.Duration(num(m, k, 10)) * time.Second
}

// Subscribe implements IKE. The event session is opened on first use and
// re-opened (announcing EventResync) whenever charon goes away.
func (v *ViciIKE) Subscribe() (<-chan Event, func()) {
	sub := &subscriber{ch: make(chan Event, eventBuffer)}
	v.evMu.Lock()
	if v.closed {
		v.evMu.Unlock()
		close(sub.ch)
		return sub.ch, func() {}
	}
	v.subs[sub] = struct{}{}
	if v.evStop == nil {
		v.evStop = make(chan struct{})
		v.evDone = make(chan struct{})
		go v.eventLoop(v.evStop, v.evDone)
	}
	v.evMu.Unlock()

	var once sync.Once
	return sub.ch, func() {
		once.Do(func() {
			v.evMu.Lock()
			defer v.evMu.Unlock()
			if _, ok := v.subs[sub]; ok {
				delete(v.subs, sub)
				close(sub.ch)
			}
		})
	}
}

type subscriber struct {
	ch     chan Event
	lagged bool // an event was dropped; owe the reader an EventResync
}

// deliver hands ev to every subscriber without ever blocking: a reader too
// slow to keep up loses events but is told so with an EventResync as soon
// as it has room again.
func (v *ViciIKE) deliver(ev Event) {
	v.evMu.Lock()
	defer v.evMu.Unlock()
	for sub := range v.subs {
		if sub.lagged {
			select {
			case sub.ch <- Event{Kind: EventResync}:
				sub.lagged = false
			default:
				continue
			}
		}
		select {
		case sub.ch <- ev:
		default:
			sub.lagged = true
		}
	}
}

func (v *ViciIKE) eventLoop(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	defer func() {
		v.evMu.Lock()
		defer v.evMu.Unlock()
		for sub := range v.subs {
			close(sub.ch)
			delete(v.subs, sub)
		}
	}()
	first := true
	for {
		err := v.listenOnce(stop, !first)
		first = false
		if err == nil {
			return // stopped
		}
		select {
		case <-stop:
			return
		case <-time.After(v.retry):
		}
	}
}

// listenOnce opens one event session and forwards its events until it
// fails (returning the error) or stop is closed (returning nil). After a
// reconnect, subscribers get an EventResync once the new session is
// listening, since anything in between was missed.
func (v *ViciIKE) listenOnce(stop <-chan struct{}, reconnected bool) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	s, err := v.dial(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()

	raw := make(chan vici.Event, 256)
	s.NotifyEvents(raw)
	if err := s.Subscribe("ike-updown", "child-updown"); err != nil {
		return fmt.Errorf("ipsec: vici subscribe: %w", err)
	}
	if reconnected {
		v.deliver(Event{Kind: EventResync})
	}
	for {
		select {
		case <-stop:
			return nil
		case e, ok := <-raw:
			if !ok {
				return errors.New("ipsec: vici event session closed")
			}
			if ev, ok := parseEvent(e.Name, e.Message); ok {
				v.deliver(ev)
			}
		}
	}
}
