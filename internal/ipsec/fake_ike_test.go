package ipsec

import (
	"context"
	"fmt"
	"slices"
	"sync"
)

// fakeIKE is an in-memory IKE daemon: loading a connection and initiating
// it produces an established IKE_SA with an installed CHILD_SA, and every
// change is announced as an event, the way charon behaves. Errors and
// delays are injected per operation.
type fakeIKE struct {
	mu      sync.Mutex
	conns   map[string]Connection
	secrets map[string]SharedSecret
	sas     []IKESA
	nextID  uint64
	log     []string
	lists   int // ListSAs calls

	errs       map[string]error // by operation: "load-conn", "initiate", ...
	onInitiate func(ctx context.Context, ike, child string) error
	// honorCtx makes every call fail once its context is done, as the
	// real daemon client does; it proves cleanup runs on a live context.
	honorCtx bool

	subs map[chan Event]struct{}
}

var _ IKE = (*fakeIKE)(nil)

func newFakeIKE() *fakeIKE {
	return &fakeIKE{
		conns:   map[string]Connection{},
		secrets: map[string]SharedSecret{},
		errs:    map[string]error{},
		subs:    map[chan Event]struct{}{},
		nextID:  100,
	}
}

func (f *fakeIKE) record(op string) error {
	f.log = append(f.log, op)
	if err := f.errs[op]; err != nil {
		return err
	}
	return nil
}

// ctxErr is the error a ctx-honouring daemon client would return.
func (f *fakeIKE) ctxErr(ctx context.Context) error {
	if f.honorCtx {
		return ctx.Err()
	}
	return nil
}

func (f *fakeIKE) setErr(op string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[op] = err
}

func (f *fakeIKE) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

func (f *fakeIKE) listCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lists
}

func (f *fakeIKE) LoadConn(ctx context.Context, c Connection) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	if err := f.record("load-conn " + c.Name); err != nil {
		return err
	}
	if err := f.errs["load-conn"]; err != nil {
		return err
	}
	if err := c.Validate(); err != nil {
		return err
	}
	f.conns[c.Name] = c
	return nil
}

func (f *fakeIKE) UnloadConn(ctx context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	if err := f.record("unload-conn " + name); err != nil {
		return err
	}
	if err := f.errs["unload-conn"]; err != nil {
		return err
	}
	if _, ok := f.conns[name]; !ok {
		return fmt.Errorf("unload-conn %s: %w", name, ErrNotFound)
	}
	delete(f.conns, name)
	return nil
}

func (f *fakeIKE) LoadShared(ctx context.Context, s SharedSecret) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	if err := f.record("load-shared " + s.ID); err != nil {
		return err
	}
	if err := f.errs["load-shared"]; err != nil {
		return err
	}
	if err := s.Validate(); err != nil {
		return err
	}
	f.secrets[s.ID] = s
	return nil
}

func (f *fakeIKE) UnloadShared(ctx context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	if err := f.record("unload-shared " + id); err != nil {
		return err
	}
	if err := f.errs["unload-shared"]; err != nil {
		return err
	}
	if _, ok := f.secrets[id]; !ok {
		return fmt.Errorf("unload-shared %s: %w", id, ErrNotFound)
	}
	delete(f.secrets, id)
	return nil
}

func (f *fakeIKE) Initiate(ctx context.Context, ike, child string) error {
	f.mu.Lock()
	err := f.record("initiate " + child)
	if err == nil {
		err = f.errs["initiate"]
	}
	if err == nil {
		err = f.ctxErr(ctx)
	}
	hook := f.onInitiate
	f.mu.Unlock()
	if err != nil {
		return err
	}
	if hook != nil {
		if err := hook(ctx, ike, child); err != nil {
			return err
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.conns[ike]
	if !ok {
		return fmt.Errorf("initiate: no connection %s: %w", ike, ErrNotFound)
	}
	if child != ChildName(c.Name, c.Epoch) {
		return fmt.Errorf("initiate: connection %s has no child %s", ike, child)
	}
	i := slices.IndexFunc(f.sas, func(s IKESA) bool { return s.Name == ike && s.State == IKEStateEstablished })
	if i < 0 {
		f.nextID++
		f.sas = append(f.sas, IKESA{
			Name: ike, UniqueID: f.nextID, State: IKEStateEstablished,
			LocalHost: c.LocalAddr.String(), RemoteHost: c.RemoteAddr.String(),
			LocalID: c.LocalID, RemoteID: c.RemoteID, Initiator: true,
			EncrAlg: "AES_GCM_16", PRFAlg: "PRF_HMAC_SHA2_256", DHGroup: "CURVE_25519",
		})
		i = len(f.sas) - 1
		f.emitLocked(Event{Kind: EventIKEUpDown, Up: true, IKE: f.sas[i]})
	}
	f.nextID++
	f.sas[i].Children = append(f.sas[i].Children, ChildSA{
		Name: child, UniqueID: f.nextID, State: ChildStateInstalled,
		Mode: "TUNNEL", Protocol: "ESP",
		SPIIn: fmt.Sprintf("%08x", 0xc0000000+f.nextID), SPIOut: fmt.Sprintf("%08x", 0xd0000000+f.nextID),
		IfIDIn: c.IfID, IfIDOut: c.IfID, EncrAlg: "AES_GCM_16",
	})
	f.emitLocked(Event{Kind: EventChildUpDown, Up: true, IKE: f.sas[i]})
	return nil
}

func (f *fakeIKE) TerminateIKE(ctx context.Context, ike string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	if err := f.record("terminate-ike " + ike); err != nil {
		return err
	}
	if err := f.errs["terminate"]; err != nil {
		return err
	}
	return f.removeIKELocked(func(s IKESA) bool { return s.Name == ike })
}

func (f *fakeIKE) TerminateIKEByID(ctx context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	if err := f.record(fmt.Sprintf("terminate-ike-id %d", id)); err != nil {
		return err
	}
	if err := f.errs["terminate"]; err != nil {
		return err
	}
	return f.removeIKELocked(func(s IKESA) bool { return s.UniqueID == id })
}

func (f *fakeIKE) removeIKELocked(match func(IKESA) bool) error {
	var kept, gone []IKESA
	for _, s := range f.sas {
		if match(s) {
			gone = append(gone, s)
		} else {
			kept = append(kept, s)
		}
	}
	if len(gone) == 0 {
		return fmt.Errorf("terminate: %w", ErrNotFound)
	}
	f.sas = kept
	for _, s := range gone {
		s.State = "DELETING"
		f.emitLocked(Event{Kind: EventIKEUpDown, Up: false, IKE: s})
	}
	return nil
}

func (f *fakeIKE) TerminateChild(ctx context.Context, id uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.ctxErr(ctx); err != nil {
		return err
	}
	if err := f.record(fmt.Sprintf("terminate-child %d", id)); err != nil {
		return err
	}
	if err := f.errs["terminate-child"]; err != nil {
		return err
	}
	for i := range f.sas {
		for j, c := range f.sas[i].Children {
			if c.UniqueID == id {
				f.sas[i].Children = slices.Delete(f.sas[i].Children, j, j+1)
				ev := f.sas[i]
				ev.Children = []ChildSA{c}
				f.emitLocked(Event{Kind: EventChildUpDown, Up: false, IKE: ev})
				return nil
			}
		}
	}
	return fmt.Errorf("terminate child %d: %w", id, ErrNotFound)
}

func (f *fakeIKE) ListSAs(ctx context.Context, ike string) ([]IKESA, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists++
	if err := f.ctxErr(ctx); err != nil {
		return nil, err
	}
	if err := f.errs["list"]; err != nil {
		return nil, err
	}
	var out []IKESA
	for _, s := range f.sas {
		if ike == "" || s.Name == ike {
			s.Children = append([]ChildSA(nil), s.Children...)
			out = append(out, s)
		}
	}
	return out, nil
}

func (f *fakeIKE) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	f.mu.Lock()
	f.subs[ch] = struct{}{}
	f.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			f.mu.Lock()
			defer f.mu.Unlock()
			if _, ok := f.subs[ch]; ok {
				delete(f.subs, ch)
				close(ch)
			}
		})
	}
}

func (f *fakeIKE) subscribers() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.subs)
}

func (f *fakeIKE) emit(ev Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.emitLocked(ev)
}

func (f *fakeIKE) emitLocked(ev Event) {
	for ch := range f.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}

// closeSubscriptions ends every subscription, as a closing IKE does.
func (f *fakeIKE) closeSubscriptions() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for ch := range f.subs {
		close(ch)
		delete(f.subs, ch)
	}
}

// addSA inserts an SA without announcing it, for responder-side SAs and
// for changes a test wants the poll fallback or a resync to discover.
func (f *fakeIKE) addSA(sa IKESA) IKESA {
	f.mu.Lock()
	defer f.mu.Unlock()
	if sa.UniqueID == 0 {
		f.nextID++
		sa.UniqueID = f.nextID
	}
	f.sas = append(f.sas, sa)
	return sa
}

// dropIKE removes conn's SAs the way DPD with dpd_action=clear does, and
// announces it only if announce is set.
func (f *fakeIKE) dropIKE(conn string, announce bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var kept []IKESA
	for _, s := range f.sas {
		if s.Name != conn {
			kept = append(kept, s)
			continue
		}
		if announce {
			s.State = "DELETING"
			f.emitLocked(Event{Kind: EventIKEUpDown, Up: false, IKE: s})
		}
	}
	f.sas = kept
}
