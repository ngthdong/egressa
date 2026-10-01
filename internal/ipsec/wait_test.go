package ipsec

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// loaded returns a fakeIKE with clientConn loaded.
func loaded(t *testing.T) (*fakeIKE, Connection) {
	t.Helper()
	f := newFakeIKE()
	c := clientConn()
	if err := f.LoadConn(context.Background(), c); err != nil {
		t.Fatalf("LoadConn: %v", err)
	}
	return f, c
}

func TestIsWarm(t *testing.T) {
	f, c := loaded(t)
	ctx := context.Background()
	if warm, err := IsWarm(ctx, f, c.Name); err != nil || warm {
		t.Fatalf("IsWarm before Initiate = %v, %v", warm, err)
	}
	if err := f.Initiate(ctx, c.Name, ChildName(c.Name, c.Epoch)); err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	if warm, err := IsWarm(ctx, f, c.Name); err != nil || !warm {
		t.Fatalf("IsWarm after Initiate = %v, %v", warm, err)
	}
	f.setErr("list", errors.New("daemon gone"))
	if _, err := IsWarm(ctx, f, c.Name); err == nil {
		t.Fatal("IsWarm hid a query error")
	}
}

func TestWaitWarm_AlreadyWarm(t *testing.T) {
	f, c := loaded(t)
	ctx := context.Background()
	if err := f.Initiate(ctx, c.Name, ChildName(c.Name, c.Epoch)); err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	sa, err := WaitWarm(ctx, f, c.Name, time.Hour)
	if err != nil || !sa.Warm() || sa.Name != c.Name {
		t.Fatalf("WaitWarm = %+v, %v", sa, err)
	}
	if f.subscribers() != 0 {
		t.Fatal("WaitWarm left its subscription open")
	}
}

func TestWaitWarm_WokenByEvent(t *testing.T) {
	f, c := loaded(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		waitForCond(func() bool { return f.subscribers() == 1 })
		_ = f.Initiate(ctx, c.Name, ChildName(c.Name, c.Epoch))
	}()
	// An hour-long poll: only the event can end this wait in time.
	sa, err := WaitWarm(ctx, f, c.Name, time.Hour)
	if err != nil || !sa.Warm() {
		t.Fatalf("WaitWarm = %+v, %v", sa, err)
	}
}

func TestWaitWarm_IgnoresOtherConnections(t *testing.T) {
	f, c := loaded(t)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	go func() {
		waitForCond(func() bool { return f.subscribers() == 1 })
		for i := 0; i < 5; i++ {
			f.emit(Event{Kind: EventIKEUpDown, Up: true, IKE: IKESA{Name: "someone-else"}})
		}
	}()
	if _, err := WaitWarm(ctx, f, c.Name, time.Hour); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitWarm = %v, want a deadline error", err)
	}
	if n := f.listCount(); n != 1 {
		t.Fatalf("ListSAs called %d times, want only the initial query: events about other connections must not trigger re-queries", n)
	}
}

func TestWaitWarm_ResyncTriggersRequery(t *testing.T) {
	f, c := loaded(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		waitForCond(func() bool { return f.subscribers() == 1 })
		// The SA appears without an event (the event was lost)...
		f.addSA(IKESA{Name: c.Name, State: IKEStateEstablished,
			Children: []ChildSA{{Name: ChildName(c.Name, c.Epoch), State: ChildStateInstalled}}})
		// ...and the subscription says events may have been missed.
		f.emit(Event{Kind: EventResync})
	}()
	if _, err := WaitWarm(ctx, f, c.Name, time.Hour); err != nil {
		t.Fatalf("WaitWarm after a resync: %v", err)
	}
}

func TestWaitWarm_PollFallback(t *testing.T) {
	f, c := loaded(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		waitForCond(func() bool { return f.subscribers() == 1 })
		f.addSA(IKESA{Name: c.Name, State: IKEStateEstablished,
			Children: []ChildSA{{State: ChildStateInstalled}}}) // no event at all
	}()
	if _, err := WaitWarm(ctx, f, c.Name, 10*time.Millisecond); err != nil {
		t.Fatalf("WaitWarm with only the poll to notice: %v", err)
	}
}

func TestWaitWarm_ClosedEventsFallBackToPolling(t *testing.T) {
	f, c := loaded(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		waitForCond(func() bool { return f.subscribers() == 1 })
		f.closeSubscriptions()
		f.addSA(IKESA{Name: c.Name, State: IKEStateEstablished,
			Children: []ChildSA{{State: ChildStateInstalled}}})
	}()
	if _, err := WaitWarm(ctx, f, c.Name, 10*time.Millisecond); err != nil {
		t.Fatalf("WaitWarm after the event channel closed: %v", err)
	}
}

func TestWaitWarm_Errors(t *testing.T) {
	f, c := loaded(t)
	f.setErr("list", errors.New("daemon gone"))
	if _, err := WaitWarm(context.Background(), f, c.Name, time.Hour); err == nil ||
		!strings.Contains(err.Error(), "daemon gone") {
		t.Fatalf("WaitWarm with a failing first query = %v", err)
	}

	f2, c2 := loaded(t)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	go func() {
		waitForCond(func() bool { return f2.subscribers() == 1 })
		f2.setErr("list", errors.New("transient"))
	}()
	_, err := WaitWarm(ctx, f2, c2.Name, 5*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "transient") {
		t.Fatalf("WaitWarm timing out after query errors = %v, want the deadline and the last query error", err)
	}

	// A later successful query clears the remembered error.
	f3, c3 := loaded(t)
	ctx3, cancel3 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel3()
	go func() {
		waitForCond(func() bool { return f3.subscribers() == 1 })
		f3.setErr("list", errors.New("blip"))
		time.Sleep(20 * time.Millisecond)
		f3.setErr("list", nil)
	}()
	_, err = WaitWarm(ctx3, f3, c3.Name, 5*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "blip") {
		t.Fatalf("WaitWarm = %v, want a plain deadline error once queries recovered", err)
	}
}

func TestWaitDown(t *testing.T) {
	f, c := loaded(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := WaitDown(ctx, f, c.Name, time.Hour); err != nil {
		t.Fatalf("WaitDown with nothing up: %v", err)
	}
	if err := f.Initiate(ctx, c.Name, ChildName(c.Name, c.Epoch)); err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	// Another connection's SA staying up must not count.
	f.addSA(IKESA{Name: "other", State: IKEStateEstablished})
	go func() {
		waitForCond(func() bool { return f.subscribers() == 1 })
		f.dropIKE(c.Name, true) // what DPD with dpd_action=clear does
	}()
	if err := WaitDown(ctx, f, c.Name, time.Hour); err != nil {
		t.Fatalf("WaitDown after DPD cleared the SA: %v", err)
	}

	f.addSA(IKESA{Name: c.Name, State: IKEStateEstablished})
	short, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if err := WaitDown(short, f, c.Name, 0); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitDown with the SA still up = %v, want a deadline error", err)
	}
}

// waitForCond spins until cond holds or 5s pass; for goroutines in tests
// that cannot call t.Fatal.
func waitForCond(cond func() bool) {
	deadline := time.Now().Add(5 * time.Second)
	for !cond() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
}

func TestIKESA_Warm(t *testing.T) {
	for name, tc := range map[string]struct {
		sa   IKESA
		want bool
	}{
		"installed":       {IKESA{State: IKEStateEstablished, Children: []ChildSA{{State: ChildStateRekeyed}, {State: ChildStateInstalled}}}, true},
		"no children":     {IKESA{State: IKEStateEstablished}, false},
		"child not ready": {IKESA{State: IKEStateEstablished, Children: []ChildSA{{State: ChildStateInstalling}}}, false},
		"not established": {IKESA{State: "CONNECTING", Children: []ChildSA{{State: ChildStateInstalled}}}, false},
	} {
		if got := tc.sa.Warm(); got != tc.want {
			t.Errorf("%s: Warm() = %v, want %v", name, got, tc.want)
		}
	}
	sas := []IKESA{{Name: "a", UniqueID: 3}, {Name: "a", UniqueID: 9}, {Name: "b", UniqueID: 20}}
	if sa, ok := FindIKE(sas, "a"); !ok || sa.UniqueID != 9 {
		t.Errorf("FindIKE = %+v, %v; want the newest", sa, ok)
	}
	if _, ok := FindIKE(sas, "c"); ok {
		t.Error("FindIKE found a missing name")
	}
}
