package netem

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// fakeTC records the commands it is given and fails as told.
type fakeTC struct {
	cmds   []string
	failOn string // fail the command containing this
	out    string // what a failing command prints
	show   string
}

func (f *fakeTC) run(name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	f.cmds = append(f.cmds, line)
	if f.failOn != "" && strings.Contains(line, f.failOn) {
		return []byte(f.out), errors.New("exit status 2")
	}
	if strings.Contains(line, " show ") {
		return []byte(f.show + "|" + args[0] + "\n"), nil
	}
	return nil, nil
}

func TestShapeArgsAndParse(t *testing.T) {
	for spec, want := range map[string]string{
		"delay=80ms":                        "delay 80ms",
		"delay=80ms,jitter=5ms":             "delay 80ms 5ms",
		"loss=1%":                           "delay 0ms loss 1%",
		"delay=1.5ms, loss=0.5,rate=10mbit": "delay 1.5ms loss 0.5% rate 10mbit",
		"":                                  "delay 0ms",
	} {
		s, err := ParseShape(spec)
		if err != nil || s.String() != want {
			t.Errorf("ParseShape(%q) = %q, %v; want %q", spec, s, err, want)
		}
	}
	for _, bad := range []string{"delay", "speed=1", "delay=x", "jitter=5ms", "loss=150", "loss=-1", "rate=fast", "rate=10", "rate=mbit", "jitter=x", "loss=x", "delay=-1s"} {
		if _, err := ParseShape(bad); err == nil {
			t.Errorf("ParseShape(%q) accepted", bad)
		}
	}
	if !(Shape{}).IsZero() || (Shape{Loss: 1}).IsZero() {
		t.Error("IsZero")
	}
}

func TestCommands(t *testing.T) {
	a, b := netip.MustParseAddr("192.0.2.12"), netip.MustParseAddr("192.0.2.11")
	cmds, err := Commands("wan0", map[netip.Addr]Shape{a: {Loss: 100}, b: {Delay: 80 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, len(cmds))
	for i, c := range cmds {
		got[i] = strings.Join(c, " ")
	}
	want := []string{
		"qdisc add dev wan0 root handle 1: prio bands 5 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1",
		// sorted by address: .11 gets the first extra band
		"qdisc add dev wan0 parent 1:4 handle 40: netem delay 80ms",
		"filter add dev wan0 parent 1: protocol ip prio 1 u32 match ip dst 192.0.2.11/32 flowid 1:4",
		"qdisc add dev wan0 parent 1:5 handle 41: netem delay 0ms loss 100%",
		"filter add dev wan0 parent 1: protocol ip prio 1 u32 match ip dst 192.0.2.12/32 flowid 1:5",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("commands:\n%s", strings.Join(got, "\n"))
	}
	if cmds, err := Commands("wan0", nil); err != nil || cmds != nil {
		t.Errorf("no rules: %v, %v", cmds, err)
	}
	if _, err := Commands("wan0", map[netip.Addr]Shape{netip.MustParseAddr("2001:db8::1"): {}}); err == nil {
		t.Error("accepted an IPv6 destination")
	}
	if _, err := Commands("wan0", map[netip.Addr]Shape{a: {Loss: 200}}); err == nil {
		t.Error("accepted a bad shape")
	}
	many := map[netip.Addr]Shape{}
	for i := 0; i <= MaxDestinations; i++ {
		many[netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)})] = Shape{Delay: time.Millisecond}
	}
	if _, err := Commands("wan0", many); err == nil {
		t.Error("accepted more destinations than prio has bands")
	}
}

func TestDevice(t *testing.T) {
	f := &fakeTC{}
	d := Device{Name: "wan0", Run: f.run}
	if err := d.Apply(map[netip.Addr]Shape{netip.MustParseAddr("192.0.2.11"): {Delay: time.Millisecond}}); err != nil {
		t.Fatal(err)
	}
	if len(f.cmds) != 4 || f.cmds[0] != "tc qdisc del dev wan0 root" {
		t.Fatalf("apply ran %q", f.cmds)
	}
	// Clearing a clear device is fine; other failures are not.
	f = &fakeTC{failOn: "qdisc del", out: "Error: Cannot delete qdisc with handle of zero."}
	d.Run = f.run
	if err := d.Clear(); err != nil {
		t.Errorf("clear of a clear device: %v", err)
	}
	f.out = "Error: Operation not permitted."
	if err := d.Clear(); err == nil {
		t.Error("a failed clear succeeded")
	}
	if err := d.Apply(nil); err == nil {
		t.Error("apply hid a failed clear")
	}
	// A failed command midway clears what was done.
	f = &fakeTC{failOn: "filter add"}
	d.Run = f.run
	if err := d.Apply(map[netip.Addr]Shape{netip.MustParseAddr("192.0.2.11"): {Delay: time.Millisecond}}); err == nil {
		t.Error("apply hid a failed filter")
	}
	if last := f.cmds[len(f.cmds)-1]; last != "tc qdisc del dev wan0 root" {
		t.Errorf("no clean-up after a failure: %q", f.cmds)
	}
	if err := d.Apply(map[netip.Addr]Shape{netip.MustParseAddr("192.0.2.11"): {Loss: 300}}); err == nil {
		t.Error("applied a bad shape")
	}
	// Show prints qdiscs, then filters.
	f = &fakeTC{show: "x"}
	d.Run = f.run
	if out, err := d.Show(); err != nil || out != "x|qdisc\nx|filter\n" {
		t.Errorf("show = %q, %v", out, err)
	}
	f.failOn = "qdisc show"
	if _, err := d.Show(); err == nil {
		t.Error("show hid an error")
	}
	f.failOn = "filter show"
	if _, err := d.Show(); err == nil {
		t.Error("show hid a filter error")
	}
}

func TestExec(t *testing.T) {
	if out, err := Exec("echo", "hi"); err != nil || strings.TrimSpace(string(out)) != "hi" {
		t.Errorf("echo: %q, %v", out, err)
	}
	if _, err := Exec("false"); err == nil {
		t.Error("false succeeded")
	}
}

const scenarioJSON = `{
  "name": "a",
  "description": "the direct path degrades",
  "expect": "move to the detour",
  "steps": [
    {"at": "10s", "node": "client", "peer": "gw1", "delay": "150ms"},
    {"at": "10s", "node": "client", "peer": "gw2", "loss": 1},
    {"at": "10s", "node": "gw1", "peer": "client", "delay": "150ms"},
    {"at": "70s", "node": "client", "peer": "gw1", "clear": true},
    {"at": "70s", "node": "client", "peer": "gw2", "clear": true},
    {"at": "70s", "node": "gw1", "peer": "client", "clear": true}
  ]
}`

func TestScenarioParse(t *testing.T) {
	s, err := Parse([]byte(scenarioJSON))
	if err != nil {
		t.Fatal(err)
	}
	if s.Duration() != 70*time.Second || !reflect.DeepEqual(s.Nodes(), []string{"client", "gw1"}) {
		t.Errorf("duration %s, nodes %v", s.Duration(), s.Nodes())
	}
	if got := s.Steps[0].Shape(); got.Delay != 150*time.Millisecond {
		t.Errorf("step 0 shape %v", got)
	}
	if !s.Steps[3].Shape().IsZero() {
		t.Error("a clear step has a shape")
	}
	for name, bad := range map[string]string{
		"not json":      `{`,
		"unknown field": `{"name":"x","steps":[{"at":"1s","node":"a","peer":"b"}],"speed":1}`,
		"no name":       `{"steps":[{"at":"1s","node":"a","peer":"b"}]}`,
		"no steps":      `{"name":"x"}`,
		"no peer":       `{"name":"x","steps":[{"at":"1s","node":"a"}]}`,
		"self":          `{"name":"x","steps":[{"at":"1s","node":"a","peer":"a"}]}`,
		"negative":      `{"name":"x","steps":[{"at":"-1s","node":"a","peer":"b"}]}`,
		"clear+shape":   `{"name":"x","steps":[{"at":"1s","node":"a","peer":"b","clear":true,"loss":1}]}`,
		"bad shape":     `{"name":"x","steps":[{"at":"1s","node":"a","peer":"b","loss":101}]}`,
		"bad duration":  `{"name":"x","steps":[{"at":"soon","node":"a","peer":"b"}]}`,
		"number time":   `{"name":"x","steps":[{"at":10,"node":"a","peer":"b"}]}`,
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	d, err := Duration(90 * time.Second).MarshalJSON()
	if err != nil || string(d) != `"1m30s"` {
		t.Errorf("marshal %s, %v", d, err)
	}
}

func TestLoadShippedScenarios(t *testing.T) {
	paths, err := filepath.Glob("../../deploy/scenarios/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) < 3 {
		t.Fatalf("found %d scenarios in deploy/scenarios, want a, b and c", len(paths))
	}
	for _, p := range paths {
		s, err := Load(p)
		if err != nil {
			t.Errorf("%s: %v", p, err)
			continue
		}
		if s.Description == "" || s.Expect == "" {
			t.Errorf("%s: say what it does and what to expect", p)
		}
		for _, n := range s.Nodes() {
			if n != "client" && !strings.HasPrefix(n, "gw") {
				t.Errorf("%s: node %q is not client or gw<n>", p, n)
			}
		}
	}
	if _, err := Load(filepath.Join(t.TempDir(), "none.json")); err == nil {
		t.Error("loaded a missing file")
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil {
		t.Error("loaded an invalid scenario")
	}
}

func TestParseHosts(t *testing.T) {
	h, err := ParseHosts("client=10.0.0.2, gw1=10.0.0.3,")
	if err != nil || h["client"] != netip.MustParseAddr("10.0.0.2") || len(h) != 2 {
		t.Fatalf("hosts %v, %v", h, err)
	}
	for _, bad := range []string{"client", "=1.2.3.4", "gw1=x"} {
		if _, err := ParseHosts(bad); err == nil {
			t.Errorf("ParseHosts(%q) accepted", bad)
		}
	}
}

// fakeClock moves forward exactly as far as it is asked to sleep.
type fakeClock struct{ now time.Time }

func (c *fakeClock) clock() Clock {
	return Clock{
		Now:   func() time.Time { return c.now },
		Sleep: func(ctx context.Context, d time.Duration) error { c.now = c.now.Add(d); return ctx.Err() },
	}
}

func TestRun(t *testing.T) {
	s, err := Parse([]byte(scenarioJSON))
	if err != nil {
		t.Fatal(err)
	}
	hosts := map[string]netip.Addr{
		"client": netip.MustParseAddr("192.0.2.100"),
		"gw1":    netip.MustParseAddr("192.0.2.11"),
		"gw2":    netip.MustParseAddr("192.0.2.12"),
	}
	start := time.Unix(1000, 0)
	c := &fakeClock{now: start}
	f := &fakeTC{}
	var logged []string
	err = Run(context.Background(), s, "client", hosts, Device{Name: "wan0", Run: f.run}, start, c.clock(),
		func(format string, args ...any) { logged = append(logged, format) })
	if err != nil {
		t.Fatal(err)
	}
	// Two applies (t+10s with both peers shaped, t+70s with none), each a
	// clear first.
	applies := 0
	for _, cmd := range f.cmds {
		if cmd == "tc qdisc del dev wan0 root" {
			applies++
		}
	}
	if applies != 2 || c.now != start.Add(70*time.Second) || len(logged) != 4 {
		t.Errorf("%d applies, ended at %s, %d log lines:\n%s", applies, c.now.Sub(start), len(logged), strings.Join(f.cmds, "\n"))
	}
	if !strings.Contains(strings.Join(f.cmds, "\n"), "match ip dst 192.0.2.12/32") {
		t.Error("gw2 was not shaped")
	}

	// Errors: no steps for the node, an unknown peer, a cancelled wait,
	// a failing tc.
	if err := Run(context.Background(), s, "gw9", hosts, Device{Run: f.run}, start, c.clock(), func(string, ...any) {}); err == nil {
		t.Error("ran with no step for the node")
	}
	if err := Run(context.Background(), s, "client", map[string]netip.Addr{}, Device{Run: f.run}, start, c.clock(), func(string, ...any) {}); err == nil {
		t.Error("ran with an unknown peer")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.now = start
	if err := Run(ctx, s, "client", hosts, Device{Run: f.run}, start, c.clock(), func(string, ...any) {}); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled run: %v", err)
	}
	c.now = start.Add(time.Hour) // late: no waiting
	bad := &fakeTC{failOn: "netem"}
	if err := Run(context.Background(), s, "client", hosts, Device{Run: bad.run}, start, c.clock(), func(string, ...any) {}); err == nil {
		t.Error("a failing tc went unnoticed")
	}
	// The real clock sleeps and honours cancellation.
	if err := RealClock.Sleep(context.Background(), time.Millisecond); err != nil {
		t.Error(err)
	}
	if err := RealClock.Sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("real sleep after cancel: %v", err)
	}
}
