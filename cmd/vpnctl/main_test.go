package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const spanLines = `{"time":"x","level":"INFO","msg":"span","role":"client","version":"v","trace_id":"t1","session":"42","epoch":2,"span":"migration.commit","start":"2026-10-06T01:00:00.001Z","duration_ms":0.5,"status":"ok"}
{"time":"x","level":"INFO","msg":"span","role":"gateway","node":"sg","version":"v","trace_id":"t1","session":"42","epoch":2,"span":"migration.apply","start":"2026-10-06T01:00:00.002Z","duration_ms":1,"status":"ok"}
{"time":"x","level":"INFO","msg":"span","role":"client","version":"v","trace_id":"t9","session":"7","epoch":4,"span":"migration.commit","start":"2026-10-06T01:00:01Z","duration_ms":1,"status":"conflict"}
`

func TestTrace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.log")
	if err := os.WriteFile(path, []byte(spanLines), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"trace", path}, &out, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "session 42") || !strings.Contains(out.String(), "session 7") ||
		!strings.Contains(out.String(), "gateway sg") {
		t.Fatalf("trace:\n%s", out.String())
	}
	out.Reset()
	if err := run([]string{"trace", "--session", "7", "-"}, &out, strings.NewReader(spanLines)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "session 42") || !strings.Contains(out.String(), "conflict") {
		t.Fatalf("trace --session 7:\n%s", out.String())
	}
	if err := run([]string{"trace"}, &out, nil); err == nil {
		t.Error("trace without logs")
	}
	if err := run([]string{"trace", filepath.Join(t.TempDir(), "none")}, &out, nil); err == nil {
		t.Error("trace of a missing file")
	}
	if err := run([]string{"trace", "--bogus"}, &out, nil); err == nil {
		t.Error("trace with a bad flag")
	}
}

type fakeTC struct{ cmds []string }

func (f *fakeTC) run(name string, args ...string) ([]byte, error) {
	f.cmds = append(f.cmds, name+" "+strings.Join(args, " "))
	return []byte("qdisc prio 1: root\n"), nil
}

func TestNetem(t *testing.T) {
	f := &fakeTC{}
	var out bytes.Buffer
	if err := cmdNetem(context.Background(), []string{"apply", "--dev", "wan0", "--rule", "192.0.2.11:delay=80ms", "--rule", "192.0.2.12:loss=100"}, &out, f.run); err != nil {
		t.Fatal(err)
	}
	all := strings.Join(f.cmds, "\n")
	if !strings.Contains(all, "netem delay 80ms") || !strings.Contains(all, "loss 100%") {
		t.Fatalf("apply ran:\n%s", all)
	}
	if err := cmdNetem(context.Background(), []string{"clear", "--dev", "wan0"}, &out, f.run); err != nil {
		t.Fatal(err)
	}
	if err := cmdNetem(context.Background(), []string{"show", "--dev", "wan0"}, &out, f.run); err != nil || !strings.Contains(out.String(), "prio") {
		t.Fatalf("show: %q, %v", out.String(), err)
	}

	scen := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(scen, []byte(`{"name":"s","steps":[
		{"at":"0s","node":"client","peer":"gw1","delay":"10ms"},
		{"at":"0s","node":"client","peer":"gw1","clear":true}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := cmdNetem(context.Background(), []string{"run", "--dev", "wan0", "--scenario", scen, "--node", "client", "--hosts", "gw1=192.0.2.11", "--start", "1"}, &out, f.run); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "scenario s on client") {
		t.Errorf("run output %q", out.String())
	}

	for name, args := range map[string][]string{
		"no subcommand":   {},
		"no dev":          {"clear"},
		"no rule":         {"apply", "--dev", "wan0"},
		"bad rule":        {"apply", "--dev", "wan0", "--rule", "192.0.2.11"},
		"bad rule ip":     {"apply", "--dev", "wan0", "--rule", "x:delay=1ms"},
		"bad rule shape":  {"apply", "--dev", "wan0", "--rule", "192.0.2.11:loss=900"},
		"run needs flags": {"run", "--dev", "wan0"},
		"run bad file":    {"run", "--dev", "wan0", "--scenario", "/none", "--node", "a", "--hosts", "a=1.2.3.4"},
		"run bad hosts":   {"run", "--dev", "wan0", "--scenario", scen, "--node", "client", "--hosts", "gw1"},
		"unknown":         {"bounce", "--dev", "wan0"},
		"bad flag":        {"clear", "--nope"},
	} {
		if err := cmdNetem(context.Background(), args, &out, f.run); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if (rules{}).String() == "" {
		t.Error("rules String")
	}
}

func TestRunDispatch(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{{"version"}, {"help"}} {
		if err := run(args, &out, nil); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
	if err := run(nil, &out, nil); err == nil {
		t.Error("no arguments accepted")
	}
	if err := run([]string{"frobnicate"}, &out, nil); err == nil {
		t.Error("unknown command accepted")
	}
}

// scriptedTC is a fake tc: it records each command, and fail decides
// whether one fails.
type scriptedTC struct {
	cmds []string
	fail func(cmd string) bool
}

func (f *scriptedTC) run(name string, args ...string) ([]byte, error) {
	cmd := name + " " + strings.Join(args, " ")
	f.cmds = append(f.cmds, cmd)
	if f.fail != nil && f.fail(cmd) {
		return []byte("RTNETLINK answers: Operation not permitted"), errors.New("exit status 2")
	}
	return nil, nil
}

func (f *scriptedTC) last() string { return f.cmds[len(f.cmds)-1] }

func writeScenario(t *testing.T, steps string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(path, []byte(`{"name":"s","steps":[`+steps+`]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runArgs(scen string) []string {
	return []string{"run", "--dev", "wan0", "--scenario", scen, "--node", "client", "--hosts", "gw1=192.0.2.11,gw2=192.0.2.12"}
}

// Interrupted after a step shaped the device: the shaping goes.
func TestNetemRunInterruptedClears(t *testing.T) {
	scen := writeScenario(t, `{"at":"0s","node":"client","peer":"gw1","delay":"80ms"},
		{"at":"1h","node":"client","peer":"gw1","clear":true}`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &scriptedTC{}
	f.fail = func(cmd string) bool {
		if strings.Contains(cmd, "netem delay 80ms") {
			cancel() // the operator presses ^C while the step waits for the next
		}
		return false
	}
	var out bytes.Buffer
	err := cmdNetem(ctx, runArgs(scen), &out, f.run)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if f.last() != "tc qdisc del dev wan0 root" || !strings.Contains(out.String(), "removed the shaping") {
		t.Errorf("not cleared; ran:\n%s\n%s", strings.Join(f.cmds, "\n"), out.String())
	}
}

// A step that fails halfway, where Apply itself could not clean up (its
// first clear failed): run clears what the previous step shaped.
func TestNetemRunFailureClears(t *testing.T) {
	scen := writeScenario(t, `{"at":"0s","node":"client","peer":"gw1","delay":"80ms"},
		{"at":"0s","node":"client","peer":"gw2","delay":"0ms","clear":true},
		{"at":"10ms","node":"client","peer":"gw2","loss":5}`)
	dels := 0
	f := &scriptedTC{}
	f.fail = func(cmd string) bool {
		if cmd == "tc qdisc del dev wan0 root" {
			dels++
			return dels == 2 // the second step's clear fails once
		}
		return false
	}
	var out bytes.Buffer
	err := cmdNetem(context.Background(), runArgs(scen), &out, f.run)
	if err == nil {
		t.Fatal("a failing step went unnoticed")
	}
	if f.last() != "tc qdisc del dev wan0 root" || dels != 3 {
		t.Errorf("not cleared after the failure (%d clears); ran:\n%s", dels, strings.Join(f.cmds, "\n"))
	}

	// And if that clear fails too, both errors are reported.
	f = &scriptedTC{fail: func(cmd string) bool { return cmd == "tc qdisc del dev wan0 root" && len(f.cmds) > 2 }}
	err = cmdNetem(context.Background(), runArgs(scen), &out, f.run)
	if err == nil || !strings.Contains(err.Error(), "could not remove the shaping") {
		t.Errorf("err %v", err)
	}
}

// Failing before any step shaped anything: the device is left alone (it
// may carry someone else's qdisc).
func TestNetemRunFailureBeforeShapingLeavesDevice(t *testing.T) {
	scen := writeScenario(t, `{"at":"0s","node":"gw1","peer":"client","delay":"80ms"}`)
	f := &scriptedTC{}
	var out bytes.Buffer
	if err := cmdNetem(context.Background(), runArgs(scen), &out, f.run); err == nil {
		t.Fatal("a node with no steps went unnoticed")
	}
	if len(f.cmds) != 0 {
		t.Errorf("touched the device: %v", f.cmds)
	}
}
