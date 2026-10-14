package netem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"
)

// A Scenario changes the shaping of a testbed over time. Its nodes are
// logical names (client, gw1, gw2, ...) that a hosts map turns into
// addresses where the scenario runs; every node runs the steps that name
// it, counting from one start instant shared by all, so the nodes change
// together.
type Scenario struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Expect says what the system should do, for the person watching.
	Expect string `json:"expect"`
	Steps  []Step `json:"steps"`
}

// Step shapes the traffic from Node to Peer from At on, until a later
// step for the same pair changes it. Clear (or an empty shape) removes
// the shaping.
type Step struct {
	At     Duration `json:"at"`
	Node   string   `json:"node"`
	Peer   string   `json:"peer"`
	Delay  Duration `json:"delay,omitempty"`
	Jitter Duration `json:"jitter,omitempty"`
	Loss   float64  `json:"loss,omitempty"`
	Rate   string   `json:"rate,omitempty"`
	Clear  bool     `json:"clear,omitempty"`
}

// Shape returns the shape the step sets.
func (s Step) Shape() Shape {
	if s.Clear {
		return Shape{}
	}
	return Shape{Delay: time.Duration(s.Delay), Jitter: time.Duration(s.Jitter), Loss: s.Loss, Rate: s.Rate}
}

// Duration is a time.Duration written as "10s" in JSON.
type Duration time.Duration

// UnmarshalJSON reads "10s", "150ms", ...
func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("netem: a duration is a string like \"10s\": %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("netem: %w", err)
	}
	*d = Duration(v)
	return nil
}

// MarshalJSON writes the duration as "10s".
func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

// Parse reads a scenario and checks it.
func Parse(data []byte) (Scenario, error) {
	var s Scenario
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, fmt.Errorf("netem: scenario: %w", err)
	}
	return s, s.Validate()
}

// Load reads a scenario file.
func Load(path string) (Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Scenario{}, err
	}
	s, err := Parse(data)
	if err != nil {
		return s, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// Validate checks every step.
func (s Scenario) Validate() error {
	if s.Name == "" {
		return errors.New("netem: a scenario needs a name")
	}
	if len(s.Steps) == 0 {
		return fmt.Errorf("netem: scenario %s has no steps", s.Name)
	}
	for i, st := range s.Steps {
		switch {
		case st.Node == "" || st.Peer == "":
			return fmt.Errorf("netem: scenario %s step %d: node and peer are required", s.Name, i)
		case st.Node == st.Peer:
			return fmt.Errorf("netem: scenario %s step %d: %s shapes itself", s.Name, i, st.Node)
		case st.At < 0:
			return fmt.Errorf("netem: scenario %s step %d: negative time", s.Name, i)
		case st.Clear && (st.Delay != 0 || st.Jitter != 0 || st.Loss != 0 || st.Rate != ""):
			return fmt.Errorf("netem: scenario %s step %d: clear takes no shape", s.Name, i)
		}
		if err := st.Shape().Validate(); err != nil {
			return fmt.Errorf("netem: scenario %s step %d: %w", s.Name, i, err)
		}
	}
	return nil
}

// Nodes returns the nodes the scenario shapes, sorted.
func (s Scenario) Nodes() []string {
	var out []string
	for _, st := range s.Steps {
		if !slices.Contains(out, st.Node) {
			out = append(out, st.Node)
		}
	}
	slices.Sort(out)
	return out
}

// Duration is when the last step happens.
func (s Scenario) Duration() time.Duration {
	var d time.Duration
	for _, st := range s.Steps {
		d = max(d, time.Duration(st.At))
	}
	return d
}

// ParseHosts reads "client=10.0.0.2,gw1=10.0.0.3".
func ParseHosts(spec string) (map[string]netip.Addr, error) {
	hosts := map[string]netip.Addr{}
	for _, kv := range strings.Split(spec, ",") {
		if kv = strings.TrimSpace(kv); kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("netem: host %q is not name=address", kv)
		}
		a, err := netip.ParseAddr(v)
		if err != nil {
			return nil, fmt.Errorf("netem: host %s: %w", k, err)
		}
		hosts[k] = a
	}
	return hosts, nil
}

// Clock is how Run waits; tests replace it.
type Clock struct {
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
}

// RealClock is the wall clock.
var RealClock = Clock{
	Now: time.Now,
	Sleep: func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	},
}

// Run applies, on dev, the steps of s that name node, each at start plus
// its time; hosts turns peer names into addresses. Steps at the same time
// are applied together. It returns after the last of them, leaving that
// shaping in place (a scenario ends by clearing what it set).
func Run(ctx context.Context, s Scenario, node string, hosts map[string]netip.Addr, dev Device, start time.Time, clock Clock, log func(string, ...any)) error {
	var mine []Step
	for _, st := range s.Steps {
		if st.Node != node {
			continue
		}
		if _, ok := hosts[st.Peer]; !ok {
			return fmt.Errorf("netem: scenario %s: no address for %s", s.Name, st.Peer)
		}
		mine = append(mine, st)
	}
	if len(mine) == 0 {
		return fmt.Errorf("netem: scenario %s has no step for node %s", s.Name, node)
	}
	slices.SortStableFunc(mine, func(a, b Step) int { return int(a.At - b.At) })
	rules := map[netip.Addr]Shape{}
	for i := 0; i < len(mine); {
		at := mine[i].At
		j := i
		for j < len(mine) && mine[j].At == at {
			j++
		}
		if wait := start.Add(time.Duration(at)).Sub(clock.Now()); wait > 0 {
			if err := clock.Sleep(ctx, wait); err != nil {
				return err
			}
		}
		for _, st := range mine[i:j] {
			if sh := st.Shape(); sh.IsZero() {
				delete(rules, hosts[st.Peer])
			} else {
				rules[hosts[st.Peer]] = sh
			}
		}
		if err := dev.Apply(rules); err != nil {
			return err
		}
		for _, st := range mine[i:j] {
			log("t+%s %s -> %s: %s", time.Duration(st.At), node, st.Peer, describe(st))
		}
		i = j
	}
	return nil
}

func describe(st Step) string {
	if sh := st.Shape(); !sh.IsZero() {
		return sh.String()
	}
	return "clear"
}
