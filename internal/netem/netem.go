// Package netem shapes the links of a testbed with Linux netem: delay,
// jitter, loss and rate, per destination address, on one device. A
// device carries a prio qdisc whose first three bands keep the default
// priority map, and one extra band per shaped destination, each with its
// own netem, picked by a u32 filter on the destination address. Traffic
// to anywhere else is untouched.
//
// Scenarios (scenario.go) change the shaping of several nodes over time
// from one shared start instant.
package netem

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Shape is what packets to one destination go through.
type Shape struct {
	Delay  time.Duration
	Jitter time.Duration
	// Loss is a percentage, 0..100.
	Loss float64
	// Rate limits the bandwidth, in tc's notation ("10mbit"); empty is
	// no limit.
	Rate string
}

// IsZero reports whether s changes nothing.
func (s Shape) IsZero() bool { return s == Shape{} }

// Validate checks s can be turned into netem arguments.
func (s Shape) Validate() error {
	switch {
	case s.Delay < 0 || s.Jitter < 0:
		return errors.New("netem: delay and jitter must not be negative")
	case s.Jitter > 0 && s.Delay == 0:
		return errors.New("netem: jitter needs a delay")
	case s.Loss < 0 || s.Loss > 100:
		return fmt.Errorf("netem: loss %g%% is not a percentage", s.Loss)
	case s.Rate != "" && !rateRE(s.Rate):
		return fmt.Errorf("netem: rate %q must look like 10mbit, 500kbit or 1gbit", s.Rate)
	}
	return nil
}

func rateRE(r string) bool {
	num := strings.TrimRightFunc(r, func(c rune) bool { return c >= 'a' && c <= 'z' })
	unit := r[len(num):]
	if _, err := strconv.ParseFloat(num, 64); err != nil || num == "" {
		return false
	}
	return slices.Contains([]string{"bit", "kbit", "mbit", "gbit", "bps", "kbps", "mbps", "gbps"}, unit)
}

func ms(d time.Duration) string {
	return strconv.FormatFloat(float64(d)/float64(time.Millisecond), 'f', -1, 64) + "ms"
}

// Args returns s as netem arguments.
func (s Shape) Args() []string {
	args := []string{"delay", ms(s.Delay)}
	if s.Jitter > 0 {
		args = append(args, ms(s.Jitter))
	}
	if s.Loss > 0 {
		args = append(args, "loss", strconv.FormatFloat(s.Loss, 'f', -1, 64)+"%")
	}
	if s.Rate != "" {
		args = append(args, "rate", s.Rate)
	}
	return args
}

func (s Shape) String() string { return strings.Join(s.Args(), " ") }

// ParseShape reads "delay=80ms,jitter=5ms,loss=1,rate=10mbit" (any
// subset, in any order).
func ParseShape(spec string) (Shape, error) {
	var s Shape
	for _, kv := range strings.Split(spec, ",") {
		if kv = strings.TrimSpace(kv); kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return s, fmt.Errorf("netem: %q is not key=value", kv)
		}
		var err error
		switch k {
		case "delay":
			s.Delay, err = time.ParseDuration(v)
		case "jitter":
			s.Jitter, err = time.ParseDuration(v)
		case "loss":
			s.Loss, err = strconv.ParseFloat(strings.TrimSuffix(v, "%"), 64)
		case "rate":
			s.Rate = v
		default:
			return s, fmt.Errorf("netem: unknown setting %q (want delay, jitter, loss or rate)", k)
		}
		if err != nil {
			return s, fmt.Errorf("netem: %s: %w", k, err)
		}
	}
	return s, s.Validate()
}

// MaxDestinations is how many destinations one device can shape: prio
// has 16 bands and the first three are the default ones.
const MaxDestinations = 13

// Runner runs a command and returns its combined output.
type Runner func(name string, args ...string) ([]byte, error)

// Exec runs commands for real.
func Exec(name string, args ...string) ([]byte, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// Device shapes the traffic leaving one network interface.
type Device struct {
	Name string
	Run  Runner
}

// priomap keeps the default priority-to-band mapping within the first
// three bands, so the extra bands only get what a filter sends there.
var priomap = []string{"1", "2", "2", "2", "1", "2", "0", "0", "1", "1", "1", "1", "1", "1", "1", "1"}

// Commands returns the tc commands that shape dev as rules says,
// starting from a device with no qdisc of its own.
func Commands(dev string, rules map[netip.Addr]Shape) ([][]string, error) {
	dsts := make([]netip.Addr, 0, len(rules))
	for a, s := range rules {
		if !a.Is4() {
			return nil, fmt.Errorf("netem: %s: only IPv4 destinations are supported", a)
		}
		if err := s.Validate(); err != nil {
			return nil, fmt.Errorf("netem: %s: %w", a, err)
		}
		dsts = append(dsts, a)
	}
	if len(dsts) == 0 {
		return nil, nil
	}
	if len(dsts) > MaxDestinations {
		return nil, fmt.Errorf("netem: %d destinations on %s, at most %d", len(dsts), dev, MaxDestinations)
	}
	slices.SortFunc(dsts, func(a, b netip.Addr) int { return a.Compare(b) })
	cmds := [][]string{append([]string{"qdisc", "add", "dev", dev, "root", "handle", "1:", "prio",
		"bands", strconv.Itoa(3 + len(dsts)), "priomap"}, priomap...)}
	for i, dst := range dsts {
		band := fmt.Sprintf("1:%d", 4+i)
		cmds = append(cmds,
			append([]string{"qdisc", "add", "dev", dev, "parent", band, "handle", fmt.Sprintf("%d:", 40+i), "netem"}, rules[dst].Args()...),
			[]string{"filter", "add", "dev", dev, "parent", "1:", "protocol", "ip", "prio", "1",
				"u32", "match", "ip", "dst", netip.PrefixFrom(dst, 32).String(), "flowid", band},
		)
	}
	return cmds, nil
}

// Apply replaces whatever shaping dev has with rules (none clears it).
func (d Device) Apply(rules map[netip.Addr]Shape) error {
	cmds, err := Commands(d.Name, rules)
	if err != nil {
		return err
	}
	if err := d.Clear(); err != nil {
		return err
	}
	for _, c := range cmds {
		if _, err := d.Run("tc", c...); err != nil {
			_ = d.Clear()
			return err
		}
	}
	return nil
}

// Clear removes dev's root qdisc, and so all of its shaping. A device
// with none is already clear.
func (d Device) Clear() error {
	out, err := d.Run("tc", "qdisc", "del", "dev", d.Name, "root")
	if err == nil {
		return nil
	}
	msg := string(out) + err.Error()
	for _, benign := range []string{"No such file or directory", "Cannot delete qdisc with handle of zero", "Invalid handle"} {
		if strings.Contains(msg, benign) {
			return nil
		}
	}
	return err
}

// Show returns dev's qdiscs and filters as tc prints them.
func (d Device) Show() (string, error) {
	q, err := d.Run("tc", "qdisc", "show", "dev", d.Name)
	if err != nil {
		return "", err
	}
	f, err := d.Run("tc", "filter", "show", "dev", d.Name)
	if err != nil {
		return "", err
	}
	return string(q) + string(f), nil
}
