package gateway

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
)

// Rule preferences and routing tables this agent owns. Everything it
// installs uses these, so a restart can clear what a crash left behind.
const (
	probeRulePref = 100
	fwdRulePref   = 1000
	probeTable    = 100
	// egressTableBase + n is the table for the egress reached over egb<n>.
	egressTableBase = 1000
)

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ip(args ...string) error { return run("ip", args...) }

// ipIgnore runs ip and ignores the "already there" or "not there" answers
// that make an add or delete idempotent.
func ipIgnore(args ...string) error {
	err := ip(args...)
	if err == nil {
		return nil
	}
	msg := err.Error()
	for _, benign := range []string{"File exists", "No such process", "No such file or directory", "Cannot find device", "FIB table does not exist"} {
		if strings.Contains(msg, benign) {
			return nil
		}
	}
	return err
}

func setRPFilterLoose(dev string) error {
	// Loose (2): a backbone carries return traffic whose source is an
	// Internet address and client traffic whose virtual IP is routed out
	// another device; strict reverse-path filtering would drop both.
	return os.WriteFile("/proc/sys/net/ipv4/conf/"+dev+"/rp_filter", []byte("2\n"), 0o644)
}

func addrUp(dev string, addr netip.Addr, mtu int) error {
	if err := ipIgnore("addr", "add", netip.PrefixFrom(addr, 32).String(), "dev", dev); err != nil {
		return err
	}
	if err := ip("link", "set", dev, "mtu", strconv.Itoa(mtu), "up"); err != nil {
		return err
	}
	return setRPFilterLoose(dev)
}

// clearRules deletes every rule at pref, left over from a previous run.
func clearRules(pref int) {
	for i := 0; i < 100000; i++ {
		if ip("rule", "del", "pref", strconv.Itoa(pref)) != nil {
			return
		}
	}
}

func flushTable(table int) error {
	return ipIgnore("route", "flush", "table", strconv.Itoa(table))
}

func ruleFrom(vip netip.Addr, table int) []string {
	return []string{"from", netip.PrefixFrom(vip, 32).String(), "lookup", strconv.Itoa(table), "pref", strconv.Itoa(fwdRulePref)}
}

func addRule(args []string) error { return ipIgnore(append([]string{"rule", "add"}, args...)...) }
func delRule(args []string) error { return ipIgnore(append([]string{"rule", "del"}, args...)...) }

// natRule masquerades the client subnet out of the uplink only: traffic
// an access gateway forwards over the backbone must keep its virtual IP.
func natRule(subnet netip.Prefix, uplink string) []string {
	return []string{"-t", "nat", "%s", "POSTROUTING", "-s", subnet.String(), "-o", uplink, "-j", "MASQUERADE"}
}

func forwardRules(dev string) [][]string {
	return [][]string{
		{"%s", "FORWARD", "-i", dev, "-j", "ACCEPT"},
		{"%s", "FORWARD", "-o", dev, "-j", "ACCEPT"},
	}
}

func withOp(rule []string, op string) []string {
	out := slices.Clone(rule)
	for i, a := range out {
		if a == "%s" {
			out[i] = op
		}
	}
	return out
}

// ensureIptables inserts rule unless iptables -C finds it already there.
func ensureIptables(rule []string) error {
	if run("iptables", withOp(rule, "-C")...) == nil {
		return nil
	}
	return run("iptables", withOp(rule, "-I")...)
}

func deleteIptables(rule []string) error { return run("iptables", withOp(rule, "-D")...) }
