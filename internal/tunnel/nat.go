package tunnel

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

const ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

// EnableIPForwarding turns on kernel IPv4 forwarding
// (net.ipv4.ip_forward). Without it, the kernel never routes packets
// between interfaces at all.
func EnableIPForwarding() error {
	if err := os.WriteFile(ipForwardPath, []byte("1\n"), 0644); err != nil {
		return fmt.Errorf("tunnel: enable IP forwarding: %w", err)
	}

	enabled, err := IPForwardingEnabled()
	if err != nil {
		return fmt.Errorf("tunnel: verify IP forwarding: %w", err)
	}
	if !enabled {
		return fmt.Errorf("tunnel: IP forwarding not enabled after write to %s", ipForwardPath)
	}
	return nil
}

func IPForwardingEnabled() (bool, error) {
	got, err := os.ReadFile(ipForwardPath)
	if err != nil {
		return false, fmt.Errorf("tunnel: read IP forwarding state: %w", err)
	}
	return len(got) > 0 && got[0] == '1', nil
}

// NATRule is a MASQUERADE rule matching outbound traffic whose source is
// within Subnet.
type NATRule struct {
	Subnet netip.Prefix
}

func (r NATRule) args(command string) []string {
	return []string{"-t", "nat", command, "POSTROUTING", "-s", r.Subnet.String(), "-j", "MASQUERADE"}
}

func AddNAT(rule NATRule) error {
	return runIptables(rule.args("-A"))
}

func RemoveNAT(rule NATRule) error {
	return runIptables(rule.args("-D"))
}

func HasNAT(rule NATRule) (bool, error) {
	return ruleExists(rule.args("-C"))
}

// ForwardRule allows traffic to and from Interface through the kernel's
// FORWARD chain.
//
// This is needed in addition to EnableIPForwarding and NATRule:
// net.ipv4.ip_forward only lets the kernel consider forwarding a packet at
// all, and a NATRule only rewrites the source address on the way out —
// neither overrides the FORWARD chain's own policy. Many hosts default
// that policy to DROP independent of ip_forward (notably anything with
// Docker installed, which does this for container isolation), so
// ip_forward+NAT alone silently produces "no connectivity, no error"
// instead of a working gateway, unless something explicitly ACCEPTs the
// tunnel's traffic here.
type ForwardRule struct {
	Interface string
}

func (r ForwardRule) inArgs(command string) []string {
	return []string{command, "FORWARD", "-i", r.Interface, "-j", "ACCEPT"}
}

func (r ForwardRule) outArgs(command string) []string {
	return []string{command, "FORWARD", "-o", r.Interface, "-j", "ACCEPT"}
}

func AddForward(rule ForwardRule) error {
	if err := runIptables(rule.inArgs("-A")); err != nil {
		return err
	}
	if err := runIptables(rule.outArgs("-A")); err != nil {
		return err
	}
	return nil
}

// RemoveForward removes both directions of rule, attempting each
// regardless of whether the other fails, and joins any errors together.
func RemoveForward(rule ForwardRule) error {
	errIn := runIptables(rule.inArgs("-D"))
	errOut := runIptables(rule.outArgs("-D"))
	return errors.Join(errIn, errOut)
}

// HasForward reports whether both directions of rule are present.
func HasForward(rule ForwardRule) (bool, error) {
	in, err := ruleExists(rule.inArgs("-C"))
	if err != nil {
		return false, err
	}
	out, err := ruleExists(rule.outArgs("-C"))
	if err != nil {
		return false, err
	}
	return in && out, nil
}

// ruleExists runs an "iptables -C ..." check and reports whether the rule
// is present: exit code 1 means "no such rule" (not an error), any other
// nonzero exit is a real failure (e.g. insufficient privilege).
func ruleExists(checkArgs []string) (bool, error) {
	out, err := exec.Command("iptables", checkArgs...).CombinedOutput()
	if err == nil {
		return true, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return false, nil
	}
	return false, fmt.Errorf("tunnel: iptables -C: %w (output: %s)", err, strings.TrimSpace(string(out)))
}

func runIptables(args []string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("tunnel: iptables %s: %w (output: %s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
