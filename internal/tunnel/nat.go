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
	out, err := exec.Command("iptables", rule.args("-C")...).CombinedOutput()
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
