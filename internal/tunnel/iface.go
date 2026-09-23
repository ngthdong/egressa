package tunnel

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// ConfigureInterface assigns addr to the interface and brings it up.
// Requires CAP_NET_ADMIN.
func ConfigureInterface(name string, addr netip.Prefix) error {
	if err := runIP("addr", "add", addr.String(), "dev", name); err != nil {
		return fmt.Errorf("tunnel: assign address to %s: %w", name, err)
	}
	if err := runIP("link", "set", name, "up"); err != nil {
		return fmt.Errorf("tunnel: bring %s up: %w", name, err)
	}
	return nil
}

func runIP(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w (output: %s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
