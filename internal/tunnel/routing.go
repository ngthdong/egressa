package tunnel

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

type RouteInfo struct {
	Gateway   netip.Addr
	Interface string
}

func currentRoute(dst netip.Addr) (RouteInfo, error) {
	out, err := exec.Command("ip", "route", "get", dst.String()).Output()
	if err != nil {
		return RouteInfo{}, fmt.Errorf("tunnel: ip route get %s: %w", dst, err)
	}
	return parseRouteGet(string(out))
}

func parseRouteGet(output string) (RouteInfo, error) {
	fields := strings.Fields(output)
	var info RouteInfo
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "via":
			if i+1 >= len(fields) {
				return RouteInfo{}, fmt.Errorf("tunnel: parse route output: %q ends right after \"via\"", output)
			}
			addr, err := netip.ParseAddr(fields[i+1])
			if err != nil {
				return RouteInfo{}, fmt.Errorf("tunnel: parse gateway %q: %w", fields[i+1], err)
			}
			info.Gateway = addr
		case "dev":
			if i+1 >= len(fields) {
				return RouteInfo{}, fmt.Errorf("tunnel: parse route output: %q ends right after \"dev\"", output)
			}
			info.Interface = fields[i+1]
		}
	}
	if info.Interface == "" {
		return RouteInfo{}, fmt.Errorf("tunnel: no interface found in route output: %q", output)
	}
	return info, nil
}

func AddBypassRoute(gatewayIP netip.Addr, via RouteInfo) error {
	args := []string{"route", "add", gatewayIP.String() + "/32"}
	if via.Gateway.IsValid() {
		args = append(args, "via", via.Gateway.String())
	}
	args = append(args, "dev", via.Interface)
	return runIP(args...)
}

func RemoveBypassRoute(gatewayIP netip.Addr) error {
	return runIP("route", "del", gatewayIP.String()+"/32")
}

func SetFullTunnelDefault(tunInterface string) error {
	return runIP("route", "replace", "default", "dev", tunInterface)
}

func RestoreDefaultRoute(original RouteInfo) error {
	args := []string{"route", "replace", "default"}
	if original.Gateway.IsValid() {
		args = append(args, "via", original.Gateway.String())
	}
	args = append(args, "dev", original.Interface)
	return runIP(args...)
}

func EnableFullTunnel(tunInterface string, gatewayEndpoint netip.Addr) (restore func() error, err error) {
	original, err := currentRoute(gatewayEndpoint)
	if err != nil {
		return nil, fmt.Errorf("tunnel: determine current route to gateway: %w", err)
	}

	if err := AddBypassRoute(gatewayEndpoint, original); err != nil {
		return nil, fmt.Errorf("tunnel: add bypass route: %w", err)
	}

	if err := SetFullTunnelDefault(tunInterface); err != nil {
		_ = RemoveBypassRoute(gatewayEndpoint)
		return nil, fmt.Errorf("tunnel: set full-tunnel default route: %w", err)
	}

	restore = func() error {
		err1 := RestoreDefaultRoute(original)
		err2 := RemoveBypassRoute(gatewayEndpoint)
		return errors.Join(err1, err2)
	}
	return restore, nil
}
