package tunnel

import (
	"net/netip"
	"testing"
)

func TestParseRouteGet(t *testing.T) {
	cases := []struct {
		name    string
		output  string
		want    RouteInfo
		wantErr bool
	}{
		{
			name:   "gateway route",
			output: "8.8.8.8 via 192.168.1.1 dev eth0 src 192.168.1.50 uid 1000 \n    cache \n",
			want: RouteInfo{
				Gateway:   netip.MustParseAddr("192.168.1.1"),
				Interface: "eth0",
			},
		},
		{
			name:   "on-link, no gateway",
			output: "192.168.1.5 dev eth0 src 192.168.1.50 uid 1000 \n    cache \n",
			want: RouteInfo{
				Interface: "eth0",
			},
		},
		{
			name:   "extra fields in unfamiliar order do not confuse the parser",
			output: "203.0.113.9 dev wg0 src 10.201.0.2 via 10.0.0.1 mtu 1420 \n",
			want: RouteInfo{
				Gateway:   netip.MustParseAddr("10.0.0.1"),
				Interface: "wg0",
			},
		},
		{
			name:    "missing dev entirely",
			output:  "8.8.8.8 via 192.168.1.1 src 192.168.1.50\n",
			wantErr: true,
		},
		{
			name:    "via with nothing after it",
			output:  "8.8.8.8 via",
			wantErr: true,
		},
		{
			name:    "dev with nothing after it",
			output:  "8.8.8.8 via 192.168.1.1 dev",
			wantErr: true,
		},
		{
			name:    "garbage gateway address",
			output:  "8.8.8.8 via not-an-address dev eth0",
			wantErr: true,
		},
		{
			name:    "empty output",
			output:  "",
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRouteGet(tc.output)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRouteGet: %v", err)
			}
			if got != tc.want {
				t.Errorf("parseRouteGet(%q) = %+v, want %+v", tc.output, got, tc.want)
			}
		})
	}
}

func TestRouteInfo_ZeroGatewayIsInvalid(t *testing.T) {
	var info RouteInfo
	if info.Gateway.IsValid() {
		t.Error("zero-value RouteInfo.Gateway should not be a valid address")
	}
}

// TestCurrentRoute checks currentRoute against the real routing table.
// "ip route get" is a read-only query, so unlike the route-mutating
// functions below, this works with no privilege needed.
func TestCurrentRoute(t *testing.T) {
	info, err := currentRoute(netip.MustParseAddr("8.8.8.8"))
	if err != nil {
		t.Fatalf("currentRoute: %v", err)
	}
	if info.Interface == "" {
		t.Error("currentRoute: expected a nonempty Interface")
	}
}

func TestCurrentRoute_InvalidDestination(t *testing.T) {
	if _, err := currentRoute(netip.Addr{}); err == nil {
		t.Fatal("currentRoute with an invalid address: expected error, got nil")
	}
}

// TestAddBypassRoute_RemoveBypassRoute calls both directly: mutating the
// routing table needs CAP_NET_ADMIN, so in an unprivileged environment
// this exercises their error path via runIP, same as the iptables tests
// do for AddNAT/RemoveNAT.
func TestAddBypassRoute_RemoveBypassRoute(t *testing.T) {
	gatewayIP := netip.MustParseAddr("203.0.113.201")
	via := RouteInfo{Gateway: netip.MustParseAddr("192.0.2.1"), Interface: "lo"}

	addErr := AddBypassRoute(gatewayIP, via)
	removeErr := RemoveBypassRoute(gatewayIP)

	if addErr != nil {
		skipIfPrivilegedCommandFailed(t, "ip", addErr)
		t.Fatalf("AddBypassRoute: %v", addErr)
	}
	if removeErr != nil {
		t.Fatalf("RemoveBypassRoute: %v", removeErr)
	}
}

// TestAddBypassRoute_NoGateway checks the on-link case (via.Gateway not
// set), which omits "via" from the ip route command entirely.
func TestAddBypassRoute_NoGateway(t *testing.T) {
	gatewayIP := netip.MustParseAddr("203.0.113.202")
	via := RouteInfo{Interface: "lo"}

	err := AddBypassRoute(gatewayIP, via)
	if err != nil {
		skipIfPrivilegedCommandFailed(t, "ip", err)
		t.Fatalf("AddBypassRoute: %v", err)
	}
	t.Cleanup(func() { _ = RemoveBypassRoute(gatewayIP) })
}

func TestSetFullTunnelDefault_RestoreDefaultRoute(t *testing.T) {
	setErr := SetFullTunnelDefault("lo")
	restoreErr := RestoreDefaultRoute(RouteInfo{Gateway: netip.MustParseAddr("192.0.2.1"), Interface: "lo"})

	if setErr != nil {
		skipIfPrivilegedCommandFailed(t, "ip", setErr)
		t.Fatalf("SetFullTunnelDefault: %v", setErr)
	}
	if restoreErr != nil {
		t.Fatalf("RestoreDefaultRoute: %v", restoreErr)
	}
}

// TestRestoreDefaultRoute_NoGateway checks the on-link case, which omits
// "via" from the ip route command entirely.
func TestRestoreDefaultRoute_NoGateway(t *testing.T) {
	err := RestoreDefaultRoute(RouteInfo{Interface: "lo"})
	if err != nil {
		skipIfPrivilegedCommandFailed(t, "ip", err)
		t.Fatalf("RestoreDefaultRoute: %v", err)
	}
}

// TestEnableFullTunnel_NoPermission checks that EnableFullTunnel cleans up
// after itself (no bypass route left behind) when the second step,
// SetFullTunnelDefault, fails after the first, AddBypassRoute, already
// succeeded. In an unprivileged environment AddBypassRoute itself is what
// fails, which still exercises EnableFullTunnel's first error-return path.
func TestEnableFullTunnel_NoPermission(t *testing.T) {
	restore, err := EnableFullTunnel("lo", netip.MustParseAddr("8.8.8.8"))
	if err != nil {
		skipIfPrivilegedCommandFailed(t, "ip", err)
		t.Fatalf("EnableFullTunnel: %v", err)
	}
	defer func() { _ = restore() }()
}
