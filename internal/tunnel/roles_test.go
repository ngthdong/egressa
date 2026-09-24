package tunnel

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

// TestNewAccessGateway_NewEgressGateway covers the two constructors, which
// just store the pointer and don't touch it, so a nil *RealDevice is safe
// here (unlike calling any delegating method below, which would need a
// real, privileged one).
func TestNewAccessGateway_NewEgressGateway(t *testing.T) {
	if NewAccessGateway(nil) == nil {
		t.Error("NewAccessGateway(nil) returned nil")
	}
	if NewEgressGateway(nil) == nil {
		t.Error("NewEgressGateway(nil) returned nil")
	}
}

// TestEgressGateway_ConfigureNAT_NilDevice checks ConfigureNAT/
// RemoveNATConfig on an EgressGateway built with a nil *RealDevice: unlike
// every other EgressGateway/AccessGateway method, these two never touch
// the receiver's dev at all -- they delegate straight to the package-level
// AddNAT/RemoveNAT -- so this is safe and needs no CAP_NET_ADMIN-gated
// RealDevice, just (like nat_test.go's AddNAT/RemoveNAT tests) whatever
// privilege iptables itself needs.
func TestEgressGateway_ConfigureNAT_NilDevice(t *testing.T) {
	eg := NewEgressGateway(nil)
	subnet := netip.MustParsePrefix("203.0.113.240/28")

	addErr := eg.ConfigureNAT(subnet)
	removeErr := eg.RemoveNATConfig(subnet)

	if addErr != nil {
		skipIfIptablesUnavailable(t, addErr)
		t.Fatalf("ConfigureNAT: %v", addErr)
	}
	if removeErr != nil {
		t.Fatalf("RemoveNATConfig: %v", removeErr)
	}
}

func TestAccessGateway_NoNATMethod(t *testing.T) {
	typ := reflect.TypeOf(&AccessGateway{})
	for i := 0; i < typ.NumMethod(); i++ {
		name := typ.Method(i).Name
		if strings.Contains(strings.ToLower(name), "nat") {
			t.Errorf("AccessGateway has a NAT-related method: %s, access gateways must never be able to NAT", name)
		}
	}
}

func TestEgressGateway_HasNATMethod(t *testing.T) {
	typ := reflect.TypeOf(&EgressGateway{})
	found := false
	for i := 0; i < typ.NumMethod(); i++ {
		if strings.Contains(strings.ToLower(typ.Method(i).Name), "nat") {
			found = true
			break
		}
	}
	if !found {
		t.Error("EgressGateway has no NAT-related method, it should expose ConfigureNAT")
	}
}

func TestAccessGateway_DelegatesToRealDevice(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dev, err := NewReal(RealConfig{PrivateKey: kp.Private, InterfaceName: "egressa-t5a-a"})
	if err != nil {
		skipIfNoTUNPermission(t, err)
		t.Fatalf("NewReal: %v", err)
	}
	defer dev.Close()

	ag := NewAccessGateway(dev)
	if ag.Name() != dev.Name() {
		t.Errorf("AccessGateway.Name() = %q, want %q (RealDevice.Name())", ag.Name(), dev.Name())
	}

	port, err := ag.ListenPort()
	if err != nil {
		t.Fatalf("ListenPort: %v", err)
	}
	if port == 0 {
		t.Error("ListenPort() returned 0")
	}
}

func TestEgressGateway_ConfigureNAT(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dev, err := NewReal(RealConfig{PrivateKey: kp.Private, InterfaceName: "egressa-t5a-e"})
	if err != nil {
		skipIfNoTUNPermission(t, err)
		t.Fatalf("NewReal: %v", err)
	}
	defer dev.Close()

	eg := NewEgressGateway(dev)
	// RFC 5737 TEST-NET-3, same convention as nat_test.go: reserved for
	// documentation, never a real route.
	subnet := netip.MustParsePrefix("203.0.113.0/24")

	if err := eg.ConfigureNAT(subnet); err != nil {
		skipIfPrivilegedCommandFailed(t, "iptables", err)
		t.Fatalf("ConfigureNAT: %v", err)
	}
	t.Cleanup(func() {
		_ = eg.RemoveNATConfig(subnet)
	})

	has, err := HasNAT(NATRule{Subnet: subnet})
	if err != nil {
		t.Fatalf("HasNAT: %v", err)
	}
	if !has {
		t.Error("expected NAT rule to exist after ConfigureNAT")
	}
}
