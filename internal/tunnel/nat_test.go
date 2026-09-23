package tunnel

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func skipIfIptablesUnavailable(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, exec.ErrNotFound) {
		t.Skipf("skipping: iptables not installed: %v", err)
	}
	msg := err.Error()
	if strings.Contains(msg, "Permission denied") ||
		strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "must be root") ||
		strings.Contains(msg, "Operation not permitted") {
		t.Skipf("skipping: insufficient privilege for iptables: %v", err)
	}
}

func TestEnableIPForwarding(t *testing.T) {
	original, err := IPForwardingEnabled()
	if err != nil {
		t.Skipf("cannot read %s: %v", ipForwardPath, err)
	}
	t.Cleanup(func() {
		val := []byte("0\n")
		if original {
			val = []byte("1\n")
		}
		_ = os.WriteFile(ipForwardPath, val, 0644)
	})

	if err := EnableIPForwarding(); err != nil {
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("skipping: %v (needs root)", err)
		}
		t.Fatalf("EnableIPForwarding: %v", err)
	}

	enabled, err := IPForwardingEnabled()
	if err != nil {
		t.Fatalf("IPForwardingEnabled: %v", err)
	}
	if !enabled {
		t.Error("expected IP forwarding to be enabled after EnableIPForwarding")
	}
}

func TestNAT_AddCheckRemove(t *testing.T) {
	rule := NATRule{Subnet: netip.MustParsePrefix("203.0.113.0/24")}

	if has, err := HasNAT(rule); err != nil {
		skipIfIptablesUnavailable(t, err)
		t.Fatalf("HasNAT (before): %v", err)
	} else if has {
		t.Fatal("test rule already present before AddNAT; a previous run may have leaked it")
	}

	if err := AddNAT(rule); err != nil {
		skipIfIptablesUnavailable(t, err)
		t.Fatalf("AddNAT: %v", err)
	}
	t.Cleanup(func() {
		_ = RemoveNAT(rule)
	})

	has, err := HasNAT(rule)
	if err != nil {
		t.Fatalf("HasNAT (after add): %v", err)
	}
	if !has {
		t.Fatal("expected rule to be present after AddNAT")
	}

	if err := RemoveNAT(rule); err != nil {
		t.Fatalf("RemoveNAT: %v", err)
	}

	has, err = HasNAT(rule)
	if err != nil {
		t.Fatalf("HasNAT (after remove): %v", err)
	}
	if has {
		t.Error("expected rule to be gone after RemoveNAT")
	}
}

func TestAddNAT_RemoveNAT(t *testing.T) {
	rule := NATRule{Subnet: netip.MustParsePrefix("203.0.113.192/26")}
	addErr := AddNAT(rule)
	removeErr := RemoveNAT(rule)

	if addErr != nil {
		skipIfIptablesUnavailable(t, addErr)
		t.Fatalf("AddNAT: %v", addErr)
	}
	if removeErr != nil {
		t.Fatalf("RemoveNAT: %v", removeErr)
	}
}

func TestHasNAT_AbsentByDefault(t *testing.T) {
	rule := NATRule{Subnet: netip.MustParsePrefix("203.0.113.128/25")}

	has, err := HasNAT(rule)
	if err != nil {
		skipIfIptablesUnavailable(t, err)
		t.Fatalf("HasNAT: %v", err)
	}
	if has {
		t.Error("expected no rule for a subnet this suite never added one for")
	}
}
