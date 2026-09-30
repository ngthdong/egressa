package encryption

import "testing"

func TestParseBackend(t *testing.T) {
	cases := map[string]Backend{
		"":             DefaultBackend,
		"wireguard":    BackendWireGuard,
		"WireGuard":    BackendWireGuard,
		" wg ":         BackendWireGuard,
		"wireguard-go": BackendWireGuard,
		"ipsec":        BackendIPsec,
		"IPSEC":        BackendIPsec,
		"strongswan":   BackendIPsec,
	}
	for in, want := range cases {
		got, err := ParseBackend(in)
		if err != nil {
			t.Errorf("ParseBackend(%q): unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseBackend(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseBackend_Unknown(t *testing.T) {
	if _, err := ParseBackend("openvpn"); err == nil {
		t.Fatal("ParseBackend(\"openvpn\"): expected an error, got nil")
	}
}

func TestDefaultBackendIsWireGuard(t *testing.T) {
	if DefaultBackend != BackendWireGuard {
		t.Fatalf("DefaultBackend = %q, want %q", DefaultBackend, BackendWireGuard)
	}
}

func TestBackends_ListsEveryBackendOnceAndParsesBack(t *testing.T) {
	seen := map[Backend]bool{}
	for _, b := range Backends() {
		if seen[b] {
			t.Fatalf("Backends() lists %q twice", b)
		}
		seen[b] = true
		parsed, err := ParseBackend(b.String())
		if err != nil || parsed != b {
			t.Fatalf("ParseBackend(%q) = (%q, %v), want (%q, nil)", b.String(), parsed, err, b)
		}
		_ = b.Capabilities() // must not panic for any listed backend
	}
	if len(seen) != 2 {
		t.Fatalf("Backends() = %v, want exactly wireguard and ipsec", Backends())
	}
}

// TestCapabilities_PinnedTable pins every field of both capability
// sets. A change here is a change to what higher layers may rely on,
// so it must be made deliberately, in this test, not as a side effect.
func TestCapabilities_PinnedTable(t *testing.T) {
	want := map[Backend]Capabilities{
		BackendWireGuard: {
			KernelDataPath:               false,
			InBandSessionHeader:          true,
			AuthenticatedSessionMetadata: false,
			PassiveLoss:                  true,
			PassiveJitter:                true,
			CrossPathDedup:               true,
			Fencing:                      FencingEpochHeader,
		},
		BackendIPsec: {
			KernelDataPath:               true,
			InBandSessionHeader:          false,
			AuthenticatedSessionMetadata: true,
			PassiveLoss:                  true,
			PassiveJitter:                false,
			CrossPathDedup:               false,
			Fencing:                      FencingSATeardown,
		},
	}
	for b, w := range want {
		if got := b.Capabilities(); got != w {
			t.Errorf("%s.Capabilities() = %+v, want %+v", b, got, w)
		}
	}
}

func TestCapabilities_KernelDataPathImpliesNoInBandHeader(t *testing.T) {
	for _, b := range Backends() {
		c := b.Capabilities()
		if c.KernelDataPath && (c.InBandSessionHeader || c.PassiveJitter || c.CrossPathDedup) {
			t.Errorf("%s: KernelDataPath=true but claims a per-packet user-space mechanism: %+v", b, c)
		}
	}
}

func TestCapabilities_UnknownBackendPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Capabilities of an unknown backend did not panic")
		}
	}()
	Backend("bogus").Capabilities()
}
