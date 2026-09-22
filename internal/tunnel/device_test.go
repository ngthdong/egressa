package tunnel

import (
	"net/netip"
	"strings"
	"testing"
)

func testAddr(t *testing.T) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr("10.99.0.1")
	if err != nil {
		t.Fatalf("ParseAddr: %v", err)
	}
	return addr
}

func TestNew_ConstructConfigureClose(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	dev, err := New(Config{
		PrivateKey: kp.Private,
		Addresses:  []netip.Addr{testAddr(t)},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer dev.Close()

	got, err := dev.uapiConfig()
	if err != nil {
		t.Fatalf("uapiConfig: %v", err)
	}
	wantLine := "private_key=" + Hex(kp.Private)
	if !strings.Contains(got, wantLine) {
		t.Errorf("device config missing %q; got:\n%s", wantLine, got)
	}
}

// TestNew_MultipleInstances checks that constructing and closing several
// devices in sequence works cleanly, with no leaked state between them.
func TestNew_MultipleInstances(t *testing.T) {
	for i := 0; i < 3; i++ {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}

		dev, err := New(Config{
			PrivateKey: kp.Private,
			Addresses:  []netip.Addr{testAddr(t)},
		})
		if err != nil {
			t.Fatalf("New (iteration %d): %v", i, err)
		}
		dev.Close()
	}
}

func TestNew_DefaultMTU(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	dev, err := New(Config{
		PrivateKey: kp.Private,
		Addresses:  []netip.Addr{testAddr(t)},
	})
	if err != nil {
		t.Fatalf("New with MTU=0: %v", err)
	}
	dev.Close()
}

func TestNew_NetAccessor(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	dev, err := New(Config{
		PrivateKey: kp.Private,
		Addresses:  []netip.Addr{testAddr(t)},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer dev.Close()

	if dev.Net() == nil {
		t.Error("Net() returned nil")
	}
}

// TestNew_ListenPortInUse checks that New surfaces a bind error when the
// requested port is already held by another device, rather than silently
// picking a different one.
func TestNew_ListenPortInUse(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	first, err := New(Config{
		PrivateKey: kp.Private,
		ListenPort: 51901,
		Addresses:  []netip.Addr{testAddr(t)},
	})
	if err != nil {
		t.Fatalf("New (first): %v", err)
	}
	defer first.Close()

	_, err = New(Config{
		PrivateKey: kp.Private,
		ListenPort: 51901,
		Addresses:  []netip.Addr{testAddr(t)},
	})
	if err == nil {
		t.Fatal("New with an already-bound port: expected error, got nil")
	}
}

func TestNew_ExplicitListenPort(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	dev, err := New(Config{
		PrivateKey: kp.Private,
		ListenPort: 51900,
		Addresses:  []netip.Addr{testAddr(t)},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer dev.Close()

	got, err := dev.uapiConfig()
	if err != nil {
		t.Fatalf("uapiConfig: %v", err)
	}
	if !strings.Contains(got, "listen_port=51900") {
		t.Errorf("device config missing listen_port=51900; got:\n%s", got)
	}
}
