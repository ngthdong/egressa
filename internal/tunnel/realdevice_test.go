package tunnel

import (
	"errors"
	"os"
	"testing"
)

// skipIfNoTUNPermission lets a test degrade to a skip, instead of a
// failure, in environments without CAP_NET_ADMIN (a plain developer
// machine, an unprivileged CI runner). Any other error is a real
// failure.
func skipIfNoTUNPermission(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, ErrPermissionDenied) {
		t.Skipf("skipping: %v (run as root / with CAP_NET_ADMIN to exercise this test)", err)
	}
}

func TestNewReal_ConstructConfigureClose(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	dev, err := NewReal(RealConfig{
		PrivateKey:    kp.Private,
		InterfaceName: "egressa-t4b",
	})
	if err != nil {
		skipIfNoTUNPermission(t, err)
		t.Fatalf("NewReal: %v", err)
	}

	name := dev.Name()
	if name == "" {
		dev.Close()
		t.Fatal("Name() returned empty string")
	}

	// Cross-check against the OS directly, the same way `ip link show`
	// would: while the device is alive, its interface must be a real,
	// visible network interface, not just something wireguard-go claims
	// internally.
	sysPath := "/sys/class/net/" + name
	if _, err := os.Stat(sysPath); err != nil {
		dev.Close()
		t.Fatalf("interface %q not visible at %s: %v", name, sysPath, err)
	}

	dev.Close()

	// A TUN device created without IFF_PERSIST disappears when its file
	// descriptor closes. If it is still there, Close did not actually
	// release the OS-level interface.
	if _, err := os.Stat(sysPath); err == nil {
		t.Errorf("interface %q still visible at %s after Close", name, sysPath)
	} else if !os.IsNotExist(err) {
		t.Errorf("unexpected error checking %s after Close: %v", sysPath, err)
	}
}

func TestNewReal_MultipleInstances(t *testing.T) {
	names := []string{"egressa-t4b-a", "egressa-t4b-b", "egressa-t4b-c"}
	for i, name := range names {
		kp, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("GenerateKeyPair (iteration %d): %v", i, err)
		}

		dev, err := NewReal(RealConfig{
			PrivateKey:    kp.Private,
			InterfaceName: name,
		})
		if err != nil {
			skipIfNoTUNPermission(t, err)
			t.Fatalf("NewReal (iteration %d, %q): %v", i, name, err)
		}
		dev.Close()
	}
}

// TestNewReal_MTU checks that wireguard-go's own TUN layer reports back
// the MTU we requested. It deliberately does NOT check
// /sys/class/net/.../mtu (the kernel-visible interface MTU): whether
// CreateTUN pushes the requested MTU down to the kernel via an ioctl, or
// only tracks it internally, is not something this project has
// independently confirmed. Asserting a specific kernel-level value here
// would be a guess, not a verified fact.
func TestNewReal_MTU(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	dev, err := NewReal(RealConfig{
		PrivateKey:    kp.Private,
		InterfaceName: "egressa-t4b-mtu",
	})
	if err != nil {
		skipIfNoTUNPermission(t, err)
		t.Fatalf("NewReal with MTU=0: %v", err)
	}
	defer dev.Close()

	got, err := dev.MTU()
	if err != nil {
		t.Fatalf("MTU: %v", err)
	}
	if got != DefaultMTU {
		t.Errorf("MTU() = %d, want %d (DefaultMTU)", got, DefaultMTU)
	}
}
