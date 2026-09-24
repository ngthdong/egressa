package tunnel

import (
	"errors"
	"os"
	"testing"
)

func skipIfNoTUNPermission(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, ErrPermissionDenied) {
		t.Skipf("skipping: %v (run as root / with CAP_NET_ADMIN to exercise this test)", err)
	}
}

func TestClassifyTUNError(t *testing.T) {
	cases := []struct {
		name           string
		err            error
		wantPermission bool
	}{
		{"os.ErrPermission", os.ErrPermission, true},
		{"message: operation not permitted", errors.New("operation not permitted"), true},
		{"message: permission denied", errors.New("permission denied"), true},
		{"generic error", errors.New("no such device"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyTUNError("egressa-t0", tc.err)
			if got == nil {
				t.Fatal("classifyTUNError returned nil")
			}
			if isPermission := errors.Is(got, ErrPermissionDenied); isPermission != tc.wantPermission {
				t.Errorf("classifyTUNError(%v): errors.Is(_, ErrPermissionDenied) = %v, want %v", tc.err, isPermission, tc.wantPermission)
			}
		})
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
