package tunnel

import (
	"net/netip"
	"testing"
)

func TestConfigureInterface_NoSuchDevice(t *testing.T) {
	err := ConfigureInterface("egressa-nonexistent-zzz", netip.MustParsePrefix("10.99.0.1/32"))
	if err == nil {
		t.Fatal("ConfigureInterface on a nonexistent device: expected error, got nil")
	}
}
