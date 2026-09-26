package measurement

import (
	"net/netip"
	"sync"
	"testing"
)

func TestRIB_LookupExactMatch(t *testing.T) {
	r := NewRIB()
	if err := r.AddPrefix(mustPrefix(t, "10.0.0.0/8")); err != nil {
		t.Fatal(err)
	}

	got, ok := r.Lookup(netip.MustParseAddr("10.1.2.3"))
	if !ok {
		t.Fatal("Lookup: expected a match")
	}
	if got != mustPrefix(t, "10.0.0.0/8") {
		t.Fatalf("Lookup = %s, want 10.0.0.0/8", got)
	}
}

func TestRIB_LookupLongestPrefixWins(t *testing.T) {
	r := NewRIB()
	if err := r.AddPrefix(mustPrefix(t, "10.0.0.0/8")); err != nil {
		t.Fatal(err)
	}
	if err := r.AddPrefix(mustPrefix(t, "10.1.0.0/16")); err != nil {
		t.Fatal(err)
	}

	got, ok := r.Lookup(netip.MustParseAddr("10.1.2.3"))
	if !ok {
		t.Fatal("Lookup: expected a match")
	}
	if got != mustPrefix(t, "10.1.0.0/16") {
		t.Fatalf("Lookup = %s, want the more specific 10.1.0.0/16, not the /8", got)
	}

	// An address in the /8 but outside the /16 must still fall back to
	// the /8.
	got2, ok2 := r.Lookup(netip.MustParseAddr("10.2.0.5"))
	if !ok2 || got2 != mustPrefix(t, "10.0.0.0/8") {
		t.Fatalf("Lookup(10.2.0.5) = %s, ok=%v; want 10.0.0.0/8, true", got2, ok2)
	}
}

func TestRIB_LookupNoMatch_EmptyRIB(t *testing.T) {
	r := NewRIB()
	if _, ok := r.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Fatal("Lookup on an empty RIB returned ok=true")
	}
}

func TestRIB_LookupOutsideAnyPrefix(t *testing.T) {
	r := NewRIB()
	if err := r.AddPrefix(mustPrefix(t, "10.0.0.0/8")); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Lookup(netip.MustParseAddr("192.168.1.1")); ok {
		t.Fatal("Lookup for an address outside every loaded prefix returned ok=true")
	}
}

func TestRIB_DefaultRouteMatchesEverythingButLosesToMoreSpecific(t *testing.T) {
	r := NewRIB()
	if err := r.AddPrefix(mustPrefix(t, "0.0.0.0/0")); err != nil {
		t.Fatal(err)
	}
	if err := r.AddPrefix(mustPrefix(t, "203.0.113.0/24")); err != nil {
		t.Fatal(err)
	}

	got, ok := r.Lookup(netip.MustParseAddr("1.2.3.4"))
	if !ok || got != mustPrefix(t, "0.0.0.0/0") {
		t.Fatalf("Lookup(1.2.3.4) = %s, ok=%v; want the default route", got, ok)
	}

	got2, ok2 := r.Lookup(netip.MustParseAddr("203.0.113.7"))
	if !ok2 || got2 != mustPrefix(t, "203.0.113.0/24") {
		t.Fatalf("Lookup(203.0.113.7) = %s, ok=%v; want the more specific /24, not the default route", got2, ok2)
	}
}

func TestRIB_IPv6(t *testing.T) {
	r := NewRIB()
	if err := r.AddPrefix(mustPrefix(t, "2001:db8::/32")); err != nil {
		t.Fatal(err)
	}

	got, ok := r.Lookup(netip.MustParseAddr("2001:db8:1:2::1"))
	if !ok || got != mustPrefix(t, "2001:db8::/32") {
		t.Fatalf("Lookup = %s, ok=%v; want 2001:db8::/32", got, ok)
	}

	if _, ok := r.Lookup(netip.MustParseAddr("2001:db9::1")); ok {
		t.Fatal("Lookup outside the loaded IPv6 prefix returned ok=true")
	}
}

func TestRIB_AddPrefix_InvalidPrefix(t *testing.T) {
	r := NewRIB()
	if err := r.AddPrefix(netip.Prefix{}); err == nil {
		t.Fatal("AddPrefix(zero Prefix): expected an error")
	}
}

func TestRIB_AddPrefix_Idempotent(t *testing.T) {
	r := NewRIB()
	for i := 0; i < 2; i++ {
		if err := r.AddPrefix(mustPrefix(t, "192.0.2.0/24")); err != nil {
			t.Fatalf("AddPrefix (call %d): %v", i, err)
		}
	}
	got, ok := r.Lookup(netip.MustParseAddr("192.0.2.5"))
	if !ok || got != mustPrefix(t, "192.0.2.0/24") {
		t.Fatalf("Lookup after duplicate AddPrefix = %s, ok=%v; want 192.0.2.0/24, true", got, ok)
	}
}

func TestRIB_LoadPrefixes(t *testing.T) {
	r := NewRIB()
	prefixes := []netip.Prefix{
		mustPrefix(t, "10.0.0.0/8"),
		mustPrefix(t, "172.16.0.0/12"),
		mustPrefix(t, "192.168.0.0/16"),
	}
	if err := r.LoadPrefixes(prefixes); err != nil {
		t.Fatalf("LoadPrefixes: %v", err)
	}
	for _, addr := range []string{"10.5.5.5", "172.16.1.1", "192.168.100.1"} {
		if _, ok := r.Lookup(netip.MustParseAddr(addr)); !ok {
			t.Fatalf("Lookup(%s) after LoadPrefixes: expected a match", addr)
		}
	}
}

func TestRIB_LoadPrefixes_StopsAtFirstError(t *testing.T) {
	r := NewRIB()
	prefixes := []netip.Prefix{
		mustPrefix(t, "10.0.0.0/8"),
		{}, // invalid
		mustPrefix(t, "192.168.0.0/16"),
	}
	err := r.LoadPrefixes(prefixes)
	if err == nil {
		t.Fatal("LoadPrefixes: expected an error from the invalid entry")
	}
	// The prefix before the failing one must still have been loaded.
	if _, ok := r.Lookup(netip.MustParseAddr("10.1.1.1")); !ok {
		t.Fatal("prefix loaded before the failing entry should still be queryable")
	}
}

func TestRIB_HostRoute(t *testing.T) {
	r := NewRIB()
	if err := r.AddPrefix(mustPrefix(t, "203.0.113.42/32")); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Lookup(netip.MustParseAddr("203.0.113.42")); !ok {
		t.Fatal("Lookup on the exact host route: expected a match")
	}
	if _, ok := r.Lookup(netip.MustParseAddr("203.0.113.43")); ok {
		t.Fatal("Lookup one address away from a /32 host route: expected no match")
	}
}

func TestRIB_ConcurrentLookup_NoRace(t *testing.T) {
	r := NewRIB()
	if err := r.LoadPrefixes([]netip.Prefix{
		mustPrefix(t, "10.0.0.0/8"),
		mustPrefix(t, "10.1.0.0/16"),
		mustPrefix(t, "2001:db8::/32"),
	}); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	const goroutines = 20
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			r.Lookup(netip.MustParseAddr("10.1.2.3"))
			r.Lookup(netip.MustParseAddr("8.8.8.8"))
			r.Lookup(netip.MustParseAddr("2001:db8:1::1"))
		}()
	}
	wg.Wait()
}
