package ipsec

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
)

// routeSet tracks the tunnel routes one Client or Gateway installed, so it
// can move them between XFRM interfaces and withdraw exactly those, never
// anything it did not create. It is not safe for concurrent use.
type routeSet struct {
	net       Net
	installed map[netip.Prefix]Route
}

func newRouteSet(n Net) *routeSet {
	return &routeSet{net: n, installed: map[netip.Prefix]Route{}}
}

// apply makes want the complete set of installed routes. Each wanted
// route is replaced in place, so traffic for a prefix moves from the old
// interface to the new one without a gap. If any replace fails, every
// prefix already changed is put back the way it was (the previous route,
// or no route) and apply returns the error with nothing changed. Only
// once all of want is in place are installed prefixes missing from want
// withdrawn.
func (s *routeSet) apply(want []Route) error {
	type change struct {
		r       Route
		prev    Route
		hadPrev bool
	}
	var done []change
	for _, r := range want {
		prev, had := s.installed[r.Dst]
		if err := s.net.RouteReplace(r); err != nil {
			var undo []error
			for i := len(done) - 1; i >= 0; i-- {
				c := done[i]
				if c.hadPrev {
					undo = append(undo, s.net.RouteReplace(c.prev))
				} else {
					undo = append(undo, ignoreNotExist(s.net.RouteDel(c.r)))
				}
			}
			if uerr := errors.Join(undo...); uerr != nil {
				return fmt.Errorf("%w (and undoing the partial change failed: %v)", err, uerr)
			}
			return err
		}
		done = append(done, change{r: r, prev: prev, hadPrev: had})
	}

	keep := make(map[netip.Prefix]Route, len(want))
	for _, r := range want {
		keep[r.Dst] = r
	}
	var errs []error
	for dst, r := range s.installed {
		if _, ok := keep[dst]; ok {
			continue
		}
		if err := ignoreNotExist(s.net.RouteDel(r)); err != nil {
			// Still ours and still there: keep tracking it so a later
			// apply or clear retries the withdrawal.
			keep[dst] = r
			errs = append(errs, err)
		}
	}
	s.installed = keep
	return errors.Join(errs...)
}

// clear withdraws every installed route.
func (s *routeSet) clear() error {
	return s.apply(nil)
}

// routes returns the installed routes, sorted by destination.
func (s *routeSet) routes() []Route {
	out := make([]Route, 0, len(s.installed))
	for _, r := range s.installed {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Route) int {
		if c := a.Dst.Addr().Compare(b.Dst.Addr()); c != 0 {
			return c
		}
		return a.Dst.Bits() - b.Dst.Bits()
	})
	return out
}

// fullTunnelPrefixes are the two halves of the address space that carry
// all traffic through a tunnel while staying more specific than the
// host's default route, which is never touched.
func fullTunnelPrefixes(f Family) []netip.Prefix {
	if f == FamilyV6 {
		return []netip.Prefix{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")}
	}
	return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
}

// allAddresses is the traffic selector covering every address of f.
func allAddresses(f Family) netip.Prefix {
	if f == FamilyV6 {
		return netip.MustParsePrefix("::/0")
	}
	return netip.MustParsePrefix("0.0.0.0/0")
}

func hostPrefix(a netip.Addr) netip.Prefix {
	return netip.PrefixFrom(a, a.BitLen())
}

// ifaceName names the XFRM interface for ifID: "<prefix><if_id>", which
// fits IFNAMSIZ for any prefix of up to 5 characters.
func ifaceName(prefix string, ifID uint32) string {
	return prefix + strconv.FormatUint(uint64(ifID), 10)
}

func ignoreNotExist(err error) error {
	if errors.Is(err, ErrNotExist) {
		return nil
	}
	return err
}

func ignoreNotFound(err error) error {
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// checkAddr rejects an invalid or zoned (scoped) address.
func checkAddr(what string, a netip.Addr) error {
	if !a.IsValid() {
		return fmt.Errorf("ipsec: %s: missing or invalid address", what)
	}
	if a.Zone() != "" {
		return fmt.Errorf("ipsec: %s %s: scoped (zoned) addresses are not supported", what, a)
	}
	return nil
}

// checkSameFamily rejects b when a is set and b is of the other family.
func checkSameFamily(what string, a, b netip.Addr) error {
	if a.IsValid() && b.IsValid() && a.Is4() != b.Is4() {
		return fmt.Errorf("ipsec: %s %s is not the same address family as %s", what, b, a)
	}
	return nil
}

// checkPrefixes rejects invalid prefixes and prefixes of a family other
// than f. (A netip.Prefix never carries a zone: PrefixFrom drops it.)
func checkPrefixes(what string, f Family, ps []netip.Prefix) error {
	for _, p := range ps {
		if !p.IsValid() {
			return fmt.Errorf("ipsec: %s: invalid prefix %v", what, p)
		}
		if familyOf(p.Addr()) != f {
			return fmt.Errorf("ipsec: %s %s is not an IPv%d prefix", what, p, f)
		}
	}
	return nil
}
