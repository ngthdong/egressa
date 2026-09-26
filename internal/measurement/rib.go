package measurement

import (
	"fmt"
	"net/netip"
)

type ribNode struct {
	children [2]*ribNode
	prefix   netip.Prefix
	set      bool
}

// RIB stores IP prefixes in a binary trie and supports longest-prefix-match
// lookups.
//
// The trie has separate roots for IPv4 and IPv6. Each level represents one
// address bit, and a node with set=true represents an installed prefix.
//
// A RIB is intended to be built first and then queried concurrently.
// It is safe for concurrent Lookup calls after construction is complete,
// but AddPrefix and LoadPrefixes must not run concurrently with lookups or
// with other mutations.
type RIB struct {
	v4 *ribNode
	v6 *ribNode
}

func NewRIB() *RIB {
	return &RIB{v4: &ribNode{}, v6: &ribNode{}}
}

func isTrueIPv6(addr netip.Addr) bool {
	return addr.Is6() && !addr.Is4In6()
}

func addrBits(addr netip.Addr) []byte {
	if isTrueIPv6(addr) {
		a := addr.As16()
		return a[:]
	}
	a := addr.As4()
	return a[:]
}

func bitAt(b []byte, i int) int {
	return int((b[i/8] >> (7 - uint(i%8))) & 1)
}

// AddPrefix adds one announced prefix to the RIB. Adding the same prefix
// twice is idempotent.
func (r *RIB) AddPrefix(p netip.Prefix) error {
	if !p.IsValid() {
		return fmt.Errorf("measurement: invalid prefix %v", p)
	}
	p = p.Masked()

	node := r.v4
	if isTrueIPv6(p.Addr()) {
		node = r.v6
	}
	bits := addrBits(p.Addr())
	for i := 0; i < p.Bits(); i++ {
		bit := bitAt(bits, i)
		if node.children[bit] == nil {
			node.children[bit] = &ribNode{}
		}
		node = node.children[bit]
	}
	node.set = true
	node.prefix = p
	return nil
}

func (r *RIB) LoadPrefixes(prefixes []netip.Prefix) error {
	for _, p := range prefixes {
		if err := r.AddPrefix(p); err != nil {
			return err
		}
	}
	return nil
}

// Lookup returns the most specific prefix containing addr.
// The lookup walks the address from the most significant bit and remembers
// the deepest matching prefix seen so far.
func (r *RIB) Lookup(addr netip.Addr) (netip.Prefix, bool) {
	node := r.v4
	width := 32
	if isTrueIPv6(addr) {
		node = r.v6
		width = 128
	}
	bits := addrBits(addr)

	var best netip.Prefix
	var ok bool
	for i := 0; i < width; i++ {
		if node.set {
			best, ok = node.prefix, true
		}
		bit := bitAt(bits, i)
		if node.children[bit] == nil {
			return best, ok
		}
		node = node.children[bit]
	}
	if node.set {
		best, ok = node.prefix, true
	}
	return best, ok
}
