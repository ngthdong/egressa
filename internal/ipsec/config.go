package ipsec

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type AuthMethod string

const (
	AuthPSK    AuthMethod = "psk"
	AuthPubkey AuthMethod = "pubkey"
)

type StartAction string

const (
	StartNone  StartAction = "none"
	StartStart StartAction = "start"
)

var (
	DefaultIKEProposals = []string{"aes256gcm16-prfsha256-x25519"}
	DefaultESPProposals = []string{"aes256gcm16-x25519"}
)

// AnyID as a RemoteID accepts any peer identity: a gateway's single
// responder connection uses it for all of its clients.
const AnyID = "%any"

// Connection describes one IKEv2 connection to a peer and its CHILD_SA.
type Connection struct {
	// Name identifies the IKE connection. The CHILD_SA name is derived
	// from Name and Epoch.
	Name string

	// Epoch identifies the Egressa ownership generation under which
	// this CHILD_SA is established. It is used for stale-SA fencing.
	Epoch uint64

	LocalAddr    netip.Addr
	RemoteAddr   netip.Addr
	LocalID      string
	RemoteID     string
	Auth         AuthMethod // Auth selects the IKE authentication method.
	PSK          string     // PSK is the pre-shared secret used when Auth is AuthPSK.
	LocalPubkey  string
	RemotePubkey string
	LocalTS      []netip.Prefix // The local inner traffic selectors for the CHILD_SA.
	RemoteTS     []netip.Prefix // the remote inner traffic selectors for the CHILD_SA.

	// IfID identifies the XFRM interface bound to this CHILD_SA.
	// Each peer must use a unique IfID for route-based IPsec.
	IfID uint32

	IKEProposals []string // nil means DefaultIKEProposals
	ESPProposals []string // nil means DefaultESPProposals

	// DPDDelay controls the interval for IKE dead peer detection.
	DPDDelay time.Duration
	Start    StartAction
}

var (
	nameRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$`)
	idRE       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@:-]{0,127}$`)
	fileRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	proposalRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)
)

const minPSKLen = 16

func (c Connection) Validate() error {
	if !nameRE.MatchString(c.Name) {
		return fmt.Errorf("ipsec: connection name %q must match %s", c.Name, nameRE)
	}
	if !c.RemoteAddr.IsValid() && c.Start == StartStart {
		return fmt.Errorf(
			"ipsec: connection %s: start_action=start needs a concrete RemoteAddr, not %%any", c.Name,
		)
	}
	if c.LocalAddr.Zone() != "" || c.RemoteAddr.Zone() != "" {
		return fmt.Errorf(
			"ipsec: connection %s: scoped (zoned) addresses are not supported", c.Name,
		)
	}
	if c.LocalAddr.IsValid() && c.RemoteAddr.IsValid() && c.LocalAddr.Is4() != c.RemoteAddr.Is4() {
		return fmt.Errorf(
			"ipsec: connection %s: LocalAddr %s and RemoteAddr %s are different address families",
			c.Name, c.LocalAddr, c.RemoteAddr,
		)
	}
	if !idRE.MatchString(c.LocalID) {
		return fmt.Errorf("ipsec: connection %s: LocalID %q must match %s", c.Name, c.LocalID, idRE)
	}
	if c.RemoteID != AnyID && !idRE.MatchString(c.RemoteID) {
		return fmt.Errorf("ipsec: connection %s: RemoteID %q must be %s or match %s", c.Name, c.RemoteID, AnyID, idRE)
	}
	switch c.Auth {
	case AuthPSK:
		if err := validatePSK("connection "+c.Name, c.PSK); err != nil {
			return err
		}
	case AuthPubkey:
		if !fileRE.MatchString(c.LocalPubkey) || !fileRE.MatchString(c.RemotePubkey) {
			return fmt.Errorf(
				"ipsec: connection %s: LocalPubkey/RemotePubkey must be plain file names matching %s",
				c.Name, fileRE,
			)
		}
	default:
		return fmt.Errorf("ipsec: connection %s: unknown auth method %q", c.Name, c.Auth)
	}
	if len(c.LocalTS) == 0 || len(c.RemoteTS) == 0 {
		return fmt.Errorf("ipsec: connection %s: LocalTS and RemoteTS must both be non-empty", c.Name)
	}
	for _, p := range append(append([]netip.Prefix(nil), c.LocalTS...), c.RemoteTS...) {
		if !p.IsValid() {
			return fmt.Errorf("ipsec: connection %s: invalid traffic selector %v", c.Name, p)
		}
	}
	if c.IfID == 0 {
		return fmt.Errorf(
			"ipsec: connection %s: IfID must be non-zero (route-based design; 0 would fall back to policy-based matching)",
			c.Name,
		)
	}
	for _, p := range append(append([]string(nil), c.IKEProposals...), c.ESPProposals...) {
		if !proposalRE.MatchString(p) {
			return fmt.Errorf("ipsec: connection %s: proposal %q must match %s", c.Name, p, proposalRE)
		}
	}
	if c.DPDDelay < 0 {
		return fmt.Errorf("ipsec: connection %s: DPDDelay must not be negative", c.Name)
	}
	switch c.Start {
	case "", StartNone, StartStart:
	default:
		return fmt.Errorf("ipsec: connection %s: unknown start action %q", c.Name, c.Start)
	}
	return nil
}

// validatePSK checks a pre-shared key: long enough, and printable ASCII
// without spaces, quotes or backslashes so it never needs quoting in
// swanctl.conf.
func validatePSK(owner, psk string) error {
	if len(psk) < minPSKLen {
		return fmt.Errorf("ipsec: %s: PSK must be at least %d characters", owner, minPSKLen)
	}
	for _, r := range psk {
		if r < 0x21 || r > 0x7e || r == '"' || r == '\\' {
			return fmt.Errorf(
				"ipsec: %s: PSK may only contain printable ASCII without spaces, quotes or backslashes", owner)
		}
	}
	return nil
}

// ChildName is the CHILD_SA name for connection conn at epoch.
func ChildName(conn string, epoch uint64) string {
	return conn + "-e" + strconv.FormatUint(epoch, 10)
}

func ParseChildName(child string) (conn string, epoch uint64, ok bool) {
	i := strings.LastIndex(child, "-e")
	if i <= 0 || i+2 >= len(child) {
		return "", 0, false
	}
	digits := child[i+2:]
	if digits[0] == '+' || digits[0] == '-' || (len(digits) > 1 && digits[0] == '0') {
		return "", 0, false // ChildName never renders a sign or a leading zero
	}
	e, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return "", 0, false
	}
	return child[:i], e, true
}

// Render produces a complete swanctl.conf (connections and, for PSK
// connections, secrets) for conns. Output is deterministic: connections
// are sorted by name, so re-rendering an unchanged set produces
// byte-identical text.
func Render(conns []Connection) (string, error) {
	sorted := append([]Connection(nil), conns...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for i, c := range sorted {
		if err := c.Validate(); err != nil {
			return "", err
		}
		if i > 0 && sorted[i-1].Name == c.Name {
			return "", fmt.Errorf("ipsec: duplicate connection name %q", c.Name)
		}
	}
	ifIDs := map[uint32]string{}
	for _, c := range sorted {
		if other, dup := ifIDs[c.IfID]; dup {
			return "", fmt.Errorf(
				"ipsec: connections %s and %s share if_id %d; each peer needs its own XFRM interface",
				other, c.Name, c.IfID,
			)
		}
		ifIDs[c.IfID] = c.Name
	}

	var b strings.Builder
	b.WriteString("# Generated by egressa (internal/ipsec). Do not edit by hand.\n")
	b.WriteString("connections {\n")
	for _, c := range sorted {
		renderConnection(&b, c)
	}
	b.WriteString("}\n")

	var psk []Connection
	for _, c := range sorted {
		if c.Auth == AuthPSK {
			psk = append(psk, c)
		}
	}
	if len(psk) > 0 {
		b.WriteString("secrets {\n")
		for _, c := range psk {
			fmt.Fprintf(&b, "  ike-%s {\n", c.Name)
			fmt.Fprintf(&b, "    id-1 = %s\n", c.LocalID)
			fmt.Fprintf(&b, "    id-2 = %s\n", c.RemoteID)
			// strongSwan reads a secret starting with "0x" as hex
			// and "0s" as base64, so writing the PSK verbatim would
			// silently change its meaning for such values. Hex also
			// keeps the secret free of any quoting concern.
			fmt.Fprintf(&b, "    secret = 0x%s\n", hex.EncodeToString([]byte(c.PSK)))
			b.WriteString("  }\n")
		}
		b.WriteString("}\n")
	}
	return b.String(), nil
}

func renderConnection(b *strings.Builder, c Connection) {
	ike := c.IKEProposals
	if len(ike) == 0 {
		ike = DefaultIKEProposals
	}
	esp := c.ESPProposals
	if len(esp) == 0 {
		esp = DefaultESPProposals
	}
	start := c.Start
	if start == "" {
		start = StartNone
	}

	fmt.Fprintf(b, "  %s {\n", c.Name)
	b.WriteString("    version = 2\n")
	if c.LocalAddr.IsValid() {
		fmt.Fprintf(b, "    local_addrs = %s\n", c.LocalAddr)
	}
	if c.RemoteAddr.IsValid() {
		fmt.Fprintf(b, "    remote_addrs = %s\n", c.RemoteAddr)
	} else {
		b.WriteString("    remote_addrs = %any\n")
	}
	fmt.Fprintf(b, "    proposals = %s\n", strings.Join(ike, ","))
	if c.DPDDelay > 0 {
		fmt.Fprintf(b, "    dpd_delay = %ds\n", ceilSeconds(c.DPDDelay))
	}
	b.WriteString("    local {\n")
	fmt.Fprintf(b, "      auth = %s\n", c.Auth)
	fmt.Fprintf(b, "      id = %s\n", c.LocalID)
	if c.Auth == AuthPubkey {
		fmt.Fprintf(b, "      pubkeys = %s\n", c.LocalPubkey)
	}
	b.WriteString("    }\n")
	b.WriteString("    remote {\n")
	fmt.Fprintf(b, "      auth = %s\n", c.Auth)
	fmt.Fprintf(b, "      id = %s\n", c.RemoteID)
	if c.Auth == AuthPubkey {
		fmt.Fprintf(b, "      pubkeys = %s\n", c.RemotePubkey)
	}
	b.WriteString("    }\n")
	b.WriteString("    children {\n")
	fmt.Fprintf(b, "      %s {\n", ChildName(c.Name, c.Epoch))
	fmt.Fprintf(b, "        local_ts = %s\n", joinPrefixes(c.LocalTS))
	fmt.Fprintf(b, "        remote_ts = %s\n", joinPrefixes(c.RemoteTS))
	fmt.Fprintf(b, "        esp_proposals = %s\n", strings.Join(esp, ","))
	b.WriteString("        mode = tunnel\n")
	fmt.Fprintf(b, "        if_id_in = %d\n", c.IfID)
	fmt.Fprintf(b, "        if_id_out = %d\n", c.IfID)
	fmt.Fprintf(b, "        start_action = %s\n", start)
	if c.DPDDelay > 0 {
		// a dead gateway must disappear from the SA
		// list so the caller sees it, instead of charon
		// silently retrying it behind the caller's back.
		b.WriteString("        dpd_action = clear\n")
	}
	b.WriteString("      }\n")
	b.WriteString("    }\n")
	b.WriteString("  }\n")
}

func joinPrefixes(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.Masked().String()
	}
	return strings.Join(s, ",")
}

func ceilSeconds(d time.Duration) int64 {
	s := int64(d / time.Second)
	if d%time.Second != 0 {
		s++
	}
	return s
}
