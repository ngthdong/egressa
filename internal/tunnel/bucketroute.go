package tunnel

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

type BucketID string

type EgressID string

type EgressMark uint32

type egressEntry struct {
	mark    EgressMark
	tableID int
	route   RouteInfo
}

type EgressRouteTable struct {
	mu          sync.Mutex
	nextMark    EgressMark
	nextTableID int
	egresses    map[EgressID]egressEntry
}

func NewEgressRouteTable(baseTableID int) *EgressRouteTable {
	return &EgressRouteTable{
		nextMark:    1,
		nextTableID: baseTableID,
		egresses:    make(map[EgressID]egressEntry),
	}
}

func (t *EgressRouteTable) RegisterEgress(id EgressID, route RouteInfo) EgressMark {
	t.mu.Lock()
	defer t.mu.Unlock()

	if e, ok := t.egresses[id]; ok {
		return e.mark
	}
	e := egressEntry{mark: t.nextMark, tableID: t.nextTableID, route: route}
	t.nextMark++
	t.nextTableID++
	t.egresses[id] = e
	return e.mark
}

func (t *EgressRouteTable) Mark(id EgressID) (EgressMark, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.egresses[id]
	return e.mark, ok
}

func (t *EgressRouteTable) TableID(id EgressID) (int, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.egresses[id]
	return e.tableID, ok
}

func (t *EgressRouteTable) Route(id EgressID) (RouteInfo, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.egresses[id]
	return e.route, ok
}

func (t *EgressRouteTable) Egresses() []EgressID {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]EgressID, 0, len(t.egresses))
	for id := range t.egresses {
		out = append(out, id)
	}
	return out
}

func markHex(mark EgressMark) string {
	return fmt.Sprintf("0x%x", uint32(mark))
}

func ruleArgs(mark EgressMark, tableID int) []string {
	return []string{"rule", "add", "fwmark", markHex(mark), "table", strconv.Itoa(tableID)}
}

func ruleDelArgs(mark EgressMark, tableID int) []string {
	return []string{"rule", "del", "fwmark", markHex(mark), "table", strconv.Itoa(tableID)}
}

func routeArgs(tableID int, route RouteInfo) []string {
	args := []string{"route", "replace", "default"}
	if route.Gateway.IsValid() {
		args = append(args, "via", route.Gateway.String())
	}
	args = append(args, "dev", route.Interface, "table", strconv.Itoa(tableID))
	return args
}

func hasRule(mark EgressMark, tableID int) (bool, error) {
	out, err := exec.Command("ip", "rule", "show").Output()
	if err != nil {
		return false, fmt.Errorf("tunnel: ip rule show: %w", err)
	}
	markNeedle := "fwmark " + markHex(mark)
	tableNeedle := "lookup " + strconv.Itoa(tableID)
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, markNeedle) && strings.Contains(line, tableNeedle) {
			return true, nil
		}
	}
	return false, nil
}

// Apply installs the policy rule and default route for a registered egress.
// The fwmark and routing table assigned to the egress remain stable.
// Safe to call repeatedly: the rule is added only if missing, and the
// route is installed with "ip route replace".
// Requires CAP_NET_ADMIN
func (t *EgressRouteTable) Apply(id EgressID) error {
	t.mu.Lock()
	e, ok := t.egresses[id]
	t.mu.Unlock()
	if !ok {
		return fmt.Errorf("tunnel: egress %q was never registered", id)
	}

	exists, err := hasRule(e.mark, e.tableID)
	if err != nil {
		return fmt.Errorf("tunnel: check existing ip rule for egress %q: %w", id, err)
	}
	if !exists {
		if err := runIP(ruleArgs(e.mark, e.tableID)...); err != nil {
			return fmt.Errorf("tunnel: add ip rule for egress %q: %w", id, err)
		}
	}
	if err := runIP(routeArgs(e.tableID, e.route)...); err != nil {
		return fmt.Errorf("tunnel: set route for egress %q: %w", id, err)
	}
	return nil
}

// Teardown removes the policy rule and routing table for a registered egress.
// It is intended for permanent egress removal; it does not remove the egress
// from the route table's bookkeeping or release its mark or table ID.
// Bucket reassignment must use BucketEgressMap.Assign instead.
// Requires CAP_NET_ADMIN.
func (t *EgressRouteTable) Teardown(id EgressID) error {
	t.mu.Lock()
	e, ok := t.egresses[id]
	t.mu.Unlock()
	if !ok {
		return fmt.Errorf("tunnel: egress %q was never registered", id)
	}
	errRule := runIP(ruleDelArgs(e.mark, e.tableID)...)
	errRoute := runIP("route", "flush", "table", strconv.Itoa(e.tableID))
	return errors.Join(errRule, errRoute)
}

type BucketEgressMap struct {
	mu          sync.Mutex
	routes      *EgressRouteTable
	assignments map[BucketID]EgressID
}

func NewBucketEgressMap(routes *EgressRouteTable) *BucketEgressMap {
	return &BucketEgressMap{routes: routes, assignments: make(map[BucketID]EgressID)}
}

func (b *BucketEgressMap) Assign(bucket BucketID, egress EgressID) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.assignments[bucket] = egress
}

func (b *BucketEgressMap) EgressFor(bucket BucketID) (EgressID, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.assignments[bucket]
	return e, ok
}

// LabelNewFlow returns the mark assigned to a bucket for a new flow.
// The mark remains stable for the lifetime of the flow via conntrack.
// Returns false if the bucket has no assignment or its egress is unregistered.
func (b *BucketEgressMap) LabelNewFlow(bucket BucketID) (EgressMark, bool) {
	b.mu.Lock()
	egress, ok := b.assignments[bucket]
	b.mu.Unlock()
	if !ok {
		return 0, false
	}
	return b.routes.Mark(egress)
}

type ConnmarkRestoreRule struct {
	Chain string
}

func (r ConnmarkRestoreRule) args(command string) []string {
	return []string{"-t", "mangle", command, r.Chain, "-j", "CONNMARK", "--restore-mark"}
}

func AddConnmarkRestore(rule ConnmarkRestoreRule) error {
	return runIptables(rule.args("-A"))
}

func RemoveConnmarkRestore(rule ConnmarkRestoreRule) error {
	return runIptables(rule.args("-D"))
}

func HasConnmarkRestore(rule ConnmarkRestoreRule) (bool, error) {
	return ruleExists(rule.args("-C"))
}

type ConnmarkSaveRule struct {
	Chain string
}

func (r ConnmarkSaveRule) args(command string) []string {
	return []string{"-t", "mangle", command, r.Chain, "-j", "CONNMARK", "--save-mark"}
}

func AddConnmarkSave(rule ConnmarkSaveRule) error {
	return runIptables(rule.args("-A"))
}

func RemoveConnmarkSave(rule ConnmarkSaveRule) error {
	return runIptables(rule.args("-D"))
}

func HasConnmarkSave(rule ConnmarkSaveRule) (bool, error) {
	return ruleExists(rule.args("-C"))
}
