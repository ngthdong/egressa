package tunnel

import (
	"net/netip"
	"testing"
)

func TestMarkHex(t *testing.T) {
	if got, want := markHex(1), "0x1"; got != want {
		t.Fatalf("markHex(1) = %q, want %q", got, want)
	}
	if got, want := markHex(255), "0xff"; got != want {
		t.Fatalf("markHex(255) = %q, want %q", got, want)
	}
}

func TestRuleArgsAndRouteArgs(t *testing.T) {
	got := ruleArgs(7, 105)
	want := []string{"rule", "add", "fwmark", "0x7", "table", "105"}
	if !stringSlicesEqual(got, want) {
		t.Fatalf("ruleArgs(7, 105) = %v, want %v", got, want)
	}

	gotDel := ruleDelArgs(7, 105)
	wantDel := []string{"rule", "del", "fwmark", "0x7", "table", "105"}
	if !stringSlicesEqual(gotDel, wantDel) {
		t.Fatalf("ruleDelArgs(7, 105) = %v, want %v", gotDel, wantDel)
	}

	// Direct-attached backbone link: no gateway, "dev" only.
	direct := routeArgs(105, RouteInfo{Interface: "wg-eg1"})
	wantDirect := []string{"route", "replace", "default", "dev", "wg-eg1", "table", "105"}
	if !stringSlicesEqual(direct, wantDirect) {
		t.Fatalf("routeArgs (direct) = %v, want %v", direct, wantDirect)
	}

	// A route with an explicit next-hop gateway.
	viaGW := routeArgs(105, RouteInfo{Gateway: netip.MustParseAddr("192.0.2.1"), Interface: "eth1"})
	wantViaGW := []string{"route", "replace", "default", "via", "192.0.2.1", "dev", "eth1", "table", "105"}
	if !stringSlicesEqual(viaGW, wantViaGW) {
		t.Fatalf("routeArgs (via gateway) = %v, want %v", viaGW, wantViaGW)
	}
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestEgressRouteTable_RegisterEgress_AssignsDistinctStableIdentities(t *testing.T) {
	table := NewEgressRouteTable(100)

	mark1 := table.RegisterEgress("eg-1", RouteInfo{Interface: "wg-eg1"})
	mark2 := table.RegisterEgress("eg-2", RouteInfo{Interface: "wg-eg2"})
	if mark1 == mark2 {
		t.Fatalf("two distinct egresses got the same mark: %d", mark1)
	}
	if mark1 == 0 || mark2 == 0 {
		t.Fatalf("mark 0 (reserved/unmarked) was handed out: mark1=%d mark2=%d", mark1, mark2)
	}

	table1, ok := table.TableID("eg-1")
	if !ok {
		t.Fatal("TableID(eg-1) not found")
	}
	table2, ok := table.TableID("eg-2")
	if !ok {
		t.Fatal("TableID(eg-2) not found")
	}
	if table1 == table2 {
		t.Fatalf("two distinct egresses got the same table ID: %d", table1)
	}
	if table1 < 100 || table2 < 100 {
		t.Fatalf("table IDs %d, %d fell below baseTableID 100", table1, table2)
	}
}

func TestEgressRouteTable_RegisterEgress_IdempotentForSameID(t *testing.T) {
	table := NewEgressRouteTable(100)

	first := table.RegisterEgress("eg-1", RouteInfo{Interface: "wg-eg1"})
	second := table.RegisterEgress("eg-1", RouteInfo{Interface: "wg-eg1-renamed"})
	if first != second {
		t.Fatalf("RegisterEgress returned different marks for the same id: %d then %d", first, second)
	}
	route, ok := table.Route("eg-1")
	if !ok || route.Interface != "wg-eg1" {
		t.Fatalf("Route(eg-1) = %+v, want the ORIGINAL route (interface wg-eg1) unchanged", route)
	}
}

func TestEgressRouteTable_UnknownEgress_NotFound(t *testing.T) {
	table := NewEgressRouteTable(100)
	if _, ok := table.Mark("never-registered"); ok {
		t.Fatal("Mark for an unregistered egress reported ok=true")
	}
	if _, ok := table.TableID("never-registered"); ok {
		t.Fatal("TableID for an unregistered egress reported ok=true")
	}
	if _, ok := table.Route("never-registered"); ok {
		t.Fatal("Route for an unregistered egress reported ok=true")
	}
}

func TestBucketEgressMap_AssignAndLabelNewFlow(t *testing.T) {
	routes := NewEgressRouteTable(100)
	mark1 := routes.RegisterEgress("eg-1", RouteInfo{Interface: "wg-eg1"})

	bmap := NewBucketEgressMap(routes)
	if _, ok := bmap.EgressFor("bucket-a"); ok {
		t.Fatal("EgressFor on a never-assigned bucket reported ok=true")
	}
	if _, ok := bmap.LabelNewFlow("bucket-a"); ok {
		t.Fatal("LabelNewFlow on a never-assigned bucket reported ok=true")
	}

	bmap.Assign("bucket-a", "eg-1")
	egress, ok := bmap.EgressFor("bucket-a")
	if !ok || egress != "eg-1" {
		t.Fatalf("EgressFor(bucket-a) = (%q, %v), want (eg-1, true)", egress, ok)
	}
	mark, ok := bmap.LabelNewFlow("bucket-a")
	if !ok || mark != mark1 {
		t.Fatalf("LabelNewFlow(bucket-a) = (%d, %v), want (%d, true)", mark, ok, mark1)
	}
}

func TestBucketEgressMap_LabelNewFlow_UnregisteredEgress_NotOK(t *testing.T) {
	routes := NewEgressRouteTable(100)
	bmap := NewBucketEgressMap(routes)

	bmap.Assign("bucket-a", "eg-not-yet-registered")
	if _, ok := bmap.LabelNewFlow("bucket-a"); ok {
		t.Fatal("LabelNewFlow succeeded for an egress that was never registered with the route table")
	}

	mark := routes.RegisterEgress("eg-not-yet-registered", RouteInfo{Interface: "wg-eg9"})
	got, ok := bmap.LabelNewFlow("bucket-a")
	if !ok || got != mark {
		t.Fatalf("LabelNewFlow after registration = (%d, %v), want (%d, true)", got, ok, mark)
	}
}

func TestBucketEgressMap_ReassignmentDoesNotAffectAlreadyLabeledFlow(t *testing.T) {
	routes := NewEgressRouteTable(100)
	markOld := routes.RegisterEgress("eg-old", RouteInfo{Interface: "wg-eg-old"})
	markNew := routes.RegisterEgress("eg-new", RouteInfo{Interface: "wg-eg-new"})
	tableOld, _ := routes.TableID("eg-old")
	routeOld, _ := routes.Route("eg-old")

	bmap := NewBucketEgressMap(routes)
	bmap.Assign("bucket-a", "eg-old")

	// A flow starts now: it gets labeled for the CURRENT assignment,
	// eg-old. In the real dataplane this mark would be saved into that
	// flow's conntrack entry right here and never recomputed again.
	flowMark, ok := bmap.LabelNewFlow("bucket-a")
	if !ok || flowMark != markOld {
		t.Fatalf("LabelNewFlow (pre-reassignment) = (%d, %v), want (%d, true)", flowMark, ok, markOld)
	}

	bmap.Assign("bucket-a", "eg-new")

	// A NEW flow starting now correctly sees the new egress.
	newFlowMark, ok := bmap.LabelNewFlow("bucket-a")
	if !ok || newFlowMark != markNew {
		t.Fatalf("LabelNewFlow (post-reassignment) = (%d, %v), want (%d, true)", newFlowMark, ok, markNew)
	}
	if newFlowMark == flowMark {
		t.Fatal("the new flow got the SAME mark as the old one -- reassignment had no effect at all")
	}

	stillOldTable, ok := routes.TableID("eg-old")
	if !ok || stillOldTable != tableOld {
		t.Fatalf("eg-old's table ID changed after an unrelated bucket reassignment: was %d, now %d (ok=%v)", tableOld, stillOldTable, ok)
	}
	stillOldRoute, ok := routes.Route("eg-old")
	if !ok || stillOldRoute != routeOld {
		t.Fatalf("eg-old's route changed after an unrelated bucket reassignment: was %+v, now %+v (ok=%v)", routeOld, stillOldRoute, ok)
	}
	stillOldMark, ok := routes.Mark("eg-old")
	if !ok || stillOldMark != markOld {
		t.Fatalf("eg-old's mark changed after an unrelated bucket reassignment: was %d, now %d (ok=%v)", markOld, stillOldMark, ok)
	}
}

func TestEgressRouteTable_ApplyAndTeardown(t *testing.T) {
	table := NewEgressRouteTable(100)
	table.RegisterEgress("eg-loop", RouteInfo{Interface: "lo"})

	applyErr := table.Apply("eg-loop")
	if applyErr != nil {
		skipIfPrivilegedCommandFailed(t, "ip", applyErr)
		t.Fatalf("Apply: %v", applyErr)
	}
	// Applying a second time must not fail or duplicate the rule.
	if err := table.Apply("eg-loop"); err != nil {
		t.Fatalf("second Apply (idempotency): %v", err)
	}

	if err := table.Teardown("eg-loop"); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
}

func TestEgressRouteTable_Apply_UnregisteredEgress(t *testing.T) {
	table := NewEgressRouteTable(100)
	if err := table.Apply("never-registered"); err == nil {
		t.Fatal("Apply on an unregistered egress: expected an error, got nil")
	}
	if err := table.Teardown("never-registered"); err == nil {
		t.Fatal("Teardown on an unregistered egress: expected an error, got nil")
	}
}

func TestConnmarkRestoreRule_AddHasRemove(t *testing.T) {
	rule := ConnmarkRestoreRule{Chain: "OUTPUT"}

	addErr := AddConnmarkRestore(rule)
	if addErr != nil {
		skipIfPrivilegedCommandFailed(t, "iptables", addErr)
		t.Fatalf("AddConnmarkRestore: %v", addErr)
	}
	t.Cleanup(func() { _ = RemoveConnmarkRestore(rule) })

	has, err := HasConnmarkRestore(rule)
	if err != nil {
		t.Fatalf("HasConnmarkRestore: %v", err)
	}
	if !has {
		t.Fatal("HasConnmarkRestore = false right after AddConnmarkRestore")
	}

	if err := RemoveConnmarkRestore(rule); err != nil {
		t.Fatalf("RemoveConnmarkRestore: %v", err)
	}
	has, err = HasConnmarkRestore(rule)
	if err != nil {
		t.Fatalf("HasConnmarkRestore after removal: %v", err)
	}
	if has {
		t.Fatal("HasConnmarkRestore = true after RemoveConnmarkRestore")
	}
}

func TestConnmarkSaveRule_AddHasRemove(t *testing.T) {
	rule := ConnmarkSaveRule{Chain: "PREROUTING"}

	addErr := AddConnmarkSave(rule)
	if addErr != nil {
		skipIfPrivilegedCommandFailed(t, "iptables", addErr)
		t.Fatalf("AddConnmarkSave: %v", addErr)
	}
	t.Cleanup(func() { _ = RemoveConnmarkSave(rule) })

	has, err := HasConnmarkSave(rule)
	if err != nil {
		t.Fatalf("HasConnmarkSave: %v", err)
	}
	if !has {
		t.Fatal("HasConnmarkSave = false right after AddConnmarkSave")
	}

	if err := RemoveConnmarkSave(rule); err != nil {
		t.Fatalf("RemoveConnmarkSave: %v", err)
	}
	has, err = HasConnmarkSave(rule)
	if err != nil {
		t.Fatalf("HasConnmarkSave after removal: %v", err)
	}
	if has {
		t.Fatal("HasConnmarkSave = false after RemoveConnmarkSave")
	}
}
