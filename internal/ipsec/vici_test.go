package ipsec

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/strongswan/govici/vici"
)

// ikeSAMsg builds an IKE_SA section the way charon's list-sas and updown
// events report one.
func ikeSAMsg(uniqueID uint64, state string, children ...*vici.Message) *vici.Message {
	m := newMsg(
		"uniqueid", strconv.FormatUint(uniqueID, 10),
		"version", "2",
		"state", state,
		"local-host", "192.0.2.1",
		"remote-host", "192.0.2.2",
		"local-id", "client-1",
		"remote-id", "gw-hk",
		"initiator", "yes",
		"encr-alg", "AES_GCM_16",
		"encr-keysize", "256",
		"prf-alg", "PRF_HMAC_SHA2_256",
		"dh-group", "CURVE_25519",
		"established", "12",
	)
	if len(children) > 0 {
		cs := vici.NewMessage()
		for _, c := range children {
			mustSet(cs, str(c, "name")+"-"+str(c, "uniqueid"), c)
		}
		mustSet(m, "child-sas", cs)
	}
	return m
}

func childSAMsg(name string, uniqueID uint64, state string) *vici.Message {
	return newMsg(
		"name", name,
		"uniqueid", strconv.FormatUint(uniqueID, 10),
		"reqid", "1",
		"state", state,
		"mode", "TUNNEL",
		"protocol", "ESP",
		"spi-in", "c1a2b3c4",
		"spi-out", "0d0e0f10",
		"if-id-in", "0000002a",
		"if-id-out", "0000002a",
		"encr-alg", "AES_GCM_16",
		"bytes-in", "840",
		"packets-in", "10",
		"bytes-out", "420",
		"packets-out", "5",
		"install-time", "3",
		"local-ts", []string{"10.201.0.2/32"},
		"remote-ts", []string{"0.0.0.0/0"},
	)
}

func TestNewViciIKE_DialFailureReturnsNilPointer(t *testing.T) {
	f := newFakeCharon(t)
	f.dialErr = errors.New("connection refused")
	v, err := NewViciIKE(context.Background(), WithViciDialer(f.dial))
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("NewViciIKE error = %v, want the dial error", err)
	}
	if v != nil {
		t.Fatalf("NewViciIKE returned %#v alongside an error, want nil", v)
	}
}

func TestNewViciIKE_UsesSocketPathAndRealDialer(t *testing.T) {
	dir := shortTempDir(t)
	path := dir + "/c.vici"
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	go func() {
		c, err := l.Accept()
		if err == nil {
			defer func() { _ = c.Close() }()
			buf := make([]byte, 1)
			_, _ = c.Read(buf) // hold the connection open until the client closes
		}
	}()
	v, err := NewViciIKE(context.Background(), WithViciSocket(path))
	if err != nil {
		t.Fatalf("NewViciIKE over a real unix socket: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestViciIKE_LoadConn_Message(t *testing.T) {
	f := newFakeCharon(t)
	f.handle("load-conn", ok)
	v := f.newIKE(t)

	c := clientConn()
	c.ESPProposals = []string{"aes128gcm16-x25519", "aes256gcm16-x25519"}
	if err := v.LoadConn(context.Background(), c); err != nil {
		t.Fatalf("LoadConn: %v", err)
	}
	req := f.lastRequest("load-conn")
	conn, ok := req.Get("egressa-gw-hk").(*vici.Message)
	if !ok {
		t.Fatalf("load-conn message has no section for the connection: %v", req)
	}
	checks := map[string]any{
		"version":      "2",
		"local_addrs":  []string{"192.0.2.1"},
		"remote_addrs": []string{"192.0.2.2"},
		"proposals":    []string{"aes256gcm16-prfsha256-x25519"},
		"dpd_delay":    "10s",
	}
	for k, want := range checks {
		if got := conn.Get(k); !reflect.DeepEqual(got, want) {
			t.Errorf("conn %s = %#v, want %#v", k, got, want)
		}
	}
	local := conn.Get("local").(*vici.Message)
	remote := conn.Get("remote").(*vici.Message)
	if str(local, "auth") != "psk" || str(local, "id") != "client-1" ||
		str(remote, "auth") != "psk" || str(remote, "id") != "gw-hk" {
		t.Errorf("auth sections = %v / %v", local, remote)
	}
	if local.Get("secret") != nil || strings.Contains(req.String(), c.PSK) {
		t.Error("load-conn carried the PSK; it must only ever go through load-shared")
	}
	child := conn.Get("children").(*vici.Message).Get("egressa-gw-hk-e7").(*vici.Message)
	childChecks := map[string]any{
		"local_ts":      []string{"10.201.0.2/32"},
		"remote_ts":     []string{"0.0.0.0/0"},
		"esp_proposals": []string{"aes128gcm16-x25519", "aes256gcm16-x25519"},
		"mode":          "tunnel",
		"if_id_in":      "42",
		"if_id_out":     "42",
		"start_action":  "none",
		"dpd_action":    "clear",
	}
	for k, want := range childChecks {
		if got := child.Get(k); !reflect.DeepEqual(got, want) {
			t.Errorf("child %s = %#v, want %#v", k, got, want)
		}
	}
}

func TestViciIKE_LoadConn_ResponderAndDefaults(t *testing.T) {
	f := newFakeCharon(t)
	f.handle("load-conn", ok)
	v := f.newIKE(t)

	c := gatewayConn()
	c.RemoteID = AnyID
	c.Start = StartStart
	c.RemoteAddr = netip.MustParseAddr("192.0.2.9")
	if err := v.LoadConn(context.Background(), c); err != nil {
		t.Fatalf("LoadConn: %v", err)
	}
	conn := f.lastRequest("load-conn").Get("egressa-client-1").(*vici.Message)
	if got := str(conn.Get("remote").(*vici.Message), "id"); got != AnyID {
		t.Errorf("remote id = %q, want %%any", got)
	}
	if conn.Get("dpd_delay") != nil {
		t.Error("dpd_delay set without DPDDelay")
	}
	child := conn.Get("children").(*vici.Message).Get("egressa-client-1-e7").(*vici.Message)
	if child.Get("dpd_action") != nil || str(child, "start_action") != "start" {
		t.Errorf("child = %v, want start_action=start and no dpd_action", child)
	}
	if got := child.Get("esp_proposals"); !reflect.DeepEqual(got, DefaultESPProposals) {
		t.Errorf("esp_proposals = %v, want defaults", got)
	}

	c.RemoteAddr = netip.Addr{}
	c.Start = StartNone
	c.LocalAddr = netip.Addr{}
	if err := v.LoadConn(context.Background(), c); err != nil {
		t.Fatalf("LoadConn %%any responder: %v", err)
	}
	conn = f.lastRequest("load-conn").Get("egressa-client-1").(*vici.Message)
	if got := conn.Get("remote_addrs"); !reflect.DeepEqual(got, []string{AnyID}) {
		t.Errorf("remote_addrs = %v, want [%%any]", got)
	}
	if conn.Get("local_addrs") != nil {
		t.Error("local_addrs set without LocalAddr")
	}
}

func TestViciIKE_LoadConn_Rejects(t *testing.T) {
	f := newFakeCharon(t)
	f.handle("load-conn", ok)
	v := f.newIKE(t)

	bad := clientConn()
	bad.IfID = 0
	if err := v.LoadConn(context.Background(), bad); err == nil {
		t.Error("LoadConn accepted an invalid connection")
	}
	pk := clientConn()
	pk.Auth, pk.PSK, pk.LocalPubkey, pk.RemotePubkey = AuthPubkey, "", "a.pub", "b.pub"
	if err := v.LoadConn(context.Background(), pk); err == nil || !strings.Contains(err.Error(), "only PSK") {
		t.Errorf("LoadConn(pubkey) = %v, want an explicit unsupported error", err)
	}
	if f.lastRequest("load-conn") != nil {
		t.Error("an invalid connection reached the daemon")
	}
}

func TestViciIKE_SharedSecrets(t *testing.T) {
	f := newFakeCharon(t)
	f.handle("load-shared", ok)
	f.handle("unload-shared", ok)
	v := f.newIKE(t)

	s := SharedSecret{ID: "egressa-gw-hk", PSK: "0xdeadbeef-not-hex-really", Owners: []string{"client-1", "gw-hk"}}
	if err := v.LoadShared(context.Background(), s); err != nil {
		t.Fatalf("LoadShared: %v", err)
	}
	req := f.lastRequest("load-shared")
	if str(req, "id") != s.ID || str(req, "type") != "IKE" || str(req, "data") != s.PSK ||
		!reflect.DeepEqual(req.Get("owners"), s.Owners) {
		t.Fatalf("load-shared message = %v", req)
	}
	if err := v.UnloadShared(context.Background(), s.ID); err != nil {
		t.Fatalf("UnloadShared: %v", err)
	}
	if str(f.lastRequest("unload-shared"), "id") != s.ID {
		t.Fatal("unload-shared did not name the secret")
	}

	for name, bad := range map[string]SharedSecret{
		"bad id":    {ID: "a b", PSK: s.PSK, Owners: s.Owners},
		"short psk": {ID: "x", PSK: "short", Owners: s.Owners},
		"no owners": {ID: "x", PSK: s.PSK},
		"bad owner": {ID: "x", PSK: s.PSK, Owners: []string{"a}b"}},
	} {
		if err := v.LoadShared(context.Background(), bad); err == nil {
			t.Errorf("LoadShared(%s) accepted an invalid secret", name)
		}
	}
	if err := (SharedSecret{ID: "x", PSK: s.PSK, Owners: []string{AnyID, "gw"}}).Validate(); err != nil {
		t.Errorf("an owner of %%any must be accepted: %v", err)
	}
}

func TestViciIKE_CommandErrors(t *testing.T) {
	f := newFakeCharon(t)
	f.handle("unload-conn", fail("unload: connection 'gone' not found"))
	f.handle("unload-shared", fail("permission denied"))
	f.handle("load-conn", fail(""))
	v := f.newIKE(t)

	err := v.UnloadConn(context.Background(), "gone")
	if !errors.Is(err, ErrNotFound) || f.lastRequest("unload-conn").Get("name") != "gone" {
		t.Errorf("UnloadConn of a missing conn = %v, want ErrNotFound", err)
	}
	if err := v.UnloadShared(context.Background(), "x"); err == nil || errors.Is(err, ErrNotFound) ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Errorf("UnloadShared error = %v, want the daemon's message and not ErrNotFound", err)
	}
	if err := v.LoadConn(context.Background(), clientConn()); err == nil || !strings.Contains(err.Error(), "command failed") {
		t.Errorf("LoadConn error without errmsg = %v", err)
	}
	// A command charon does not know is a transport-level failure in
	// govici's eyes (CMD_UNKNOWN), not a success.
	if _, err := v.call(context.Background(), "no-such-command", nil); err == nil {
		t.Error("an unknown command succeeded")
	}
}

func TestViciIKE_ReconnectsAfterTransportFailure(t *testing.T) {
	f := newFakeCharon(t)
	f.handle("unload-conn", ok)
	f.handle("load-conn", func(*vici.Message) ([]*vici.Message, *vici.Message) { return nil, nil }) // daemon dies
	v := f.newIKE(t)

	before := f.dialCount()
	if err := v.LoadConn(context.Background(), clientConn()); err == nil {
		t.Fatal("LoadConn succeeded although the daemon dropped the connection")
	}
	if err := v.UnloadConn(context.Background(), "x"); err != nil {
		t.Fatalf("UnloadConn after a dropped session: %v (should have reconnected)", err)
	}
	if f.dialCount() != before+1 {
		t.Fatalf("dials = %d, want exactly one reconnect", f.dialCount()-before)
	}

	f.setDialErr(errors.New("still down"))
	v.mu.Lock()
	v.drop()
	v.mu.Unlock()
	if err := v.UnloadConn(context.Background(), "x"); err == nil {
		t.Fatal("UnloadConn succeeded with charon unreachable")
	}
	if _, err := v.ListSAs(context.Background(), ""); err == nil {
		t.Fatal("ListSAs succeeded with charon unreachable")
	}
	if err := v.TerminateIKE(context.Background(), "x"); err == nil {
		t.Fatal("TerminateIKE succeeded with charon unreachable")
	}
}

func TestViciIKE_ListSAs(t *testing.T) {
	f := newFakeCharon(t)
	f.handle("list-sas", func(req *vici.Message) ([]*vici.Message, *vici.Message) {
		return []*vici.Message{
			newMsg("egressa-gw-hk", ikeSAMsg(3, IKEStateEstablished,
				childSAMsg("egressa-gw-hk-e6", 4, ChildStateRekeyed),
				childSAMsg("egressa-gw-hk-e7", 5, ChildStateInstalled),
			)),
			newMsg("egressa-gw-sg", ikeSAMsg(9, "CONNECTING")),
		}, newMsg("success", "yes")
	})
	v := f.newIKE(t)

	sas, err := v.ListSAs(context.Background(), "egressa-gw-hk")
	if err != nil {
		t.Fatalf("ListSAs: %v", err)
	}
	req := f.lastRequest("list-sas")
	if str(req, "ike") != "egressa-gw-hk" || str(req, "noblock") != "yes" {
		t.Errorf("list-sas request = %v", req)
	}
	if len(sas) != 2 {
		t.Fatalf("ListSAs returned %d IKE_SAs, want 2", len(sas))
	}
	hk := sas[0]
	want := IKESA{
		Name: "egressa-gw-hk", UniqueID: 3, State: IKEStateEstablished,
		LocalHost: "192.0.2.1", RemoteHost: "192.0.2.2",
		LocalID: "client-1", RemoteID: "gw-hk", Initiator: true,
		EncrAlg: "AES_GCM_16", PRFAlg: "PRF_HMAC_SHA2_256", DHGroup: "CURVE_25519",
		EstablishedFor: 12 * time.Second,
	}
	children := hk.Children
	hk.Children = nil
	if !reflect.DeepEqual(hk, want) {
		t.Errorf("IKE_SA = %+v\nwant     %+v", hk, want)
	}
	wantChild := ChildSA{
		Name: "egressa-gw-hk-e7", UniqueID: 5, State: ChildStateInstalled,
		Mode: "TUNNEL", Protocol: "ESP", SPIIn: "c1a2b3c4", SPIOut: "0d0e0f10",
		IfIDIn: 42, IfIDOut: 42, EncrAlg: "AES_GCM_16",
		BytesIn: 840, PacketsIn: 10, BytesOut: 420, PacketsOut: 5,
		InstalledFor: 3 * time.Second,
		LocalTS:      []string{"10.201.0.2/32"}, RemoteTS: []string{"0.0.0.0/0"},
	}
	if len(children) != 2 || !reflect.DeepEqual(children[1], wantChild) {
		t.Errorf("children = %+v\nwant [1] = %+v", children, wantChild)
	}
	if !sas[0].Warm() || sas[1].Warm() {
		t.Error("Warm: want the established IKE_SA with an installed child warm, the connecting one not")
	}

	if _, err := v.ListSAs(context.Background(), ""); err != nil {
		t.Fatalf("ListSAs(all): %v", err)
	}
	if f.lastRequest("list-sas").Get("ike") != nil {
		t.Error("ListSAs(\"\") filtered by IKE name")
	}

	f.handle("list-sas", fail("query failed"))
	if _, err := v.ListSAs(context.Background(), ""); err == nil {
		t.Error("ListSAs ignored a failed response")
	}
	f.handle("list-sas", func(*vici.Message) ([]*vici.Message, *vici.Message) { return nil, nil })
	if _, err := v.ListSAs(context.Background(), ""); err == nil {
		t.Error("ListSAs ignored the daemon dropping the connection")
	}
}

func TestViciIKE_Initiate(t *testing.T) {
	f := newFakeCharon(t)
	f.handle("initiate", func(*vici.Message) ([]*vici.Message, *vici.Message) {
		return []*vici.Message{newMsg("group", "IKE", "level", "1", "msg", "initiating IKE_SA")},
			newMsg("success", "yes")
	})
	v := f.newIKE(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := v.Initiate(ctx, "egressa-gw-hk", "egressa-gw-hk-e7"); err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	req := f.lastRequest("initiate")
	ms, _ := strconv.Atoi(str(req, "timeout"))
	if str(req, "ike") != "egressa-gw-hk" || str(req, "child") != "egressa-gw-hk-e7" ||
		str(req, "loglevel") != "1" || ms <= 0 || ms > 30000 {
		t.Errorf("initiate request = %v", req)
	}
	if err := v.Initiate(context.Background(), "a", "b"); err != nil {
		t.Fatalf("Initiate without deadline: %v", err)
	}
	if str(f.lastRequest("initiate"), "timeout") != "0" {
		t.Error("Initiate without a deadline must ask charon to wait (timeout 0)")
	}
}

func TestViciIKE_Initiate_Failures(t *testing.T) {
	f := newFakeCharon(t)
	v := f.newIKE(t)

	f.handle("initiate", func(*vici.Message) ([]*vici.Message, *vici.Message) {
		return []*vici.Message{
				newMsg("msg", "establishing CHILD_SA egressa-gw-hk-e7{1}"),
				newMsg("msg", "received AUTHENTICATION_FAILED notify error"),
			},
			newMsg("success", "no", "errmsg", "establishing CHILD_SA 'egressa-gw-hk-e7' failed")
	})
	err := v.Initiate(context.Background(), "egressa-gw-hk", "egressa-gw-hk-e7")
	if !errors.Is(err, ErrAuthFailed) || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("Initiate with a rejected PSK = %v, want ErrAuthFailed", err)
	}

	f.handle("initiate", func(*vici.Message) ([]*vici.Message, *vici.Message) {
		return []*vici.Message{newMsg("msg", "giving up after 2 retransmits")},
			newMsg("success", "no", "errmsg", "establishing CHILD_SA 'x' failed")
	})
	err = v.Initiate(context.Background(), "a", "x")
	if err == nil || errors.Is(err, ErrAuthFailed) || !strings.Contains(err.Error(), "giving up after 2 retransmits") {
		t.Fatalf("Initiate timeout failure = %v, want a non-auth error naming the last log line", err)
	}

	f.handle("initiate", fail("no config named 'a'"))
	if err := v.Initiate(context.Background(), "a", "x"); err == nil || strings.Contains(err.Error(), "last log") {
		t.Fatalf("Initiate with no logs = %v", err)
	}

	f.handle("initiate", func(*vici.Message) ([]*vici.Message, *vici.Message) { return nil, nil })
	if err := v.Initiate(context.Background(), "a", "x"); err == nil {
		t.Fatal("Initiate ignored the daemon dropping the connection")
	}

	f.setDialErr(errors.New("down"))
	if err := v.Initiate(context.Background(), "a", "x"); err == nil {
		t.Fatal("Initiate succeeded with charon unreachable")
	}
}

func TestAuthFailedDetection(t *testing.T) {
	for _, line := range []string{
		"received AUTHENTICATION_FAILED notify error",
		"authentication of 'gw-hk' with pre-shared key failed",
		"tried 1 shared key for 'c' - 'g', but MAC mismatched",
	} {
		if !authFailed([]string{"x", line}) {
			t.Errorf("authFailed missed %q", line)
		}
	}
	if authFailed([]string{"establishing CHILD_SA failed", "authentication of 'gw' with pre-shared key successful"}) {
		t.Error("authFailed matched a successful authentication")
	}
}

func TestViciIKE_Terminate(t *testing.T) {
	f := newFakeCharon(t)
	f.handle("terminate", ok)
	v := f.newIKE(t)

	if err := v.TerminateIKE(context.Background(), "egressa-gw-hk"); err != nil {
		t.Fatalf("TerminateIKE: %v", err)
	}
	req := f.lastRequest("terminate")
	if str(req, "ike") != "egressa-gw-hk" || str(req, "force") != "yes" || str(req, "timeout") != "2000" {
		t.Errorf("terminate ike request = %v", req)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := v.TerminateIKEByID(ctx, 17); err != nil {
		t.Fatalf("TerminateIKEByID: %v", err)
	}
	req = f.lastRequest("terminate")
	ms, _ := strconv.Atoi(str(req, "timeout"))
	if str(req, "ike-id") != "17" || ms <= 0 || ms > 500 {
		t.Errorf("terminate ike-id request = %v (timeout must follow the shorter ctx deadline)", req)
	}
	if err := v.TerminateChild(context.Background(), 23); err != nil {
		t.Fatalf("TerminateChild: %v", err)
	}
	if str(f.lastRequest("terminate"), "child-id") != "23" {
		t.Error("TerminateChild did not select by child-id")
	}

	f.handle("terminate", fail("no matching SAs to terminate found"))
	if err := v.TerminateIKE(context.Background(), "gone"); !errors.Is(err, ErrNotFound) {
		t.Errorf("TerminateIKE of nothing = %v, want ErrNotFound", err)
	}
	f.handle("terminate", fail("terminating SA failed"))
	if err := v.TerminateChild(context.Background(), 1); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("TerminateChild failure = %v, want a plain error", err)
	}
	f.handle("terminate", func(*vici.Message) ([]*vici.Message, *vici.Message) { return nil, nil })
	if err := v.TerminateIKEByID(context.Background(), 1); err == nil {
		t.Error("TerminateIKEByID ignored the daemon dropping the connection")
	}
}

func TestTimeoutMS(t *testing.T) {
	if got := timeoutMS(context.Background(), 0); got != "0" {
		t.Errorf("no deadline, no fallback = %s, want 0", got)
	}
	if got := timeoutMS(context.Background(), 3*time.Second); got != "3000" {
		t.Errorf("no deadline = %s, want the fallback", got)
	}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if got := timeoutMS(expired, 0); got != "1" {
		t.Errorf("past deadline = %s, want the 1ms floor", got)
	}
	far, cancel2 := context.WithTimeout(context.Background(), time.Hour)
	defer cancel2()
	if got := timeoutMS(far, 2*time.Second); got != "2000" {
		t.Errorf("far deadline with fallback = %s, want the fallback cap", got)
	}
}

func TestParseChildSA_FallsBackToSectionKey(t *testing.T) {
	c := parseChildSA("legacy-child", newMsg("uniqueid", "3", "if-id-in", "zz"))
	if c.Name != "legacy-child" || c.UniqueID != 3 || c.IfIDIn != 0 {
		t.Fatalf("parseChildSA = %+v", c)
	}
}

func TestParseEvent(t *testing.T) {
	up, ok := parseEvent("ike-updown", newMsg("up", "yes", "egressa-gw-hk", ikeSAMsg(3, IKEStateEstablished)))
	if !ok || up.Kind != EventIKEUpDown || !up.Up || up.IKE.Name != "egressa-gw-hk" || up.IKE.UniqueID != 3 {
		t.Fatalf("ike up event = %+v, %v", up, ok)
	}
	down, ok := parseEvent("ike-updown", newMsg("egressa-gw-hk", ikeSAMsg(3, "DELETING")))
	if !ok || down.Up {
		t.Fatalf("ike down event = %+v, %v", down, ok)
	}
	child, ok := parseEvent("child-updown", newMsg("up", "yes", "x",
		ikeSAMsg(3, IKEStateEstablished, childSAMsg("x-e1", 4, ChildStateInstalled))))
	if !ok || child.Kind != EventChildUpDown || len(child.IKE.Children) != 1 {
		t.Fatalf("child event = %+v, %v", child, ok)
	}
	if _, ok := parseEvent("log", newMsg("msg", "x")); ok {
		t.Error("parseEvent accepted an unrelated event")
	}
	if _, ok := parseEvent("ike-updown", newMsg("up", "yes")); ok {
		t.Error("parseEvent accepted an updown event without an IKE_SA")
	}
	for k, want := range map[EventKind]string{
		EventIKEUpDown: "ike-updown", EventChildUpDown: "child-updown", EventResync: "resync", 99: "EventKind(99)",
	} {
		if k.String() != want {
			t.Errorf("EventKind(%d).String() = %q, want %q", int(k), k.String(), want)
		}
	}
}

// waitFor polls cond briefly; event delivery crosses goroutines.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func recvEvent(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case ev, ok := <-ch:
		if !ok {
			t.Fatal("event channel closed")
		}
		return ev
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for an event")
	}
	return Event{}
}

func TestViciIKE_Subscribe(t *testing.T) {
	f := newFakeCharon(t)
	v := f.newIKE(t, WithViciReconnect(10*time.Millisecond))

	events, cancel := v.Subscribe()
	waitFor(t, "event registration", func() bool { return f.subscribers("ike-updown") == 1 })
	if f.subscribers("child-updown") != 1 {
		t.Fatal("child-updown not registered")
	}
	other, cancelOther := v.Subscribe()

	f.emit("ike-updown", newMsg("up", "yes", "egressa-gw-hk", ikeSAMsg(3, IKEStateEstablished)))
	for _, ch := range []<-chan Event{events, other} {
		if ev := recvEvent(t, ch); ev.Kind != EventIKEUpDown || !ev.Up || ev.IKE.Name != "egressa-gw-hk" {
			t.Fatalf("event = %+v", ev)
		}
	}
	cancelOther()
	cancelOther() // idempotent
	if _, ok := <-other; ok {
		t.Fatal("cancelled subscription still open")
	}

	f.emit("child-updown", newMsg("x", ikeSAMsg(3, IKEStateEstablished, childSAMsg("x-e1", 4, "DELETING"))))
	if ev := recvEvent(t, events); ev.Kind != EventChildUpDown || ev.Up {
		t.Fatalf("child down event = %+v", ev)
	}

	// charon restarts: the event session must come back and say so.
	f.closeAll()
	if ev := recvEvent(t, events); ev.Kind != EventResync {
		t.Fatalf("after a daemon restart got %+v, want EventResync", ev)
	}
	waitFor(t, "re-registration", func() bool { return f.subscribers("ike-updown") == 1 })
	f.emit("ike-updown", newMsg("y", ikeSAMsg(8, "DELETING")))
	if ev := recvEvent(t, events); ev.IKE.Name != "y" || ev.Up {
		t.Fatalf("event after reconnect = %+v", ev)
	}

	cancel()
	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	late, lateCancel := v.Subscribe()
	if _, ok := <-late; ok {
		t.Fatal("Subscribe after Close returned an open channel")
	}
	lateCancel()
}

func TestViciIKE_Deliver_SlowReaderGetsResync(t *testing.T) {
	v := &ViciIKE{subs: map[*subscriber]struct{}{}}
	sub := &subscriber{ch: make(chan Event, 2)}
	v.subs[sub] = struct{}{}
	ev := func(name string) Event { return Event{Kind: EventIKEUpDown, IKE: IKESA{Name: name}} }
	name := func() string {
		e := <-sub.ch
		if e.Kind == EventResync {
			return "resync"
		}
		return e.IKE.Name
	}

	v.deliver(ev("e1"))
	v.deliver(ev("e2"))
	v.deliver(ev("e3")) // full: dropped, reader now owed a resync
	if !sub.lagged {
		t.Fatal("dropping an event did not mark the reader as lagged")
	}
	if got := name(); got != "e1" {
		t.Fatalf("got %s, want e1", got)
	}
	v.deliver(ev("e4")) // room for one: the resync goes first, e4 is dropped
	if got := name(); got != "e2" {
		t.Fatalf("got %s, want e2", got)
	}
	if got := name(); got != "resync" {
		t.Fatalf("got %s, want resync before anything newer", got)
	}
	if !sub.lagged {
		t.Fatal("e4 was dropped after the resync, so another resync is owed")
	}
	v.deliver(ev("e5"))
	if a, b := name(), name(); a != "resync" || b != "e5" {
		t.Fatalf("got %s, %s; want resync, e5", a, b)
	}
	v.deliver(ev("e6"))
	if got := name(); got != "e6" || sub.lagged {
		t.Fatalf("got %s (lagged=%v); a reader that kept up must get events plainly", got, sub.lagged)
	}

	// A reader that is still full when the resync is due gets nothing,
	// and stays owed the resync.
	full := &subscriber{ch: make(chan Event)} // unbuffered, nobody reading
	full.lagged = true
	v.subs = map[*subscriber]struct{}{full: {}}
	v.deliver(ev("e7"))
	if !full.lagged {
		t.Fatal("a resync that could not be delivered was forgotten")
	}
}

func TestViciIKE_Subscribe_RetriesWhileDaemonDown(t *testing.T) {
	f := newFakeCharon(t)
	v := f.newIKE(t, WithViciReconnect(5*time.Millisecond))
	f.refuseEvents() // registration refused: the listener retries
	events, cancel := v.Subscribe()
	waitFor(t, "a few registration attempts", func() bool { return f.dialCount() >= 4 })
	f.setDialErr(errors.New("down"))
	n := f.dialCount()
	waitFor(t, "dial retries", func() bool { return f.dialCount() > n+2 })
	cancel()
	if err := v.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, ok := <-events; ok {
		t.Fatal("subscription still open after Close")
	}
}
