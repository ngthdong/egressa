//go:build linux

package main

import (
	"bytes"
	"errors"
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/client"
	"github.com/ngthdong/egressa/internal/control"
)

func TestParseConnect(t *testing.T) {
	for in, want := range map[string]string{"-sg": "sg", "--sg": "sg", "sg": "sg", "-sing": "sing"} {
		if got, ip, err := parseConnect([]string{in}); err != nil || got != want || ip {
			t.Errorf("parseConnect(%q) = %q, %v, %v", in, got, ip, err)
		}
	}
	if got, ip, err := parseConnect(nil); err != nil || got != "" || ip {
		t.Errorf("no argument: %q, %v, %v", got, ip, err)
	}
	for _, args := range [][]string{{"-sg", "--ipsec"}, {"--ipsec", "sg"}, {"-ipsec", "-sg"}} {
		if got, ip, err := parseConnect(args); err != nil || got != "sg" || !ip {
			t.Errorf("parseConnect(%q) = %q, %v, %v", args, got, ip, err)
		}
	}
	if got, ip, err := parseConnect([]string{"--ipsec"}); err != nil || got != "" || !ip {
		t.Errorf("--ipsec alone: %q, %v, %v", got, ip, err)
	}
	if _, _, err := parseConnect([]string{"--"}); err == nil {
		t.Error("accepted --")
	}
	if _, _, err := parseConnect([]string{"-sg", "-sing"}); err == nil {
		t.Error("accepted two gateways")
	}
}

func TestCharonReady(t *testing.T) {
	t.Setenv("EGRESSA_VICI_SOCKET", filepath.Join(t.TempDir(), "none.vici"))
	if err := charonReady(); err == nil || !strings.Contains(err.Error(), "strongswan") {
		t.Errorf("no socket: %v", err)
	}
	sock := filepath.Join(t.TempDir(), "charon.vici")
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EGRESSA_VICI_SOCKET", sock)
	if err := charonReady(); err != nil {
		t.Errorf("with a socket: %v", err)
	}
}

func TestInvite(t *testing.T) {
	inv, err := encodeInvite("https://103-153-255-240.sslip.io", "abc123")
	if err != nil || !strings.HasPrefix(inv, invitePrefix) {
		t.Fatalf("encode: %q, %v", inv, err)
	}
	got, err := decodeInvite("  " + inv + "\n")
	if err != nil || got.Controller != "https://103-153-255-240.sslip.io" || got.Token != "abc123" {
		t.Fatalf("decode: %+v, %v", got, err)
	}
	for name, bad := range map[string]string{
		"no prefix":   "abc",
		"bad base64":  invitePrefix + "!!!",
		"not json":    invitePrefix + "bm90IGpzb24",
		"no token":    mustInvite(t, `{"c":"https://x"}`),
		"bad url":     mustInvite(t, `{"c":"ftp://x","t":"a"}`),
		"missing url": mustInvite(t, `{"t":"a"}`),
	} {
		if _, err := decodeInvite(bad); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	if _, err := encodeInvite("https://x", ""); err == nil {
		t.Error("encoded an invite without a token")
	}
	if _, err := encodeInvite("x", "t"); err == nil {
		t.Error("encoded an invite with a bad URL")
	}
}

func mustInvite(t *testing.T, payload string) string {
	t.Helper()
	return invitePrefix + b64(payload)
}

func TestConf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "client.conf")
	if _, err := readConf(path); !errors.Is(err, errNotJoined) {
		t.Fatalf("missing conf: %v", err)
	}
	want := conf{Controller: "https://ctl", Token: "s3cr3t", Egress: "sg", LogFormat: "json",
		Bypass: []netip.Addr{netip.MustParseAddr("198.51.100.7")}}
	if err := writeConf(path, want); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("conf mode %v, %v; it holds the token", fi.Mode(), err)
	}
	got, err := readConf(path)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("read %+v, %v", got, err)
	}
	if err := os.WriteFile(path, []byte(`{"controller":"https://ctl"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConf(path); err == nil {
		t.Error("read a conf with no token")
	}
	if err := os.WriteFile(path, []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readConf(path); err == nil {
		t.Error("read a corrupt conf")
	}
}

var testGateways = []api.Gateway{
	{ID: "eu", Roles: control.RoleEgress, Endpoint: "192.0.2.13:51820", Alive: true},
	{ID: "relay", Roles: control.RoleAccess, Endpoint: "192.0.2.14:51820", Alive: true},
	{ID: "sg", Roles: control.RoleAccess | control.RoleEgress, Endpoint: "203.0.113.11:51820", Alive: true},
	{ID: "sing", Roles: control.RoleAccess | control.RoleEgress, Endpoint: "203.0.113.12:51820", Alive: false},
}

func TestCheckEgressAndChooseAccess(t *testing.T) {
	if err := checkEgress(testGateways, "sg"); err != nil {
		t.Errorf("sg: %v", err)
	}
	for id, want := range map[string]string{"nope": "no gateway", "relay": "does not lead", "sing": "down"} {
		if err := checkEgress(testGateways, id); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", id, err)
		}
	}
	if got := chooseAccess(testGateways, "sg", "sing"); got != "sg" {
		t.Errorf("to sg: access %q, want sg itself", got)
	}
	if got := chooseAccess(testGateways, "eu", "sing"); got != "sing" {
		t.Errorf("to egress-only eu: access %q, want the current one", got)
	}
}

func TestPrintGatewaysAndStatus(t *testing.T) {
	var buf bytes.Buffer
	printGateways(&buf, testGateways)
	out := buf.String()
	for _, want := range []string{"egressa connect -sg", "DOWN", "203.0.113.11", "relay"} {
		if !strings.Contains(out, want) {
			t.Errorf("gateway list lacks %q:\n%s", want, out)
		}
	}

	buf.Reset()
	st := client.Status{
		Started: time.Now(), Updated: time.Now(), SessionID: "42", VirtualIP: netip.MustParseAddr("10.201.0.2").String(),
		Access: "sing", Egress: "sg", EgressIP: "203.0.113.11", Epoch: 3, ControllerUp: true,
		Paths: []client.StatusPath{
			{Access: "sg", Egress: "sg", CostMS: 82.4, Usable: true, Reachable: true},
			{Access: "sing", Egress: "sg", CostMS: 95.9, Usable: true, Reachable: true, Active: true},
			{Access: "sing", Egress: "sing", CostMS: 50, Usable: true, Reachable: true},
		},
	}
	printStatus(&buf, st)
	out = strings.Join(strings.Fields(buf.String()), " ") // tabwriter pads with spaces
	for _, want := range []string{"Connected since", "Leaving from: sg (gateway 203.0.113.11)", "Entering at: sing", "Encryption: WireGuard", "Path changes: 2", "* via sing 95.9 ms", "direct 82.4 ms"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "50.0 ms") {
		t.Errorf("status shows a path to another egress:\n%s", out)
	}
	st.CurrentDead, st.ControllerUp, st.Backend = true, false, "ipsec"
	buf.Reset()
	printStatus(&buf, st)
	if !strings.Contains(buf.String(), "not answering") || !strings.Contains(buf.String(), "controller unreachable") ||
		!strings.Contains(buf.String(), "IPsec to the entry gateway") {
		t.Errorf("degraded IPsec status:\n%s", buf.String())
	}
}

func TestStatusAndDisconnectWhenNotRunning(t *testing.T) {
	t.Setenv("EGRESSA_STATUS", filepath.Join(t.TempDir(), "status.json"))
	var buf bytes.Buffer
	if err := cmdStatus(&buf); err != nil || !strings.Contains(buf.String(), "Not connected") {
		t.Fatalf("status: %q, %v", buf.String(), err)
	}
	if err := (process{}).Stop(); err == nil {
		t.Error("stopped a client that is not running")
	}
}

func TestUnitFile(t *testing.T) {
	u := unitFile("/usr/local/bin/egressa")
	if !strings.Contains(u, "ExecStart=/usr/local/bin/egressa run\n") || !strings.Contains(u, "Restart=on-failure") {
		t.Errorf("unit:\n%s", u)
	}
}

func b64(s string) string { return base64RawURL(s) }

func TestFlagGiven(t *testing.T) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.String("log-format", "text", "")
	fs.String("log-level", "info", "")
	if err := fs.Parse([]string{"--log-level", "debug"}); err != nil {
		t.Fatal(err)
	}
	if flagGiven(fs, "log-format") || !flagGiven(fs, "log-level") {
		t.Error("flagGiven")
	}
}
