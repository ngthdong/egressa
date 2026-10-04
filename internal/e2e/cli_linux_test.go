//go:build linux

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestEgressaCLI runs the commands a user types: join with an invite,
// connect to a gateway by name, look at the status, move to another
// gateway, disconnect. The background client runs as a detached process
// (EGRESSA_SERVICE=process): the namespaces have no systemd.
func TestEgressaCLI(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: end-to-end test")
	}
	if os.Getenv(envChild) != "1" {
		reexec(t)
		return
	}
	bin := os.Getenv(envBinDir)
	dir := t.TempDir()
	setupTopology(t)

	tokens := []string{"EGRESSA_GATEWAY_TOKEN=gw-secret", "EGRESSA_CLIENT_TOKEN=cl-secret"}
	ctlURL := "http://" + ctlAddr + ":8080"
	start(t, dir, "controller", "", tokens, bin+"/controller", "--listen", ctlAddr+":8080")
	waitHTTP(t, ctlURL+"/healthz")
	for _, gw := range []struct{ id, wan string }{{"hk", hkWAN}, {"sg", sgWAN}} {
		start(t, dir, "gateway-"+gw.id, gw.id, tokens, bin+"/gateway",
			"--id", gw.id, "--controller", ctlURL, "--role", "access,egress",
			"--endpoint", gw.wan+":51820", "--uplink", "inet0",
			"--private-key-file", filepath.Join(dir, gw.id+".key"))
	}
	waitLog(t, dir, "gateway-hk", "msg=ready", 20*time.Second)
	waitLog(t, dir, "gateway-sg", "msg=ready", 20*time.Second)
	stopEcho := runEchoServer(t)
	defer stopEcho()

	env := []string{
		"EGRESSA_CONF=" + filepath.Join(dir, "client.conf"),
		"EGRESSA_STATE=" + filepath.Join(dir, "client.json"),
		"EGRESSA_STATUS=" + filepath.Join(dir, "run", "status.json"),
		"EGRESSA_LOG=" + filepath.Join(dir, "egressa.log"),
		"EGRESSA_SERVICE=process",
	}
	egressa := func(args ...string) (string, error) {
		cmd := exec.Command("nsenter", append([]string{"--net=/run/netns/cli", "--", bin + "/egressa"}, args...)...)
		cmd.Env = append(os.Environ(), env...)
		out, err := cmd.CombinedOutput()
		t.Logf("$ egressa %s\n%s", strings.Join(args, " "), out)
		return string(out), err
	}
	must := func(args ...string) string {
		t.Helper()
		out, err := egressa(args...)
		if err != nil {
			t.Fatalf("egressa %s: %v", strings.Join(args, " "), err)
		}
		return strings.Join(strings.Fields(out), " ")
	}
	// Whatever happens, leave no client running in the namespace.
	t.Cleanup(func() {
		_, _ = egressa("disconnect")
		if t.Failed() {
			data, _ := os.ReadFile(filepath.Join(dir, "egressa.log"))
			t.Logf("=== egressa run log ===\n%s", tail(string(data), 60))
		}
	})
	exitIP := func() string {
		c := dialFrom(t, "cli", fmt.Sprintf("%s:%d", srvInet, echoPort))
		defer func() { _ = c.Close() }()
		return remoteOf(t, c)
	}

	// The admin makes an invite; the user joins with it.
	invCmd := exec.Command(bin+"/egressa", "invite", "--controller", ctlURL) // token from $EGRESSA_CLIENT_TOKEN
	invCmd.Env = append(os.Environ(), "EGRESSA_CLIENT_TOKEN=cl-secret")
	inv, err := invCmd.Output()
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	invite := strings.TrimSpace(string(inv))
	if out := must("join", invite); !strings.Contains(out, "egressa connect -hk") || !strings.Contains(out, "sg") {
		t.Fatalf("join output: %s", out)
	}
	if _, err := egressa("join", "egressa1.garbage"); err == nil {
		t.Error("joined with a damaged invite")
	}

	if out := must("status"); out != "Not connected." {
		t.Fatalf("status before connect: %s", out)
	}
	if out, err := egressa("connect", "-nope"); err == nil || !strings.Contains(out, `no gateway "nope"`) {
		t.Fatalf("connect to an unknown gateway: %v", err)
	}

	// Connect, leaving from hk.
	if out := must("connect", "-hk"); !strings.Contains(out, "Leaving from: hk (gateway "+hkWAN+")") {
		t.Fatalf("connect -hk output: %s", out)
	}
	if got := exitIP(); got != hkInet {
		t.Fatalf("after connect -hk the Internet sees %s, want hk's %s", got, hkInet)
	}
	if out := must("status"); !strings.Contains(out, "Leaving from: hk") || !strings.Contains(out, "Paths to hk:") {
		t.Fatalf("status: %s", out)
	}
	if out := must("list"); !strings.Contains(out, "egressa connect -sg") {
		t.Fatalf("list: %s", out)
	}
	// connect again with nothing new is a no-op that shows the status.
	if out := must("connect"); !strings.Contains(out, "Leaving from: hk") {
		t.Fatalf("second connect: %s", out)
	}

	// Move to sg: the same session and virtual IP, a new exit.
	before := must("status")
	if out := must("connect", "-sg"); !strings.Contains(out, "Leaving from: sg") {
		t.Fatalf("connect -sg output: %s", out)
	}
	if got := exitIP(); got != sgInet {
		t.Fatalf("after connect -sg the Internet sees %s, want sg's %s", got, sgInet)
	}
	after := must("status")
	vip := func(s string) string {
		_, rest, _ := strings.Cut(s, "Virtual IP: ")
		v, _, _ := strings.Cut(rest, " ")
		return v
	}
	if vip(before) == "" || vip(before) != vip(after) {
		t.Errorf("the virtual IP changed from %q to %q; the session should have moved, not been replaced", vip(before), vip(after))
	}

	// Disconnect restores the namespace's routing.
	if out := must("disconnect"); out != "Disconnected." {
		t.Fatalf("disconnect: %s", out)
	}
	if out := must("status"); out != "Not connected." {
		t.Fatalf("status after disconnect: %s", out)
	}
	if out, _ := nsRun("cli", "ip", "route", "show", "default"); strings.Contains(out, "egressa0") {
		t.Errorf("the default route still uses the tunnel:\n%s", out)
	}
	if out := must("disconnect"); out != "Not connected." {
		t.Errorf("second disconnect: %s", out)
	}
}
