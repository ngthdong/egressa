//go:build linux

package e2e

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	envCharon        = "EGRESSA_CHARON"
	envCharonPreload = "EGRESSA_CHARON_PRELOAD"
)

// findCharon returns charon's path, or skips.
func findCharon(t *testing.T) string {
	t.Helper()
	if p := os.Getenv(envCharon); p != "" {
		return p
	}
	for _, p := range []string{"/usr/lib/ipsec/charon", "/usr/libexec/ipsec/charon", "/usr/lib/strongswan/charon", "/usr/libexec/strongswan/charon"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("skipping: no charon (install strongswan-charon and strongswan-swanctl, or set " + envCharon + ")")
	return ""
}

// startCharon runs a charon in network namespace ns, in a mount namespace
// of its own with a fresh /run, its vici socket in dir. It returns the
// socket's path.
func startCharon(t *testing.T, charon, dir, ns string) string {
	t.Helper()
	d := filepath.Join(dir, "charon-"+ns)
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	socket, logf, conf := filepath.Join(d, "c.vici"), filepath.Join(d, "charon.log"), filepath.Join(d, "strongswan.conf")
	writeFile(t, conf, fmt.Sprintf(`charon {
  load_modular = yes
  install_routes = no
  install_virtual_ip = no
  retransmit_timeout = 1.0
  retransmit_tries = 2
  retransmit_base = 1.4
  plugins {
    include /etc/strongswan.d/charon/*.conf
    vici {
      load = yes
      socket = unix://%s
    }
  }
  filelog {
    egressa {
      path = %s
      default = 1
      time_format = %%T
      flush_line = yes
    }
  }
}
`, socket, logf))
	script := `mount -t tmpfs tmpfs /run && exec "$0"`
	args := []string{charon}
	if p := os.Getenv(envCharonPreload); p != "" {
		script = `mount -t tmpfs tmpfs /run && export LD_PRELOAD="$1" && exec "$0"`
		args = append(args, p)
	}
	cmd := exec.Command("nsenter", append([]string{"--net=/run/netns/" + ns, "--", "unshare", "-m", "--", "sh", "-c", script}, args...)...)
	cmd.Env = append(os.Environ(), "STRONGSWAN_CONF="+conf)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start charon in %s: %v", ns, err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
		}
		if t.Failed() {
			data, _ := os.ReadFile(logf)
			t.Logf("=== charon %s log ===\n%s", ns, tail(string(data), 40))
		}
	})
	deadline := time.Now().Add(15 * time.Second)
	for {
		if c, err := net.Dial("unix", socket); err == nil {
			_ = c.Close()
			return socket
		}
		data, _ := os.ReadFile(logf)
		if strings.Contains(string(data), "loaded plugins:") && !strings.Contains(string(data), " vici") {
			t.Skipf("skipping: charon runs without the vici plugin (it ships in strongswan-swanctl; or set %s)", envCharonPreload)
		}
		select {
		case err := <-exited:
			var ee *exec.ExitError
			if errors.As(err, &ee) && ee.ExitCode() == 64 {
				t.Skip("skipping: charon refused to start (exit 64): an AppArmor profile in enforce mode " +
					"probably confines it; set " + envCharon + " to a copy of charon, or relax the profile")
			}
			t.Fatalf("charon in %s exited: %v\n%s", ns, err, data)
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("charon in %s never opened its vici socket\n%s", ns, data)
		}
	}
}

// TestIPsecAccess runs a client whose hop to its access gateway is IPsec
// (`egressa connect --ipsec`), through real charons in the client and both
// gateways; the gateways still carry the session between them over their
// WireGuard backbone. It checks the traffic really is ESP, that the
// client moves its entry gateway over IPsec without breaking a TCP
// connection or changing its exit, that it can change exit, and that
// connecting without --ipsec goes back to WireGuard with the same
// session.
func TestIPsecAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: end-to-end test")
	}
	if os.Getenv(envChild) != "1" {
		reexec(t)
		return
	}
	bin := os.Getenv(envBinDir)
	charon := findCharon(t)
	dir := t.TempDir()
	setupTopology(t)
	vici := map[string]string{}
	for _, ns := range []string{"hk", "sg", "cli"} {
		vici[ns] = startCharon(t, charon, dir, ns)
	}

	tokens := []string{"EGRESSA_GATEWAY_TOKEN=gw-secret", "EGRESSA_CLIENT_TOKEN=cl-secret",
		"EGRESSA_IPSEC_KEY=0123456789abcdef0123456789abcdef-ipsec-master"}
	policy := filepath.Join(dir, "policy.json")
	writeFile(t, policy, `{"version": 1,
		"decision": {"Z": 1.645, "MigrationCost": 5000, "SafetyMargin": 5000},
		"flap_guard": {"ConfirmationWindow": 2000000000, "MinResidence": 4000000000, "Cooldown": 2000000000}}`)
	ctlURL := "http://" + ctlAddr + ":8080"
	start(t, dir, "controller", "", tokens, bin+"/controller", "--listen", ctlAddr+":8080", "--policy", policy)
	waitHTTP(t, ctlURL+"/healthz")
	for _, gw := range []struct{ id, wan string }{{"hk", hkWAN}, {"sg", sgWAN}} {
		start(t, dir, "gateway-"+gw.id, gw.id, tokens, bin+"/gateway",
			"--id", gw.id, "--controller", ctlURL, "--role", "access,egress",
			"--endpoint", gw.wan+":51820", "--uplink", "inet0",
			"--private-key-file", filepath.Join(dir, gw.id+".key"),
			"--ipsec", "--vici-socket", vici[gw.id])
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
		"EGRESSA_VICI_SOCKET=" + vici["cli"],
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
	status := func() string { return must("status") }

	invCmd := exec.Command(bin+"/egressa", "invite", "--controller", ctlURL)
	invCmd.Env = append(os.Environ(), "EGRESSA_CLIENT_TOKEN=cl-secret")
	inv, err := invCmd.Output()
	if err != nil {
		t.Fatalf("invite: %v", err)
	}
	if out := must("join", strings.TrimSpace(string(inv))); !strings.Contains(out, "IPSEC") {
		t.Fatalf("join output: %s", out)
	}

	// 1. Connect over IPsec, leaving from hk.
	if out := must("connect", "-hk", "--ipsec"); !strings.Contains(out, "Encryption: IPsec") || !strings.Contains(out, "Leaving from: hk") {
		t.Fatalf("connect --ipsec: %s", out)
	}
	if got := exitIP(); got != hkInet {
		t.Fatalf("over IPsec the Internet sees %s, want hk's %s", got, hkInet)
	}
	// The traffic is ESP: the client's kernel holds ESP states, and there
	// is no WireGuard interface.
	if out, _ := nsRun("cli", "ip", "xfrm", "state"); !strings.Contains(out, "proto esp") {
		t.Fatalf("no ESP state on the client:\n%s", out)
	}
	if _, err := nsRun("cli", "ip", "link", "show", "egressa0"); err == nil {
		t.Fatal("a WireGuard interface exists in IPsec mode")
	}
	vip := func(s string) string {
		_, r, _ := strings.Cut(s, "Virtual IP: ")
		v, _, _ := strings.Cut(r, " ")
		return v
	}
	firstVIP := vip(status())

	// 2. The direct path to hk degrades: the client enters through sg
	// instead (IPsec to sg, the backbone to hk), keeping its exit and its
	// open connection.
	conn := dialFrom(t, "cli", fmt.Sprintf("%s:%d", srvInet, echoPort))
	defer func() { _ = conn.Close() }()
	pinger := startPinger(t, conn)
	impair(t, "cli", hkWAN, "delay 150ms")
	impair(t, "hk", cliWAN, "delay 150ms")
	deadline := time.Now().Add(60 * time.Second)
	for !strings.Contains(status(), "Entering at: sg") {
		if time.Now().After(deadline) {
			t.Fatalf("the client never moved its IPsec entry to sg: %s", status())
		}
		time.Sleep(time.Second)
	}
	pinger.check(t, "after moving the IPsec entry to sg")
	expectRTT(t, conn, "via sg over IPsec", 0, 100*time.Millisecond)
	if got := remoteOf(t, conn); got != hkInet {
		t.Fatalf("after the move the connection leaves from %s, want hk's %s", got, hkInet)
	}
	if out := status(); !strings.Contains(out, "Leaving from: hk") || !strings.Contains(out, "Encryption: IPsec") {
		t.Fatalf("status after the move: %s", out)
	}
	pinger.stop()
	impair(t, "cli", hkWAN, "delay 0ms")
	impair(t, "hk", cliWAN, "delay 0ms")

	// 3. Change exit to sg, still over IPsec.
	if out := must("connect", "-sg", "--ipsec"); !strings.Contains(out, "Leaving from: sg") {
		t.Fatalf("connect -sg --ipsec: %s", out)
	}
	if got := exitIP(); got != sgInet {
		t.Fatalf("after connect -sg the Internet sees %s, want sg's %s", got, sgInet)
	}

	// 4. Without --ipsec: back to WireGuard, same session and virtual IP.
	if out := must("connect", "-hk"); !strings.Contains(out, "Encryption: WireGuard") || !strings.Contains(out, "Leaving from: hk") {
		t.Fatalf("connect -hk without --ipsec: %s", out)
	}
	if got := exitIP(); got != hkInet {
		t.Fatalf("over WireGuard the Internet sees %s, want hk's %s", got, hkInet)
	}
	if v := vip(status()); v != firstVIP {
		t.Errorf("the virtual IP changed from %s to %s across the switch", firstVIP, v)
	}
	if out, _ := nsRun("cli", "ip", "-br", "link"); slices.ContainsFunc(strings.Split(out, "\n"), func(l string) bool { return strings.HasPrefix(l, "egx") }) {
		t.Errorf("IPsec interfaces left after switching to WireGuard:\n%s", out)
	}

	if out := must("disconnect"); out != "Disconnected." {
		t.Fatalf("disconnect: %s", out)
	}
}
