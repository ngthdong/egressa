//go:build linux

// Package e2e runs the real controller, gateway and client binaries in
// separate network namespaces and checks the whole system: a client's
// session moves to a better path as links degrade, keeps its egress, and
// keeps its open TCP connections across every move.
//
// It needs root, or unprivileged user namespaces: without root the test
// re-executes itself under `unshare -Urnm`, where it is root over a fresh
// network namespace of its own. Nothing outside that namespace changes.
package e2e

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netns"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/client"
)

const (
	envChild  = "EGRESSA_E2E_CHILD"
	envBinDir = "EGRESSA_E2E_BIN"

	ctlAddr  = "192.0.2.1"
	hkWAN    = "192.0.2.11"
	sgWAN    = "192.0.2.12"
	cliWAN   = "192.0.2.100"
	hkInet   = "203.0.113.11"
	sgInet   = "203.0.113.12"
	srvInet  = "203.0.113.10"
	echoPort = 7000
)

// TestManagedMigration is the end-to-end proof:
//
//	               192.0.2.0/24 ("WAN", bridge wan)
//	controller ──┬──────────────┬──────────────┬─────── client (cli)
//	(this ns)    │              │              │        only reaches the
//	            hk ═backbone═  sg              │        Internet via VPN
//	             │              │
//	           203.0.113.0/24 ("Internet", bridge inet) ── srv (TCP echo)
//
// hk and sg are both access and egress gateways. The client opens its
// session with egress hk, so every connection to srv must come from hk's
// Internet address, whatever the access gateway is.
func TestManagedMigration(t *testing.T) {
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
	policy := filepath.Join(dir, "policy.json")
	writeFile(t, policy, `{
		"version": 1,
		"cost": {"TailWeight": 1, "LossWeight": 995033, "LossGate": 0.2, "MaxCapacityFraction": 0.9},
		"decision": {"Z": 1.645, "MigrationCost": 5000, "SafetyMargin": 5000},
		"flap_guard": {"ConfirmationWindow": 2000000000, "MinResidence": 4000000000, "Cooldown": 2000000000}
	}`)
	ctlURL := "http://" + ctlAddr + ":8080"
	start(t, dir, "controller", "", tokens, bin+"/controller", "--listen", ctlAddr+":8080", "--policy", policy)
	waitHTTP(t, ctlURL+"/healthz")
	for _, gw := range []struct{ id, wan string }{{"hk", hkWAN}, {"sg", sgWAN}} {
		start(t, dir, "gateway-"+gw.id, gw.id, tokens, bin+"/gateway",
			"--id", gw.id, "--controller", ctlURL, "--role", "access,egress",
			"--endpoint", gw.wan+":51820", "--uplink", "inet0",
			"--private-key-file", filepath.Join(dir, gw.id+".key"))
	}
	waitLog(t, dir, "gateway-hk", "ready", 20*time.Second)
	waitLog(t, dir, "gateway-sg", "ready", 20*time.Second)

	stopEcho := runEchoServer(t)
	defer stopEcho()

	stateFile := filepath.Join(dir, "client.json")
	start(t, dir, "client", "cli", tokens, bin+"/client",
		"--controller", ctlURL, "--state-file", stateFile, "--egress", "hk", "--full-tunnel")
	waitLog(t, dir, "client", "client: ready", 20*time.Second)

	st, _, err := client.LoadState(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	ctl, err := api.NewClient(ctlURL, "")
	if err != nil {
		t.Fatal(err)
	}
	session := func() api.Session {
		cs, err := ctl.ClientState(context.Background(), st.SessionID, st.Secret, 0, 0)
		if err != nil {
			t.Fatalf("read the session: %v", err)
		}
		return cs.Session
	}
	waitPath := func(what, access string, epoch uint64, timeout time.Duration) {
		t.Helper()
		begin := time.Now()
		deadline := begin.Add(timeout)
		for time.Now().Before(deadline) {
			s := session()
			if s.Access == access && s.Epoch == epoch {
				if s.Egress != "hk" {
					t.Fatalf("%s: egress changed to %s", what, s.Egress)
				}
				t.Logf("%s: access %s, egress %s, epoch %d after %s", what, s.Access, s.Egress, s.Epoch, time.Since(begin).Round(100*time.Millisecond))
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		dumpState(t)
		t.Fatalf("%s: session is %+v after %s, want access %s at epoch %d", what, session(), timeout, access, epoch)
	}

	s := session()
	if s.Access != "hk" || s.Egress != "hk" || s.Epoch != 1 {
		t.Fatalf("first path %+v, want hk/hk at epoch 1", s)
	}

	// One long-lived TCP connection through the VPN, kept busy for the
	// whole test. It must survive every migration.
	conn := dialFrom(t, "cli", fmt.Sprintf("%s:%d", srvInet, echoPort))
	defer func() { _ = conn.Close() }()
	pinger := startPinger(t, conn)
	if got := remoteOf(t, conn); got != hkInet {
		t.Fatalf("the Internet saw the client as %s, want hk's %s", got, hkInet)
	}

	// 1. The direct path to hk degrades: 150 ms each way. The client
	// must move to the detour through sg, keeping egress hk.
	impair(t, "cli", hkWAN, "delay 150ms")
	impair(t, "hk", cliWAN, "delay 150ms")
	waitPath("direct path degraded", "sg", 2, 60*time.Second)
	pinger.check(t, "after moving to sg")
	// The data really takes the detour: the direct path's 300 ms RTT is
	// gone from the connection.
	expectRTT(t, conn, "via sg", 0, 100*time.Millisecond)
	if got := remoteOf(t, conn); got != hkInet {
		t.Fatalf("after the move the connection's source is %s, want %s", got, hkInet)
	}
	fresh := dialFrom(t, "cli", fmt.Sprintf("%s:%d", srvInet, echoPort))
	if got := remoteOf(t, fresh); got != hkInet {
		t.Fatalf("a new connection through sg left from %s, want egress hk's %s", got, hkInet)
	}
	_ = fresh.Close()

	// 2. The direct path recovers and the backbone sg<->hk degrades
	// instead: the detour now costs the backbone's 200 ms RTT, so the
	// client must go back to hk.
	impair(t, "cli", hkWAN, "delay 0ms")
	impair(t, "hk", cliWAN, "delay 0ms")
	impair(t, "sg", hkWAN, "delay 100ms")
	impair(t, "hk", sgWAN, "delay 100ms")
	waitPath("backbone degraded", "hk", 3, 60*time.Second)
	pinger.check(t, "after moving back to hk")
	expectRTT(t, conn, "direct to hk", 0, 100*time.Millisecond)

	// 3. The trap. The direct path is a bit worse (80 ms RTT) and the
	// client reaches sg fastest, but the end-to-end detour pays the
	// backbone's 200 ms. It must stay.
	impair(t, "cli", hkWAN, "delay 40ms")
	impair(t, "hk", cliWAN, "delay 40ms")
	time.Sleep(20 * time.Second)
	if s := session(); s.Access != "hk" || s.Epoch != 3 {
		t.Fatalf("took the detour through a slow backbone: %+v", s)
	}
	t.Logf("backbone trap: stayed on hk for 20 s, as it should")
	pinger.check(t, "while staying on hk")

	// 4. The direct path dies. The client must cut over at once, flap
	// guard or not, still keeping egress hk.
	impair(t, "cli", hkWAN, "loss 100%")
	impair(t, "hk", cliWAN, "loss 100%")
	waitPath("direct path dead", "sg", 4, 20*time.Second)
	// Now through sg and the slow backbone: about its 200 ms RTT.
	expectRTT(t, conn, "via sg over the slow backbone", 180*time.Millisecond, 400*time.Millisecond)
	pinger.check(t, "after hk's direct path died")

	t.Logf("the connection made %d round trips; the longest wait for one was %s",
		pinger.count(), pinger.longestGap().Round(10*time.Millisecond))
	pinger.stop()

	// Gateways remove what they installed when they stop.
	stopProcess(t, "client")
	stopProcess(t, "gateway-hk")
	out, _ := nsRun("hk", "ip", "rule", "show")
	if strings.Contains(out, "lookup 1000") || strings.Contains(out, "lookup 100 ") {
		t.Errorf("hk left rules behind:\n%s", out)
	}
	out, _ = nsRun("hk", "iptables", "-t", "nat", "-S", "POSTROUTING")
	if strings.Contains(out, "MASQUERADE") {
		t.Errorf("hk left NAT behind:\n%s", out)
	}
}

// --- harness ---

func reexec(t *testing.T) {
	root, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Skipf("skipping: no go toolchain: %v", err)
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("skipping: unshare(1) not found")
	}
	for _, tool := range []string{"ip", "tc", "iptables", "nsenter"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("skipping: %s not found", tool)
		}
	}
	args := []string{"-nm"}
	if os.Geteuid() != 0 {
		args = []string{"-Urnm"}
	}
	if out, err := exec.Command("unshare", append(args, "true")...).CombinedOutput(); err != nil {
		t.Skipf("skipping: cannot create namespaces here (%v: %s)", err, strings.TrimSpace(string(out)))
	}

	bin := t.TempDir()
	build := exec.Command("go", "build", "-o", bin+"/", "./cmd/controller", "./cmd/gateway", "./cmd/client")
	build.Dir = filepath.Dir(strings.TrimSpace(string(root)))
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the binaries: %v\n%s", err, out)
	}

	cmd := exec.Command("unshare", append(args, os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v", "-test.count=1", "-test.timeout=10m")...)
	cmd.Env = append(os.Environ(), envChild+"=1", envBinDir+"="+bin)
	out, err := cmd.CombinedOutput()
	t.Logf("re-executed in fresh namespaces:\n%s", out)
	if err != nil {
		t.Fatalf("child test failed: %v", err)
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Skip("child test skipped (see log above)")
	}
}

func sh(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func nsRun(ns string, args ...string) (string, error) {
	out, err := exec.Command("nsenter", append([]string{"--net=/run/netns/" + ns, "--"}, args...)...).CombinedOutput()
	return string(out), err
}

func nsSh(t *testing.T, ns string, args ...string) {
	t.Helper()
	if out, err := nsRun(ns, args...); err != nil {
		t.Fatalf("[%s] %s: %v\n%s", ns, strings.Join(args, " "), err, out)
	}
}

// setupTopology builds the namespaces and links in the picture above.
func setupTopology(t *testing.T) {
	// A private /run/netns: `ip netns` needs one, and this mount
	// namespace is ours alone.
	if _, err := os.Stat("/run/netns"); err != nil {
		sh(t, "mount", "-t", "tmpfs", "tmpfs", "/run")
		if err := os.MkdirAll("/run/netns", 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sh(t, "mount", "-t", "tmpfs", "tmpfs", "/run/netns")
	sh(t, "ip", "link", "set", "lo", "up")
	if out, err := exec.Command("tc", "qdisc", "add", "dev", "lo", "root", "netem", "delay", "0ms").CombinedOutput(); err != nil {
		t.Skipf("skipping: this kernel cannot load netem (sch_netem): %v: %s", err, strings.TrimSpace(string(out)))
	}
	sh(t, "tc", "qdisc", "del", "dev", "lo", "root")
	for _, br := range []string{"wan", "inet"} {
		sh(t, "ip", "link", "add", br, "type", "bridge")
		sh(t, "ip", "link", "set", br, "up")
	}
	sh(t, "ip", "addr", "add", ctlAddr+"/24", "dev", "wan")

	link := func(ns, dev, bridge, addr string) {
		host := ns + "-" + dev
		sh(t, "ip", "link", "add", host, "type", "veth", "peer", "name", dev, "netns", ns)
		sh(t, "ip", "link", "set", host, "master", bridge)
		sh(t, "ip", "link", "set", host, "up")
		nsSh(t, ns, "ip", "addr", "add", addr+"/24", "dev", dev)
		nsSh(t, ns, "ip", "link", "set", dev, "up")
	}
	for _, ns := range []string{"hk", "sg", "cli", "srv"} {
		sh(t, "ip", "netns", "add", ns)
		nsSh(t, ns, "ip", "link", "set", "lo", "up")
	}
	link("hk", "wan0", "wan", hkWAN)
	link("sg", "wan0", "wan", sgWAN)
	link("cli", "wan0", "wan", cliWAN)
	link("hk", "inet0", "inet", hkInet)
	link("sg", "inet0", "inet", sgInet)
	link("srv", "inet0", "inet", srvInet)

	// Per-destination impairment on each WAN link: a prio qdisc whose
	// two extra bands (1:4, 1:5) each hold a netem, picked by a filter
	// on the destination address. impair() changes the netem.
	for ns, dsts := range map[string][]string{"cli": {hkWAN, sgWAN}, "hk": {cliWAN, sgWAN}, "sg": {cliWAN, hkWAN}} {
		nsSh(t, ns, "tc", "qdisc", "add", "dev", "wan0", "root", "handle", "1:", "prio", "bands", "5",
			"priomap", "1", "2", "2", "2", "1", "2", "0", "0", "1", "1", "1", "1", "1", "1", "1", "1")
		for i, dst := range dsts {
			band := fmt.Sprintf("1:%d", 4+i)
			nsSh(t, ns, "tc", "qdisc", "add", "dev", "wan0", "parent", band, "handle", fmt.Sprintf("%d:", 40+i), "netem", "delay", "0ms")
			nsSh(t, ns, "tc", "filter", "add", "dev", "wan0", "parent", "1:", "protocol", "ip", "prio", "1",
				"u32", "match", "ip", "dst", dst+"/32", "flowid", band)
			impairHandles[ns+">"+dst] = fmt.Sprintf("%d:", 40+i)
			impairParents[ns+">"+dst] = band
		}
	}
}

// dumpState logs each node's network state, for a failure.
func dumpState(t *testing.T) {
	for _, ns := range []string{"hk", "sg", "cli"} {
		for _, cmd := range [][]string{
			{"ip", "-s", "link"}, {"ip", "rule"}, {"ip", "route", "show", "table", "all"}, {"ss", "-uanp"},
		} {
			out, _ := nsRun(ns, cmd...)
			t.Logf("[%s] %s:\n%s", ns, strings.Join(cmd, " "), out)
		}
	}
}

var (
	impairHandles = map[string]string{}
	impairParents = map[string]string{}
)

// impair sets what ns's packets to dst go through, e.g. "delay 150ms".
func impair(t *testing.T, ns, dst, netem string) {
	t.Helper()
	key := ns + ">" + dst
	args := append([]string{"tc", "qdisc", "change", "dev", "wan0", "parent", impairParents[key], "handle", impairHandles[key], "netem"}, strings.Fields(netem)...)
	nsSh(t, ns, args...)
}

var procs sync.Map // name -> *exec.Cmd

func start(t *testing.T, dir, name, ns string, env []string, argv ...string) {
	t.Helper()
	logf, err := os.Create(filepath.Join(dir, name+".log"))
	if err != nil {
		t.Fatal(err)
	}
	if ns != "" {
		argv = append([]string{"nsenter", "--net=/run/netns/" + ns, "--"}, argv...)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	procs.Store(name, cmd)
	t.Cleanup(func() {
		stopProcess(t, name)
		_ = logf.Close()
		if t.Failed() || os.Getenv("EGRESSA_E2E_LOGS") == "1" {
			data, _ := os.ReadFile(logf.Name())
			t.Logf("=== %s log ===\n%s", name, tail(string(data), 80))
		}
	})
}

func stopProcess(t *testing.T, name string) {
	v, ok := procs.LoadAndDelete(name)
	if !ok {
		return
	}
	cmd := v.(*exec.Cmd)
	_ = cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Errorf("%s did not stop on SIGTERM", name)
		_ = cmd.Process.Kill()
		<-done
	}
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func waitLog(t *testing.T, dir, name, needle string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(filepath.Join(dir, name+".log"))
		if strings.Contains(string(data), needle) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	data, _ := os.ReadFile(filepath.Join(dir, name+".log"))
	t.Fatalf("%s did not log %q within %s:\n%s", name, needle, timeout, tail(string(data), 40))
}

func waitHTTP(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c := net.Dialer{Timeout: time.Second}
		if conn, err := c.Dial("tcp", strings.TrimPrefix(strings.TrimSuffix(url, "/healthz"), "http://")); err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s never came up", url)
}

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// inNS runs f on a thread switched into network namespace ns, so
// sockets f creates live there.
func inNS(t *testing.T, ns string, f func()) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = orig.Close() }()
	h, err := netns.GetFromName(ns)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	if err := netns.Set(h); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := netns.Set(orig); err != nil {
			panic(err) // this thread must not run anything else in ns
		}
	}()
	f()
}

// The echo server answers "who" with the address the connection came
// from, and echoes every other line.
func runEchoServer(t *testing.T) (stop func()) {
	var ln net.Listener
	inNS(t, "srv", func() {
		var err error
		ln, err = net.Listen("tcp", fmt.Sprintf("%s:%d", srvInet, echoPort))
		if err != nil {
			t.Fatal(err)
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				r := bufio.NewReader(c)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if line == "who\n" {
						host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
						line = host + "\n"
					}
					if _, err := io.WriteString(c, line); err != nil {
						return
					}
				}
			}()
		}
	}()
	return func() { _ = ln.Close() }
}

type lineConn struct {
	mu sync.Mutex
	net.Conn
	r *bufio.Reader
}

func dialFrom(t *testing.T, ns, addr string) *lineConn {
	t.Helper()
	var c net.Conn
	inNS(t, ns, func() {
		var err error
		c, err = net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			t.Fatalf("dial %s from %s: %v", addr, ns, err)
		}
	})
	return &lineConn{Conn: c, r: bufio.NewReader(c)}
}

func (c *lineConn) roundTrip(line string, timeout time.Duration) (string, error) {
	got, _, err := c.timedRoundTrip(line, timeout)
	return got, err
}

// timedRoundTrip also reports how long the round trip itself took, not
// counting the wait for another one on the same connection to finish.
func (c *lineConn) timedRoundTrip(line string, timeout time.Duration) (string, time.Duration, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	begin := time.Now()
	_ = c.SetDeadline(begin.Add(timeout))
	if _, err := io.WriteString(c, line+"\n"); err != nil {
		return "", 0, err
	}
	got, err := c.r.ReadString('\n')
	return strings.TrimSuffix(got, "\n"), time.Since(begin), err
}

func remoteOf(t *testing.T, c *lineConn) string {
	t.Helper()
	got, err := c.roundTrip("who", 10*time.Second)
	if err != nil {
		t.Fatalf("ask the server who we are: %v", err)
	}
	return got
}

// expectRTT checks the connection's median round trip is in [lo, hi].
func expectRTT(t *testing.T, c *lineConn, what string, lo, hi time.Duration) {
	t.Helper()
	var rtts []time.Duration
	for i := 0; i < 7; i++ {
		_, rtt, err := c.timedRoundTrip("rtt", 10*time.Second)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		rtts = append(rtts, rtt)
	}
	slices.Sort(rtts)
	med := rtts[len(rtts)/2]
	t.Logf("%s: connection RTT %s", what, med.Round(time.Millisecond))
	if med < lo || med > hi {
		t.Fatalf("%s: connection RTT %s, want %s..%s", what, med, lo, hi)
	}
}

// pinger keeps a connection busy and records how it fares.
type pinger struct {
	conn *lineConn
	done chan struct{}
	wg   sync.WaitGroup

	mu       sync.Mutex
	n        int
	maxGap   time.Duration
	phaseGap time.Duration
	lastOK   time.Time
	failure  error
}

func startPinger(t *testing.T, c *lineConn) *pinger {
	p := &pinger{conn: c, done: make(chan struct{}), lastOK: time.Now()}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for i := 0; ; i++ {
			select {
			case <-p.done:
				return
			case <-time.After(50 * time.Millisecond):
			}
			msg := fmt.Sprintf("ping %d", i)
			// TCP retransmits through a migration; only a real
			// failure (a reset, or no progress for 20 s) counts.
			got, err := p.conn.roundTrip(msg, 20*time.Second)
			p.mu.Lock()
			now := time.Now()
			switch {
			case err != nil:
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					err = fmt.Errorf("no answer for 20 s: %w", err)
				}
				p.failure = fmt.Errorf("round trip %d: %w", i, err)
			case got != msg:
				p.failure = fmt.Errorf("round trip %d: got %q", i, got)
			default:
				p.n++
				gap := now.Sub(p.lastOK)
				p.maxGap = max(p.maxGap, gap)
				p.phaseGap = max(p.phaseGap, gap)
				p.lastOK = now
			}
			failed := p.failure != nil
			p.mu.Unlock()
			if failed {
				return
			}
		}
	}()
	return p
}

func (p *pinger) check(t *testing.T, when string) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	t.Logf("%s: longest wait for a round trip since the last check: %s", when, p.phaseGap.Round(10*time.Millisecond))
	p.phaseGap = 0
	if p.failure != nil {
		t.Fatalf("%s: the long-lived connection broke: %v", when, p.failure)
	}
	if time.Since(p.lastOK) > 5*time.Second {
		t.Fatalf("%s: the long-lived connection has made no progress for %s", when, time.Since(p.lastOK))
	}
}

func (p *pinger) count() int                { p.mu.Lock(); defer p.mu.Unlock(); return p.n }
func (p *pinger) longestGap() time.Duration { p.mu.Lock(); defer p.mu.Unlock(); return p.maxGap }
func (p *pinger) stop()                     { close(p.done); p.wg.Wait() }
