//go:build linux

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// TestLocalTestbed is the smoke test of deploy/local/testbed.sh: it
// brings the testbed up (twice: the second must change nothing), checks
// every process answers /healthz and the client measures every gateway,
// shapes one path with vpnctl netem and sees only that path's RTT move,
// then brings it down and checks nothing is left, also after a failed up.
func TestLocalTestbed(t *testing.T) {
	if os.Getenv(envChild) == "" {
		reexec(t)
		return
	}
	tb := newTestbed(t)
	run, bin, targets := tb.run, tb.bin, tb.targets
	testbed, mustTestbed := tb.cmd, tb.must

	mustTestbed("up")
	mustTestbed("up") // harmless: nothing new starts
	pids := readPids(t, filepath.Join(run, "pids"))
	if len(pids) < 4 {
		t.Fatalf("pids after up: %v", pids)
	}

	// Every process answers /healthz on its management address.
	for _, addr := range []string{"10.79.0.2:9100", "10.79.0.11:9100", "10.79.0.12:9100", "10.79.0.100:9100", "10.79.0.2:8080"} {
		if body := httpGet(t, "http://"+addr+"/healthz"); body != "ok\n" {
			t.Errorf("%s/healthz: %q", addr, body)
		}
	}
	var sd []struct {
		Targets []string          `json:"targets"`
		Labels  map[string]string `json:"labels"`
	}
	if b, err := os.ReadFile(targets); err != nil || json.Unmarshal(b, &sd) != nil || len(sd) != 4 || sd[1].Labels["node"] != "gw1" {
		t.Errorf("Prometheus targets %s: %v %+v", targets, err, sd)
	}

	// The client measures every gateway.
	rtt := func(gw string) (float64, bool) {
		return metric(t, "http://10.79.0.100:9100/metrics", "egressa_client_segment_rtt_seconds",
			map[string]string{"gateway": gw, "percentile": "50"})
	}
	waitFor(t, "an RTT for every gateway", time.Minute, func() bool {
		_, ok1 := rtt("gw1")
		_, ok2 := rtt("gw2")
		return ok1 && ok2
	})
	base1, _ := rtt("gw1")
	base2, _ := rtt("gw2")
	t.Logf("RTT before: gw1 %.1f ms, gw2 %.1f ms", base1*1e3, base2*1e3)
	for _, url := range []string{"http://10.79.0.2:9100/metrics", "http://10.79.0.11:9100/metrics"} {
		if !strings.Contains(httpGet(t, url), "egressa_build_info") {
			t.Errorf("%s has no egressa_build_info", url)
		}
	}

	promtoolCheck(t, "http://10.79.0.100:9100/metrics")
	prom := startPrometheus(t, run, targets)

	// +80 ms from the client to gw1 raises gw1's RTT and only gw1's.
	vpnctl := filepath.Join(bin, "vpnctl")
	nsSh(t, "egtb-cli", vpnctl, "netem", "apply", "--dev", "wan0", "--rule", "10.77.0.11:delay=80ms")
	waitFor(t, "gw1's RTT to rise by 80 ms", time.Minute, func() bool {
		v, _ := rtt("gw1")
		return v > base1+0.060
	})
	up1, _ := rtt("gw1")
	up2, _ := rtt("gw2")
	t.Logf("RTT with +80 ms on gw1: gw1 %.1f ms, gw2 %.1f ms", up1*1e3, up2*1e3)
	if up2 > base2+0.020 {
		t.Errorf("gw2's RTT moved too: %.1f -> %.1f ms", base2*1e3, up2*1e3)
	}

	// Clearing it brings gw1 back.
	nsSh(t, "egtb-cli", vpnctl, "netem", "clear", "--dev", "wan0")
	waitFor(t, "gw1's RTT to come back", time.Minute, func() bool {
		v, _ := rtt("gw1")
		return v < base1+0.020
	})

	if prom != "" {
		checkDashboard(t, prom)
	}

	// down leaves no namespace, interface or process behind.
	mustTestbed("down")
	checkClean(t, pids)

	// down also clears a half-built testbed, and twice is harmless.
	sh(t, "ip", "netns", "add", "egtb-cli")
	sh(t, "ip", "link", "add", "egtb-wan", "type", "bridge")
	sh(t, "ip", "link", "add", "egtb-cli-w", "type", "veth", "peer", "name", "wan0", "netns", "egtb-cli")
	mustTestbed("down")
	mustTestbed("down")
	checkClean(t, nil)
	if out, err := testbed("status"); err != nil || !strings.Contains(out, "testbed: down") {
		t.Errorf("status after down: %v\n%s", err, out)
	}
}

// TestLocalTestbedFirewall brings the testbed up with FIREWALL=1: every
// gateway behind the default-deny INPUT policy the Ansible firewall role
// sets up on a VPS, in place before the gateway starts and before the
// client connects. Every path must still be measured: the client's
// probes to each gateway and the gateways' probes over the backbone come
// in through the tunnels, and the gateway opens the probe port there.
func TestLocalTestbedFirewall(t *testing.T) {
	if os.Getenv(envChild) == "" {
		reexec(t)
		return
	}
	tb := newTestbed(t, "FIREWALL=1")
	tb.must("up")

	// The firewall is in force, and the gateway opened the probe port.
	for _, ns := range []string{"egtb-gw1", "egtb-gw2"} {
		out, err := nsRun(ns, "iptables", "-S", "INPUT")
		if err != nil || !strings.Contains(out, "-P INPUT DROP") || !strings.Contains(out, "-j egtb-fw") {
			t.Fatalf("%s has no firewall: %v\n%s", ns, err, out)
		}
		t.Logf("%s INPUT:\n%s", ns, out)
	}

	const client = "http://10.79.0.100:9100/metrics"
	gwMetrics := map[string]string{"gw1": "http://10.79.0.11:9100/metrics", "gw2": "http://10.79.0.12:9100/metrics"}
	problems := func() []string {
		var p []string
		for _, gw := range []string{"gw1", "gw2"} {
			if loss, ok := metric(t, client, "egressa_client_segment_loss_ratio", map[string]string{"gateway": gw}); !ok || loss != 0 {
				p = append(p, fmt.Sprintf("client -> %s: loss %v (measured %v)", gw, loss, ok))
			}
			if _, ok := metric(t, client, "egressa_client_segment_rtt_seconds", map[string]string{"gateway": gw, "percentile": "50"}); !ok {
				p = append(p, "client -> "+gw+": no RTT")
			}
			for access := range gwMetrics {
				l := map[string]string{"access": access, "egress": gw}
				if v, ok := metric(t, client, "egressa_client_path_usable", l); !ok || v != 1 {
					p = append(p, fmt.Sprintf("path %s -> %s not usable (%v, %v)", access, gw, v, ok))
				}
				if v, ok := metric(t, client, "egressa_client_path_reachable", l); ok && v != 1 {
					p = append(p, fmt.Sprintf("path %s -> %s unreachable", access, gw))
				}
			}
		}
		for gw, url := range gwMetrics {
			for peer := range gwMetrics {
				if peer == gw {
					continue
				}
				if _, ok := metric(t, url, "egressa_gateway_backbone_rtt_seconds", map[string]string{"peer": peer, "percentile": "50"}); !ok {
					p = append(p, "backbone "+gw+" -> "+peer+": no RTT")
				}
				if loss, ok := metric(t, url, "egressa_gateway_backbone_loss_ratio", map[string]string{"peer": peer}); !ok || loss != 0 {
					p = append(p, fmt.Sprintf("backbone %s -> %s: loss %v (measured %v)", gw, peer, loss, ok))
				}
			}
		}
		return p
	}
	deadline := time.Now().Add(time.Minute)
	for p := problems(); len(p) > 0; p = problems() {
		if time.Now().After(deadline) {
			t.Fatalf("behind the firewall, not every path is measured:\n%s", strings.Join(p, "\n"))
		}
		time.Sleep(time.Second)
	}

	// And the VPN still carries traffic to the Internet target.
	var conn net.Conn
	inNS(t, "egtb-cli", func() {
		var err error
		if conn, err = net.DialTimeout("tcp", "10.78.0.10:8000", 5*time.Second); err != nil {
			t.Fatalf("dial the Internet target through the VPN: %v", err)
		}
	})
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
	if body, _ := io.ReadAll(conn); !strings.Contains(string(body), "hello from the Internet target") {
		t.Errorf("the Internet target answered %q", body)
	}

	// A gateway that crashes leaves its rules behind (no undo ran); the
	// one started after it must not add them again.
	pids := readPids(t, filepath.Join(tb.run, "pids"))
	if err := syscall.Kill(pids["gw1"], syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "gw1 to die", 10*time.Second, func() bool { return syscall.Kill(pids["gw1"], 0) != nil })
	tb.must("up") // starts gw1 again
	// The new gw1 has set up (its rules included) once it logs ready.
	waitFor(t, "the new gw1 to be ready", 30*time.Second, func() bool {
		b, _ := os.ReadFile(filepath.Join(tb.run, "logs", "gw1.log"))
		return strings.Count(string(b), `"msg":"ready"`) >= 2
	})
	out, _ := nsRun("egtb-gw1", "iptables", "-S", "INPUT")
	for _, dev := range []string{"egc0", "egb+"} {
		if n := strings.Count(out, "-i "+dev+" -p udp -m udp --dport 51900 -j ACCEPT"); n != 1 {
			t.Errorf("after a crash and restart, %d probe rules for %s:\n%s", n, dev, out)
		}
	}
	deadline = time.Now().Add(time.Minute)
	for p := problems(); len(p) > 0; p = problems() {
		if time.Now().After(deadline) {
			t.Fatalf("after gw1 restarted, not every path is measured:\n%s", strings.Join(p, "\n"))
		}
		time.Sleep(time.Second)
	}

	pids = readPids(t, filepath.Join(tb.run, "pids"))
	tb.must("down")
	checkClean(t, pids)
}

// testbed drives deploy/local/testbed.sh from a test's child process.
type testbed struct {
	run, bin, targets string
	cmd               func(cmd string) (string, error)
	must              func(cmd string)
}

// newTestbed prepares the child's namespaces for testbed.sh (a private
// /run, netem) and returns how to run it with env added to its settings.
func newTestbed(t *testing.T, env ...string) testbed {
	t.Helper()
	tb := testbed{bin: os.Getenv(envBinDir), run: t.TempDir()}
	// A private /run (for /run/netns): this mount namespace is ours.
	sh(t, "mount", "-t", "tmpfs", "tmpfs", "/run")
	sh(t, "ip", "link", "set", "lo", "up")
	if out, err := exec.Command("tc", "qdisc", "add", "dev", "lo", "root", "netem", "delay", "0ms").CombinedOutput(); err != nil {
		t.Skipf("skipping: this kernel cannot load netem (sch_netem): %v: %s", err, strings.TrimSpace(string(out)))
	}
	sh(t, "tc", "qdisc", "del", "dev", "lo", "root")

	script, err := filepath.Abs("../../deploy/local/testbed.sh")
	if err != nil {
		t.Fatal(err)
	}
	backend := os.Getenv("EGRESSA_TESTBED_BACKEND")
	if backend == "" {
		backend = "wireguard"
	}
	tb.targets = filepath.Join(tb.run, "targets.json")
	tb.cmd = func(cmd string) (string, error) {
		c := exec.Command(script, cmd)
		c.Env = append(os.Environ(), "RUN_DIR="+tb.run, "BIN_DIR="+tb.bin, "TARGETS_FILE="+tb.targets,
			"GATEWAYS=2", "BACKEND="+backend)
		c.Env = append(c.Env, env...)
		out, err := c.CombinedOutput()
		return string(out), err
	}
	tb.must = func(cmd string) {
		t.Helper()
		out, err := tb.cmd(cmd)
		t.Logf("testbed.sh %s:\n%s", cmd, out)
		if err != nil {
			for _, name := range []string{"controller", "gw1", "gw2", "client"} {
				b, _ := os.ReadFile(filepath.Join(tb.run, "logs", name+".log"))
				t.Logf("--- %s.log ---\n%s", name, tail(string(b), 30))
			}
			t.Fatalf("testbed.sh %s: %v", cmd, err)
		}
	}
	t.Cleanup(func() { _, _ = tb.cmd("down") })
	return tb
}

func readPids(t *testing.T, dir string) map[string]int {
	t.Helper()
	pids := map[string]int{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		pids[e.Name()] = pid
	}
	return pids
}

func checkClean(t *testing.T, pids map[string]int) {
	t.Helper()
	out, _ := exec.Command("ip", "netns", "list").CombinedOutput()
	if strings.Contains(string(out), "egtb-") {
		t.Errorf("namespaces left: %s", out)
	}
	out, _ = exec.Command("ip", "-o", "link", "show").CombinedOutput()
	if strings.Contains(string(out), "egtb-") {
		t.Errorf("interfaces left: %s", out)
	}
	out, _ = exec.Command("iptables", "-S", "FORWARD").CombinedOutput()
	if strings.Contains(string(out), "egtb-") {
		t.Errorf("FORWARD rules left: %s", out)
	}
	for name, pid := range pids {
		if syscall.Kill(pid, 0) == nil {
			t.Errorf("%s (pid %d) still runs", name, pid)
		}
	}
}

func httpGet(t *testing.T, url string) string {
	t.Helper()
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		t.Errorf("GET %s: %v", url, err)
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// metric scrapes url and returns the value of name with these labels.
func metric(t *testing.T, url, name string, labels map[string]string) (float64, bool) {
	t.Helper()
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return 0, false
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	p := expfmt.NewTextParser(model.UTF8Validation)
	mfs, err := p.TextToMetricFamilies(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("parse %s: %v", url, err)
	}
	mf, ok := mfs[name]
	if !ok {
		return 0, false
	}
next:
	for _, m := range mf.GetMetric() {
		have := map[string]string{}
		for _, l := range m.GetLabel() {
			have[l.GetName()] = l.GetValue()
		}
		for k, v := range labels {
			if have[k] != v {
				continue next
			}
		}
		if g := m.GetGauge(); g != nil {
			return g.GetValue(), true
		}
		return m.GetCounter().GetValue(), true
	}
	return 0, false
}

func waitFor(t *testing.T, what string, timeout time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// tool finds an optional tool: $env, else name on PATH, else "".
func tool(env, name string) string {
	if p := os.Getenv(env); p != "" {
		return p
	}
	p, _ := exec.LookPath(name)
	return p
}

// promtoolCheck lints a live endpoint with `promtool check metrics`, if
// promtool is around.
func promtoolCheck(t *testing.T, url string) {
	t.Helper()
	promtool := tool("EGRESSA_PROMTOOL", "promtool")
	if promtool == "" {
		t.Log("no promtool (set EGRESSA_PROMTOOL): skipping promtool check metrics")
		return
	}
	cmd := exec.Command(promtool, "check", "metrics")
	cmd.Stdin = strings.NewReader(httpGet(t, url))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("promtool check metrics %s: %v\n%s", url, err, out)
	}
}

// startPrometheus runs Prometheus on the testbed's targets file, as
// deploy/observability does, and returns its URL, or "" without one.
func startPrometheus(t *testing.T, run, targets string) string {
	t.Helper()
	bin := tool("EGRESSA_PROMETHEUS", "prometheus")
	if bin == "" {
		t.Log("no prometheus (set EGRESSA_PROMETHEUS): skipping the dashboard queries")
		return ""
	}
	conf := filepath.Join(run, "prometheus.yml")
	writeFile(t, conf, fmt.Sprintf(`global: {scrape_interval: 1s, scrape_timeout: 900ms}
scrape_configs:
  - job_name: egressa
    file_sd_configs: [{files: [%q], refresh_interval: 1s}]
`, targets))
	cmd := exec.Command(bin, "--config.file="+conf, "--storage.tsdb.path="+filepath.Join(run, "tsdb"),
		"--web.listen-address=127.0.0.1:19090")
	logf, err := os.Create(filepath.Join(run, "prometheus.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = logf.Close() })
	const url = "http://127.0.0.1:19090"
	waitFor(t, "every target up in Prometheus", time.Minute, func() bool {
		r := promQuery(t, url, `count(up == 1)`)
		return len(r) == 1 && r[0].Value[1] == "4"
	})
	return url
}

type promSample struct {
	Metric map[string]string `json:"metric"`
	Value  [2]any            `json:"value"`
}

func promQuery(t *testing.T, url, q string) []promSample {
	t.Helper()
	c := http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(url + "/api/v1/query?query=" + neturl.QueryEscape(q))
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	var r struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			Result []promSample `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil || r.Status != "success" {
		t.Errorf("query %s: %v %s", q, err, r.Error)
		return nil
	}
	return r.Data.Result
}

// checkDashboard runs every query of the Grafana dashboard against the
// testbed's Prometheus: each must be valid PromQL, and the panels must
// have data.
func checkDashboard(t *testing.T, prom string) {
	t.Helper()
	data, err := os.ReadFile("../../deploy/observability/grafana/dashboards/egressa.json")
	if err != nil {
		t.Fatal(err)
	}
	var d any
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	type query struct{ title, expr string }
	var qs []query
	var walk func(title string, v any)
	walk = func(title string, v any) {
		switch v := v.(type) {
		case map[string]any:
			if s, ok := v["title"].(string); ok {
				title = s
			} else if s, ok := v["name"].(string); ok {
				title = s
			}
			if e, ok := v["expr"].(string); ok {
				qs = append(qs, query{title, e})
			}
			for _, x := range v {
				walk(title, x)
			}
		case []any:
			for _, x := range v {
				walk(title, x)
			}
		}
	}
	walk("", d)
	expand := strings.NewReplacer("$client", "client", "$__rate_interval", "8s")
	// Panels that only have data once something happened: a migration,
	// a conflict, a dead path.
	eventual := map[string]bool{
		"Migrations": true, "Migration duration": true, "CAS conflicts": true,
		"LCB(Δ) against the margin": true, "Flap guard": true,
	}
	var empty []string
	for _, q := range qs {
		if len(promQuery(t, prom, expand.Replace(q.expr))) == 0 && !eventual[q.title] {
			empty = append(empty, q.title+": "+q.expr)
		}
	}
	if len(empty) > 0 {
		t.Errorf("dashboard queries with no data on the testbed:\n%s", strings.Join(empty, "\n"))
	}
	t.Logf("ran the dashboard's %d queries against the testbed's Prometheus", len(qs))
}
