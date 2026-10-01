//go:build linux

package ipsec

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// The TestIPsec_* tests run real charon daemons, one per network
// namespace, connected by a veth pair. They need root (or CAP_SYS_ADMIN
// and CAP_NET_ADMIN), and skip without it:
//
//	sudo env "PATH=$PATH" go test -race -count=1 -v -run TestIPsec_ ./internal/ipsec/
//
// Environment knobs, all optional:
//
//	EGRESSA_CHARON          charon binary (default: the distribution's)
//	EGRESSA_CHARON_PRELOAD  LD_PRELOAD for charon, e.g. a libstrongswan-vici.so
//	                        unpacked from the strongswan-swanctl package on a
//	                        machine where that package is not installed
//	EGRESSA_KEEP_LOGS=1     keep the charon logs and configs after the test
const (
	envCharon        = "EGRESSA_CHARON"
	envCharonPreload = "EGRESSA_CHARON_PRELOAD"
	envKeepLogs      = "EGRESSA_KEEP_LOGS"
)

var charonPaths = []string{
	"/usr/lib/ipsec/charon",
	"/usr/libexec/ipsec/charon",
	"/usr/lib/strongswan/charon",
	"/usr/libexec/strongswan/charon",
}

// requireRoot skips unless the test runs as (namespace) root.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("skipping: needs root to create network namespaces and run charon; " +
			`run: sudo env "PATH=$PATH" go test -race -count=1 -v -run TestIPsec_ ./internal/ipsec/`)
	}
}

func findCharon(t *testing.T) string {
	t.Helper()
	if p := os.Getenv(envCharon); p != "" {
		return p
	}
	for _, p := range charonPaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("skipping: no charon binary found (install strongswan-charon and strongswan-swanctl, or set " + envCharon + ")")
	return ""
}

// apparmorEnforces reports whether an AppArmor profile in enforce mode is
// attached to the charon binary. Such a profile keeps charon from reading
// a strongswan.conf or creating a vici socket outside the paths it allows,
// which is exactly what these tests need. An unreadable profile list means
// "unknown", reported as false; a start-up failure is diagnosed later.
func apparmorEnforces(charon string) bool {
	data, err := os.ReadFile("/sys/kernel/security/apparmor/profiles")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		name, mode, ok := strings.Cut(line, " (")
		if ok && strings.HasPrefix(mode, "enforce") && (name == charon || filepath.Base(name) == "usr.lib.ipsec.charon") {
			return true
		}
	}
	return false
}

const apparmorHint = "an AppArmor profile in enforce mode confines charon (it cannot read a test " +
	"strongswan.conf or create a vici socket in a temp dir); for this test run use " +
	"`sudo aa-complain /usr/lib/ipsec/charon` or `sudo apparmor_parser -R " +
	"/etc/apparmor.d/usr.lib.ipsec.charon`, and restore it afterwards " +
	"(`sudo aa-enforce /usr/lib/ipsec/charon`)"

// testNS is one network namespace with its own charon.
type testNS struct {
	name    string
	handle  netns.NsHandle
	net     *NetlinkNet
	dir     string // logs, config, vici socket (a short path)
	socket  string
	cmd     *exec.Cmd
	exited  chan struct{}
	exitErr error
}

// testBed is two namespaces joined by a veth pair: "a" (192.0.2.1) and
// "b" (192.0.2.2), each with a charon.
type testBed struct {
	t      *testing.T
	charon string
	a, b   *testNS
}

const (
	addrA = "192.0.2.1"
	addrB = "192.0.2.2"
)

func newTestBed(t *testing.T) *testBed {
	t.Helper()
	requireRoot(t)
	charon := findCharon(t)
	if apparmorEnforces(charon) {
		t.Skip("skipping: " + apparmorHint)
	}
	tb := &testBed{t: t, charon: charon}
	suffix := fmt.Sprintf("%d", os.Getpid()%100000)
	tb.a = tb.newNS("egta" + suffix)
	tb.b = tb.newNS("egtb" + suffix)

	// veth pair created in the test's own namespace, then one end moved
	// into each test namespace.
	la, lb := "egva"+suffix, "egvb"+suffix
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: la}, PeerName: lb}
	if err := netlink.LinkAdd(veth); err != nil {
		t.Fatalf("create veth: %v", err)
	}
	for name, ns := range map[string]*testNS{la: tb.a, lb: tb.b} {
		link, err := netlink.LinkByName(name)
		if err != nil {
			t.Fatalf("veth %s: %v", name, err)
		}
		if err := netlink.LinkSetNsFd(link, int(ns.handle)); err != nil {
			t.Fatalf("move %s into %s: %v", name, ns.name, err)
		}
	}
	tb.a.configure(t, la, addrA)
	tb.b.configure(t, lb, addrB)
	requireKernelIPsec(t, tb.a)
	tb.a.start(t, charon)
	tb.b.start(t, charon)
	return tb
}

func (tb *testBed) newNS(name string) *testNS {
	t := tb.t
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatalf("current netns: %v", err)
	}
	defer func() { _ = orig.Close() }()
	h, err := netns.NewNamed(name)
	if err != nil {
		t.Fatalf("create netns %s: %v", name, err)
	}
	if err := netns.Set(orig); err != nil {
		t.Fatalf("return to the original netns: %v", err)
	}
	ns := &testNS{name: name, handle: h}
	t.Cleanup(func() {
		ns.stop()
		_ = ns.handle.Close()
		_ = netns.DeleteNamed(name)
	})
	n, err := NewNetlinkNetAt(h)
	if err != nil {
		t.Fatalf("netlink in %s: %v", name, err)
	}
	ns.net = n
	t.Cleanup(n.Close)
	dir, err := os.MkdirTemp("", "egv")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	ns.dir = dir
	ns.socket = filepath.Join(dir, "c.vici")
	t.Cleanup(func() {
		if t.Failed() || os.Getenv(envKeepLogs) == "1" {
			t.Logf("charon files for %s kept in %s", name, dir)
			return
		}
		_ = os.RemoveAll(dir)
	})
	return ns
}

func (ns *testNS) configure(t *testing.T, link, addr string) {
	t.Helper()
	if err := ns.net.SetLinkUp("lo"); err != nil {
		t.Fatalf("%s: lo up: %v", ns.name, err)
	}
	if err := ns.net.AddAddr(link, netip.MustParsePrefix(addr+"/24")); err != nil {
		t.Fatalf("%s: address: %v", ns.name, err)
	}
	if err := ns.net.SetLinkUp(link); err != nil {
		t.Fatalf("%s: veth up: %v", ns.name, err)
	}
}

// start runs charon inside the namespace, in a private mount namespace
// whose /run is a fresh tmpfs, so two charons never share a pid file or
// control socket. Short retransmit settings make DPD give up in seconds.
func (ns *testNS) start(t *testing.T, charon string) {
	t.Helper()
	conf := filepath.Join(ns.dir, "strongswan.conf")
	logf := filepath.Join(ns.dir, "charon.log")
	cfg := fmt.Sprintf(`charon {
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
      ike = 2
      time_format = %%T
      # without this charon buffers the log until it exits, and neither
      # the start-up checks nor failure messages could read it
      flush_line = yes
    }
  }
}
`, ns.socket, logf)
	if err := os.WriteFile(conf, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write strongswan.conf: %v", err)
	}
	// LD_PRELOAD (if any) must reach charon only: preloading a charon
	// plugin into nsenter or unshare makes the dynamic loader fail.
	script := `mount -t tmpfs tmpfs /run && exec "$0"`
	args := []string{charon}
	if p := os.Getenv(envCharonPreload); p != "" {
		script = `mount -t tmpfs tmpfs /run && export LD_PRELOAD="$1" && exec "$0"`
		args = append(args, p)
	}
	ns.cmd = exec.Command("nsenter", append([]string{"--net=/var/run/netns/" + ns.name, "--",
		"unshare", "-m", "--", "sh", "-c", script}, args...)...)
	ns.cmd.Env = append(os.Environ(), "STRONGSWAN_CONF="+conf)
	ns.cmd.Stdout, ns.cmd.Stderr = nil, nil
	ns.cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := ns.cmd.Start(); err != nil {
		t.Fatalf("start charon in %s: %v", ns.name, err)
	}
	ns.exited = make(chan struct{})
	go func() {
		ns.exitErr = ns.cmd.Wait()
		close(ns.exited)
	}()

	deadline := time.Now().Add(15 * time.Second)
	for {
		if c, err := net.Dial("unix", ns.socket); err == nil {
			_ = c.Close()
			return
		}
		if loaded, ok := ns.loadedPlugins(); ok && !slices.Contains(loaded, "vici") {
			t.Skipf("skipping: charon in %s runs without the vici plugin, which ships in "+
				"strongswan-swanctl (or set %s to an unpacked libstrongswan-vici.so)", ns.name, envCharonPreload)
		}
		select {
		case <-ns.exited:
			var ee *exec.ExitError
			if errors.As(ns.exitErr, &ee) && ee.ExitCode() == 64 {
				t.Skipf("skipping: charon in %s refused to initialize (exit 64, usually an "+
					"unreadable strongswan.conf): %s", ns.name, apparmorHint)
			}
			t.Fatalf("charon in %s exited during start-up: %v\n%s", ns.name, ns.exitErr, ns.log())
		case <-time.After(50 * time.Millisecond):
		}
		if time.Now().After(deadline) {
			t.Fatalf("charon in %s never opened %s (is the vici plugin installed? it ships in "+
				"strongswan-swanctl)\n%s", ns.name, ns.socket, ns.log())
		}
	}
}

// kill stops charon abruptly, the way a crashed gateway disappears.
func (ns *testNS) kill() {
	if ns.cmd != nil && ns.cmd.Process != nil {
		_ = ns.cmd.Process.Signal(syscall.SIGKILL)
		<-ns.exited
	}
}

func (ns *testNS) stop() {
	if ns.cmd == nil || ns.cmd.Process == nil {
		return
	}
	select {
	case <-ns.exited:
		return
	default:
	}
	_ = ns.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-ns.exited:
	case <-time.After(5 * time.Second):
		ns.kill()
	}
}

// loadedPlugins returns the plugin list charon logs once it has loaded
// them, and false until it has.
func (ns *testNS) loadedPlugins() ([]string, bool) {
	data, err := os.ReadFile(filepath.Join(ns.dir, "charon.log"))
	if err != nil {
		return nil, false
	}
	_, rest, ok := strings.Cut(string(data), "loaded plugins: ")
	if !ok {
		return nil, false
	}
	line, _, _ := strings.Cut(rest, "\n")
	return strings.Fields(line), true
}

// log returns the tail of charon's log, for failure messages.
func (ns *testNS) log() string {
	f, err := os.Open(filepath.Join(ns.dir, "charon.log"))
	if err != nil {
		return "(no charon log: " + err.Error() + ")"
	}
	defer func() { _ = f.Close() }()
	var lines []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		lines = append(lines, s.Text())
		if len(lines) > 60 {
			lines = lines[1:]
		}
	}
	if err := s.Err(); err != nil {
		lines = append(lines, "(reading the log failed: "+err.Error()+")")
	}
	return "charon log tail (" + ns.name + "):\n" + strings.Join(lines, "\n")
}

func (ns *testNS) ike(t *testing.T) *ViciIKE {
	t.Helper()
	v, err := NewViciIKE(context.Background(), WithViciSocket(ns.socket), WithViciReconnect(200*time.Millisecond))
	if err != nil {
		t.Fatalf("connect to charon in %s: %v", ns.name, err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v
}

// run runs a command inside the namespace's network stack.
func (ns *testNS) run(args ...string) ([]byte, error) {
	cmd := exec.Command("nsenter", append([]string{"--net=/var/run/netns/" + ns.name, "--"}, args...)...)
	return cmd.CombinedOutput()
}

// requireKernelIPsec skips unless the kernel can do what every test here
// needs: XFRM interfaces, and ESP states with AES-GCM (charon installs one
// for every CHILD_SA, so without it not even a handshake completes).
func requireKernelIPsec(t *testing.T, ns *testNS) {
	t.Helper()
	if err := ns.net.AddXfrmInterface("egprobe", 999, ""); err != nil {
		t.Skipf("skipping: the kernel cannot create XFRM interfaces (CONFIG_XFRM_INTERFACE): %v", err)
	}
	_ = ns.net.DeleteLink("egprobe")
	h, err := netlink.NewHandleAt(ns.handle)
	if err != nil {
		t.Fatalf("netlink handle in %s: %v", ns.name, err)
	}
	defer h.Close()
	st := &netlink.XfrmState{
		Src: net.ParseIP("192.0.2.200"), Dst: net.ParseIP("192.0.2.201"),
		Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TUNNEL,
		Spi: 0x7e57, Reqid: 1, ReplayWindow: 32,
		Aead: &netlink.XfrmStateAlgo{Name: "rfc4106(gcm(aes))", Key: make([]byte, 36), ICVLen: 128},
	}
	if err := h.XfrmStateAdd(st); err != nil {
		t.Skipf("skipping: the kernel cannot install ESP states with AES-GCM "+
			"(CONFIG_INET_ESP, CONFIG_CRYPTO_GCM, or the esp4 module): %v", err)
	}
	_ = h.XfrmStateDel(st)
}
