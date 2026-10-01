//go:build linux

package ipsec

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// envInUserNS marks a test process that runUnprivilegedNetNS re-executed
// inside a fresh user+network namespace.
const envInUserNS = "EGRESSA_IPSEC_IN_USERNS"

// runUnprivilegedNetNS makes the calling test run against a real kernel
// without needing real root: it re-executes the test binary for just this
// test under `unshare -Urn`, where the process is root inside a new user
// namespace that owns a new, empty network namespace. It returns true in
// the re-executed child (the caller should then run its body) and false in
// the parent (the caller should return; the child's result is already
// reported). Environments that forbid unprivileged user namespaces skip.
func runUnprivilegedNetNS(t *testing.T) (inChild bool) {
	t.Helper()
	if os.Getenv(envInUserNS) == "1" {
		return true
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("skipping: unshare(1) not found")
	}
	if out, err := exec.Command(unshare, "-Urn", "true").CombinedOutput(); err != nil {
		t.Skipf("skipping: unprivileged user namespaces are not available here (%v: %s)",
			err, strings.TrimSpace(string(out)))
	}
	cmd := exec.Command(unshare, "-Urn", os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), envInUserNS+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("re-executed inside an unprivileged user+network namespace:\n%s", out)
	if err != nil {
		t.Fatalf("child test failed: %v", err)
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Skip("child test skipped (see log above)")
	}
	return false
}
