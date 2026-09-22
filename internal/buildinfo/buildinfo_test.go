package buildinfo

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	oldVersion, oldCommit, oldBuildTime := Version, Commit, BuildTime
	Version, Commit, BuildTime = "v0.1.0", "a1b2c3d", "2026-09-21T10:00:00Z"
	defer func() { Version, Commit, BuildTime = oldVersion, oldCommit, oldBuildTime }()

	got := String("egressa-gateway")
	want := "egressa-gateway v0.1.0 (commit a1b2c3d, built 2026-09-21T10:00:00Z)"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestString_Defaults(t *testing.T) {
	got := String("egressa-client")
	for _, want := range []string{"egressa-client", "dev", "unknown"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, missing %q", got, want)
		}
	}
}
