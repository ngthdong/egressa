package buildinfo

// Set via -ldflags -X in the Makefile. Default values mean a local,
// non-release build.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func String(binaryName string) string {
	return binaryName + " " + Version + " (commit " + Commit + ", built " + BuildTime + ")"
}
