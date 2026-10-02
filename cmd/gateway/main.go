// Command gateway is an egressa gateway: an access gateway clients
// connect to, an egress gateway traffic leaves the VPN from, or both.
//
//	EGRESSA_GATEWAY_TOKEN=... gateway --id hk --controller http://ctl:8080 \
//	    --role access,egress --endpoint 203.0.113.5:51820 --uplink eth0
//
// It needs root (or CAP_NET_ADMIN): it creates TUN devices and changes
// routes, rules and iptables, and removes them all on exit.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/buildinfo"
	"github.com/ngthdong/egressa/internal/cliutil"
	"github.com/ngthdong/egressa/internal/gateway"
	"github.com/ngthdong/egressa/internal/telemetry"
	"github.com/ngthdong/egressa/internal/tunnel"
)

func main() {
	var (
		logs        cliutil.LogFlags
		showVersion = flag.Bool("version", false, "print version and exit")
		id          = flag.String("id", "", "this gateway's ID, e.g. hk or sg (lowercase letters, digits, dashes)")
		controller  = flag.String("controller", "", "controller URL, http(s)://host:port")
		tokenFile   = flag.String("token-file", "", "file holding the gateway token (default: $EGRESSA_GATEWAY_TOKEN)")
		role        = flag.String("role", "access,egress", "roles this gateway plays: access, egress, or both")
		listenPort  = flag.Uint("listen-port", 51820, "UDP port clients' WireGuard connects to")
		endpoint    = flag.String("endpoint", "", "public ip:port clients reach --listen-port on; its IP is also where other gateways reach this one")
		uplink      = flag.String("uplink", "", "interface traffic leaves to the Internet from (needed for the egress role)")
		keyFile     = flag.String("private-key-file", "/var/lib/egressa/gateway.key", "this gateway's private key (base64), created if missing")
		mtu         = flag.Int("mtu", gateway.DefaultMTU, "tunnel MTU")
		metrics     = flag.String("metrics-listen", "", cliutil.MetricsFlagHelp)
	)
	logs.Register(flag.CommandLine)
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("gateway"))
		return
	}
	if *id == "" || *controller == "" || *endpoint == "" {
		fmt.Fprintln(os.Stderr, "gateway: --id, --controller and --endpoint are required; see -h")
		os.Exit(2)
	}
	logger, err := logs.Logger("gateway", *id)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gateway:", err)
		os.Exit(2)
	}
	if *listenPort == 0 || *listenPort > 65535 {
		cliutil.Fatal(logger, "bad --listen-port", fmt.Errorf("%d is not a port", *listenPort))
	}
	roles, err := api.ParseRoles(*role)
	if err != nil {
		cliutil.Fatal(logger, "bad --role", err)
	}
	token, err := cliutil.Secret(*tokenFile, "EGRESSA_GATEWAY_TOKEN")
	if err != nil {
		cliutil.Fatal(logger, "read the gateway token", err)
	}
	ctl, err := api.NewClient(*controller, token)
	if err != nil {
		cliutil.Fatal(logger, "bad --controller", err)
	}
	if err := os.MkdirAll(filepath.Dir(*keyFile), 0o700); err != nil {
		cliutil.Fatal(logger, "create the key directory", err)
	}
	key, err := tunnel.LoadOrCreatePrivateKey(*keyFile)
	if err != nil {
		cliutil.Fatal(logger, "load the private key", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reg, err := cliutil.Metrics(ctx, *metrics, "gateway", logger)
	if err != nil {
		cliutil.Fatal(logger, "start the metrics server", err)
	}
	agent, err := gateway.New(gateway.Config{
		ID: *id, Controller: ctl, Roles: roles, Key: key,
		ListenPort: uint16(*listenPort), Endpoint: *endpoint, Uplink: *uplink, MTU: *mtu,
		Logger: logger, Metrics: telemetry.NewGatewayMetrics(reg), Tracer: telemetry.NewTracer(logger, nil),
	})
	if err != nil {
		cliutil.Fatal(logger, "bad configuration", err)
	}
	logger.Info("starting", "build", buildinfo.String("gateway"), "public_key", tunnel.Base64(key.Public),
		"controller", *controller, "token", telemetry.Secret(token))
	if err := agent.Run(ctx); err != nil {
		cliutil.Fatal(logger, "gateway failed", err)
	}
}
