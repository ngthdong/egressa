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
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/buildinfo"
	"github.com/ngthdong/egressa/internal/cliutil"
	"github.com/ngthdong/egressa/internal/gateway"
	"github.com/ngthdong/egressa/internal/tunnel"
)

func main() {
	var (
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
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("gateway"))
		return
	}
	if *id == "" || *controller == "" || *endpoint == "" {
		fmt.Fprintln(os.Stderr, "gateway: --id, --controller and --endpoint are required; see -h")
		os.Exit(2)
	}
	if *listenPort == 0 || *listenPort > 65535 {
		log.Fatalf("gateway: bad --listen-port %d", *listenPort)
	}
	roles, err := api.ParseRoles(*role)
	if err != nil {
		log.Fatalf("gateway: %v", err)
	}
	token, err := cliutil.Secret(*tokenFile, "EGRESSA_GATEWAY_TOKEN")
	if err != nil {
		log.Fatalf("gateway: %v", err)
	}
	ctl, err := api.NewClient(*controller, token)
	if err != nil {
		log.Fatalf("gateway: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(*keyFile), 0o700); err != nil {
		log.Fatalf("gateway: %v", err)
	}
	key, err := tunnel.LoadOrCreatePrivateKey(*keyFile)
	if err != nil {
		log.Fatalf("gateway: %v", err)
	}
	agent, err := gateway.New(gateway.Config{
		ID: *id, Controller: ctl, Roles: roles, Key: key,
		ListenPort: uint16(*listenPort), Endpoint: *endpoint, Uplink: *uplink, MTU: *mtu,
	})
	if err != nil {
		log.Fatalf("gateway: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("gateway: starting (%s), public key %s", buildinfo.String("gateway"), tunnel.Base64(key.Public))
	if err := agent.Run(ctx); err != nil {
		log.Fatalf("gateway: fatal: %v", err)
	}
}
