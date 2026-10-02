// Command client is the egressa VPN client.
//
// Managed mode (the normal one) needs a controller:
//
//	EGRESSA_CLIENT_TOKEN=... client --controller http://ctl:8080 --full-tunnel
//
// It opens a session, keeps a tunnel to every access gateway and moves the
// session to the best path as conditions change. Static mode (--connect)
// talks to one gateway given on the command line, with no controller.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/buildinfo"
	"github.com/ngthdong/egressa/internal/client"
	"github.com/ngthdong/egressa/internal/cliutil"
)

func main() {
	var (
		showVersion = flag.Bool("version", false, "print version and exit")

		controller = flag.String("controller", "", "controller URL, http(s)://host:port (managed mode)")
		tokenFile  = flag.String("token-file", "", "file holding the client token (default: $EGRESSA_CLIENT_TOKEN)")
		stateFile  = flag.String("state-file", "/var/lib/egressa/client.json", "where the key and session are kept across restarts")
		egress     = flag.String("egress", "", "egress gateway to ask for when the session is first opened (default: the controller's choice)")

		connect        = flag.Bool("connect", false, "static mode: connect to the one gateway given by --gateway-pubkey and --gateway-endpoint, with no controller")
		gatewayPubKey  = flag.String("gateway-pubkey", "", "static mode: the gateway's public key, base64")
		gatewayAddr    = flag.String("gateway-endpoint", "", "static mode: the gateway's UDP endpoint, host:port")
		clientAddrFlag = flag.String("address", "10.201.0.2", "static mode: this client's virtual IP")
		privateKeyFile = flag.String("private-key-file", "", "static mode: this client's private key (base64), created if missing")

		ifaceName  = flag.String("interface", "egressa0", "TUN interface name")
		fullTunnel = flag.Bool("full-tunnel", false, "route ALL host traffic through the VPN (replaces the default route; gateways and the controller stay reachable directly)")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("client"))
		return
	}

	if *connect {
		cfg := connectConfig{
			gatewayPubKeyB64: *gatewayPubKey,
			gatewayEndpoint:  *gatewayAddr,
			clientAddr:       *clientAddrFlag,
			ifaceName:        *ifaceName,
			privateKeyFile:   *privateKeyFile,
			fullTunnel:       *fullTunnel,
		}
		if err := runConnect(cfg); err != nil {
			log.Fatalf("client: fatal: %v", err)
		}
		return
	}

	if *controller == "" {
		fmt.Fprintln(os.Stderr, "client: give --controller (managed mode) or --connect (static mode); see -h")
		os.Exit(2)
	}
	token, err := cliutil.Secret(*tokenFile, "EGRESSA_CLIENT_TOKEN")
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	ctl, err := api.NewClient(*controller, token)
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	agent, err := client.New(client.Config{
		Controller: ctl,
		StateFile:  *stateFile,
		Interface:  *ifaceName,
		Egress:     *egress,
		FullTunnel: *fullTunnel,
	})
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("client: starting (%s)", buildinfo.String("client"))
	if err := agent.Run(ctx); err != nil {
		log.Fatalf("client: fatal: %v", err)
	}
	log.Printf("client: shut down")
}
