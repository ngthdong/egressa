package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ngthdong/egressa/internal/buildinfo"
	"github.com/ngthdong/egressa/internal/tunnel"
)

func main() {
	var (
		showVersion    = flag.Bool("version", false, "print version and exit")
		controller     = flag.String("controller", "127.0.0.1:2379", "controller (etcd) endpoint")
		connect        = flag.Bool("connect", false, "connect to a gateway as a real VPN client (needs root); if false, the client starts idle")
		gatewayPubKey  = flag.String("gateway-pubkey", "", "gateway's public key, base64 (wg-style)")
		gatewayAddr    = flag.String("gateway-endpoint", "", "gateway's UDP endpoint, host:port")
		clientAddrFlag = flag.String("address", "10.201.0.2", "this client's virtual IP inside the tunnel")
		ifaceName      = flag.String("interface", "egressa0", "OS-level TUN interface name")
		privateKeyFile = flag.String("private-key-file", "", "path to this client's private key (base64); generated and saved here on first run if missing")
		fullTunnel     = flag.Bool("full-tunnel", false, "route ALL host traffic through the tunnel (changes the real default route -- see the warning in internal/tunnel.EnableFullTunnel; do not use over a remote session without a way to recover)")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("client"))
		return
	}

	if !*connect {
		if err := runIdle(*controller); err != nil {
			log.Fatalf("client: fatal: %v", err)
		}
		return
	}

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
}

// runIdle is the original Stage 1 behavior: start, log, wait for a
// shutdown signal, exit. Kept as the default (no --connect) so existing
// usage and tests are unaffected.
func runIdle(controller string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("client: starting (%s)", buildinfo.String("client"))
	log.Printf("client: controller = %s", controller)
	log.Printf("client: ready")

	<-ctx.Done()
	log.Printf("client: shutting down")
	return nil
}

type connectConfig struct {
	gatewayPubKeyB64 string
	gatewayEndpoint  string
	clientAddr       string
	ifaceName        string
	privateKeyFile   string
	fullTunnel       bool
}

// runConnect brings this host up as a real, terminal-usable VPN client:
// a real OS-level TUN interface, peered with a gateway, optionally
// routing all host traffic through it. This is the --connect path;
// needs CAP_NET_ADMIN.
func runConnect(cfg connectConfig) error {
	if cfg.gatewayPubKeyB64 == "" || cfg.gatewayEndpoint == "" {
		return fmt.Errorf("--connect requires --gateway-pubkey and --gateway-endpoint")
	}

	gatewayPub, err := tunnel.DecodeBase64(cfg.gatewayPubKeyB64)
	if err != nil {
		return fmt.Errorf("--gateway-pubkey: %w", err)
	}

	gatewayHost, err := netip.ParseAddrPort(cfg.gatewayEndpoint)
	if err != nil {
		return fmt.Errorf("--gateway-endpoint: %w", err)
	}

	clientAddr, err := netip.ParseAddr(cfg.clientAddr)
	if err != nil {
		return fmt.Errorf("--address: %w", err)
	}

	priv, err := tunnel.LoadOrCreatePrivateKey(cfg.privateKeyFile)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	var zeroPub [tunnel.KeySize]byte
	if priv.Public != zeroPub {
		log.Printf("client: public key: %s", tunnel.Base64(priv.Public))
	}

	dev, err := tunnel.NewReal(tunnel.RealConfig{
		PrivateKey:    priv.Private,
		InterfaceName: cfg.ifaceName,
	})
	if err != nil {
		return fmt.Errorf("create TUN device: %w", err)
	}
	defer dev.Close()

	if err := tunnel.ConfigureInterface(dev.Name(), netip.PrefixFrom(clientAddr, 32)); err != nil {
		return fmt.Errorf("configure interface: %w", err)
	}

	err = dev.AddPeer(gatewayPub,
		[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		cfg.gatewayEndpoint,
		25*time.Second)
	if err != nil {
		return fmt.Errorf("add gateway peer: %w", err)
	}

	log.Printf("client: connected, interface %s, virtual IP %s", dev.Name(), clientAddr)

	if cfg.fullTunnel {
		log.Printf("client: --full-tunnel set: replacing the default route (see the warning on EnableFullTunnel)")
		restore, err := tunnel.EnableFullTunnel(dev.Name(), gatewayHost.Addr())
		if err != nil {
			return fmt.Errorf("enable full tunnel: %w", err)
		}
		defer func() {
			log.Printf("client: restoring original default route")
			if err := restore(); err != nil {
				log.Printf("client: WARNING: failed to fully restore routing: %v", err)
			}
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("client: ready")
	<-ctx.Done()
	log.Printf("client: shutting down")
	return nil
}
