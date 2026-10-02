package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ngthdong/egressa/internal/telemetry"
	"github.com/ngthdong/egressa/internal/tunnel"
)

// This file is the static mode (--connect): one gateway, given by hand,
// no controller and no path selection. The managed mode is in main.go.

type connectConfig struct {
	gatewayPubKeyB64 string
	gatewayEndpoint  string
	clientAddr       string
	ifaceName        string
	privateKeyFile   string
	fullTunnel       bool
}

// runConnect brings this host up as a VPN client of one gateway: a real
// OS-level TUN interface, peered with it, optionally routing all host
// traffic through it. Needs CAP_NET_ADMIN.
func runConnect(cfg connectConfig, logger *slog.Logger) error {
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
		logger.Info("public key", "public_key", tunnel.Base64(priv.Public))
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

	logger.Info("connected", "interface", dev.Name(), "virtual_ip", clientAddr.String())

	if cfg.fullTunnel {
		logger.Info("full tunnel on: replacing the default route")
		restore, err := tunnel.EnableFullTunnel(dev.Name(), gatewayHost.Addr())
		if err != nil {
			return fmt.Errorf("enable full tunnel: %w", err)
		}
		defer func() {
			logger.Info("restoring the original default route")
			if err := restore(); err != nil {
				logger.Warn("restoring routes failed", telemetry.Err(err))
			}
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger.Info("ready")
	<-ctx.Done()
	logger.Info("shutting down")
	return nil
}
