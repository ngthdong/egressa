// Command controller is the egressa control plane.
//
//	EGRESSA_GATEWAY_TOKEN=... EGRESSA_CLIENT_TOKEN=... controller \
//	    --listen :8080 --state-file /var/lib/egressa/controller.json
//
// Gateways register with it and follow the sessions it reports; clients
// open sessions with it and commit their migrations through it. Put it
// behind TLS (--tls-cert/--tls-key) anywhere but a private network.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ngthdong/egressa/internal/api"
	"github.com/ngthdong/egressa/internal/buildinfo"
	"github.com/ngthdong/egressa/internal/cliutil"
	"github.com/ngthdong/egressa/internal/control"
	"github.com/ngthdong/egressa/internal/controller"
	"github.com/ngthdong/egressa/internal/telemetry"
)

type options struct {
	listen, stateFile, etcd          string
	gwTokenFile, clTokenFile         string
	clientSubnet, nodeSubnet, policy string
	probePort                        uint
	tlsCert, tlsKey                  string
	metricsListen                    string
}

func main() {
	var (
		o           options
		logs        cliutil.LogFlags
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.StringVar(&o.listen, "listen", ":8080", "HTTP listen address")
	flag.StringVar(&o.stateFile, "state-file", "", "keep state in this JSON file (default: in memory only, lost on restart)")
	flag.StringVar(&o.etcd, "etcd", "", "keep state in etcd at this endpoint instead (needs a build with -tags etcd)")
	flag.StringVar(&o.gwTokenFile, "gateway-token-file", "", "file holding the gateway token (default: $EGRESSA_GATEWAY_TOKEN)")
	flag.StringVar(&o.clTokenFile, "client-token-file", "", "file holding the client token (default: $EGRESSA_CLIENT_TOKEN)")
	flag.StringVar(&o.clientSubnet, "client-subnet", "10.201.0.0/16", "client virtual IPs are allocated from here")
	flag.StringVar(&o.nodeSubnet, "node-subnet", "10.200.0.0/24", "gateway node IPs are allocated from here")
	flag.UintVar(&o.probePort, "probe-port", 51900, "UDP port gateways answer probes on")
	flag.StringVar(&o.policy, "policy", "", "JSON policy document (cost weights, decision thresholds, flap guard) to set on start")
	flag.StringVar(&o.tlsCert, "tls-cert", "", "serve HTTPS with this certificate")
	flag.StringVar(&o.tlsKey, "tls-key", "", "and this key")
	flag.StringVar(&o.metricsListen, "metrics-listen", "", cliutil.MetricsFlagHelp)
	logs.Register(flag.CommandLine)
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("controller"))
		return
	}
	logger, err := logs.Logger("controller", "")
	if err != nil {
		fmt.Fprintln(os.Stderr, "controller:", err)
		os.Exit(2)
	}
	if err := run(o, logger); err != nil {
		cliutil.Fatal(logger, "controller failed", err)
	}
}

func run(o options, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cs, err := netip.ParsePrefix(o.clientSubnet)
	if err != nil {
		return fmt.Errorf("--client-subnet: %w", err)
	}
	ns, err := netip.ParsePrefix(o.nodeSubnet)
	if err != nil {
		return fmt.Errorf("--node-subnet: %w", err)
	}
	if o.probePort == 0 || o.probePort > 65535 {
		return fmt.Errorf("bad --probe-port %d", o.probePort)
	}
	gwToken, err := cliutil.Secret(o.gwTokenFile, "EGRESSA_GATEWAY_TOKEN")
	if err != nil {
		return err
	}
	clToken, err := cliutil.Secret(o.clTokenFile, "EGRESSA_CLIENT_TOKEN")
	if err != nil {
		return err
	}
	if gwToken == "" || clToken == "" {
		logger.Warn("a gateway or client token is empty; anyone who reaches the API can use that part of it", "listen", o.listen)
	}

	var store control.KVStore
	switch {
	case o.etcd != "" && o.stateFile != "":
		return errors.New("give --etcd or --state-file, not both")
	case o.etcd != "":
		s, closeFn, err := openEtcd(o.etcd)
		if err != nil {
			return err
		}
		defer closeFn()
		store = s
	case o.stateFile != "":
		s, err := controller.OpenFileStore(o.stateFile)
		if err != nil {
			return err
		}
		store = s
	default:
		logger.Warn("no --state-file or --etcd; sessions are lost on restart")
		store = control.NewMemStore()
	}

	var policy *control.PolicyDocument
	if o.policy != "" {
		data, err := os.ReadFile(o.policy)
		if err != nil {
			return err
		}
		doc := control.DefaultPolicyDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("--policy %s: %w", o.policy, err)
		}
		policy = &doc
	}

	reg, err := cliutil.Metrics(ctx, o.metricsListen, "controller", logger)
	if err != nil {
		return err
	}
	srv, err := controller.New(ctx, controller.Config{
		Store: store, GatewayToken: gwToken, ClientToken: clToken, Policy: policy,
		Network: api.Network{ClientSubnet: cs, NodeSubnet: ns, ProbePort: uint16(o.probePort)},
		Logger:  logger, Metrics: telemetry.NewControllerMetrics(reg), Tracer: telemetry.NewTracer(logger, nil),
	})
	if err != nil {
		return err
	}
	go srv.Run(ctx)

	hs := &http.Server{Addr: o.listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	logger.Info("starting", "build", buildinfo.String("controller"), "listen", o.listen,
		"gateway_token", telemetry.Secret(gwToken), "client_token", telemetry.Secret(clToken))
	if o.tlsCert != "" {
		err = hs.ListenAndServeTLS(o.tlsCert, o.tlsKey)
	} else {
		err = hs.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		logger.Info("shut down")
		return nil
	}
	return err
}
