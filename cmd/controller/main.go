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
	"log"
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
)

func main() {
	var (
		showVersion  = flag.Bool("version", false, "print version and exit")
		listen       = flag.String("listen", ":8080", "HTTP listen address")
		stateFile    = flag.String("state-file", "", "keep state in this JSON file (default: in memory only, lost on restart)")
		etcdEndpoint = flag.String("etcd", "", "keep state in etcd at this endpoint instead (needs a build with -tags etcd)")
		gwTokenFile  = flag.String("gateway-token-file", "", "file holding the gateway token (default: $EGRESSA_GATEWAY_TOKEN)")
		clTokenFile  = flag.String("client-token-file", "", "file holding the client token (default: $EGRESSA_CLIENT_TOKEN)")
		clientSubnet = flag.String("client-subnet", "10.201.0.0/16", "client virtual IPs are allocated from here")
		nodeSubnet   = flag.String("node-subnet", "10.200.0.0/24", "gateway node IPs are allocated from here")
		probePort    = flag.Uint("probe-port", 51900, "UDP port gateways answer probes on")
		policyFile   = flag.String("policy", "", "JSON policy document (cost weights, decision thresholds, flap guard) to set on start")
		tlsCert      = flag.String("tls-cert", "", "serve HTTPS with this certificate")
		tlsKey       = flag.String("tls-key", "", "and this key")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("controller"))
		return
	}
	if err := run(*listen, *stateFile, *etcdEndpoint, *gwTokenFile, *clTokenFile, *clientSubnet, *nodeSubnet, *probePort, *policyFile, *tlsCert, *tlsKey); err != nil {
		log.Fatalf("controller: fatal: %v", err)
	}
}

func run(listen, stateFile, etcdEndpoint, gwTokenFile, clTokenFile, clientSubnet, nodeSubnet string, probePort uint, policyFile, tlsCert, tlsKey string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cs, err := netip.ParsePrefix(clientSubnet)
	if err != nil {
		return fmt.Errorf("--client-subnet: %w", err)
	}
	ns, err := netip.ParsePrefix(nodeSubnet)
	if err != nil {
		return fmt.Errorf("--node-subnet: %w", err)
	}
	if probePort == 0 || probePort > 65535 {
		return fmt.Errorf("bad --probe-port %d", probePort)
	}
	gwToken, err := cliutil.Secret(gwTokenFile, "EGRESSA_GATEWAY_TOKEN")
	if err != nil {
		return err
	}
	clToken, err := cliutil.Secret(clTokenFile, "EGRESSA_CLIENT_TOKEN")
	if err != nil {
		return err
	}
	if gwToken == "" || clToken == "" {
		log.Printf("controller: WARNING: a gateway or client token is empty; anyone who reaches %s can use that API", listen)
	}

	var store control.KVStore
	switch {
	case etcdEndpoint != "" && stateFile != "":
		return errors.New("give --etcd or --state-file, not both")
	case etcdEndpoint != "":
		s, closeFn, err := openEtcd(etcdEndpoint)
		if err != nil {
			return err
		}
		defer closeFn()
		store = s
	case stateFile != "":
		s, err := controller.OpenFileStore(stateFile)
		if err != nil {
			return err
		}
		store = s
	default:
		log.Printf("controller: WARNING: no --state-file or --etcd; sessions are lost on restart")
		store = control.NewMemStore()
	}

	var policy *control.PolicyDocument
	if policyFile != "" {
		data, err := os.ReadFile(policyFile)
		if err != nil {
			return err
		}
		doc := control.DefaultPolicyDocument
		if err := json.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("--policy %s: %w", policyFile, err)
		}
		policy = &doc
	}

	srv, err := controller.New(ctx, controller.Config{
		Store: store, GatewayToken: gwToken, ClientToken: clToken, Policy: policy,
		Network: api.Network{ClientSubnet: cs, NodeSubnet: ns, ProbePort: uint16(probePort)},
	})
	if err != nil {
		return err
	}
	go srv.Run(ctx)

	hs := &http.Server{Addr: listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	log.Printf("controller: starting (%s), listening on %s", buildinfo.String("controller"), listen)
	if tlsCert != "" {
		err = hs.ListenAndServeTLS(tlsCert, tlsKey)
	} else {
		err = hs.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		log.Printf("controller: shut down")
		return nil
	}
	return err
}
