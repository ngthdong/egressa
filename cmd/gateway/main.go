package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ngthdong/egressa/internal/buildinfo"
)

func main() {
	var (
		showVersion = flag.Bool("version", false, "print version and exit")
		role        = flag.String("role", "access,egress", "roles this gateway plays")
		listenAddr  = flag.String("listen", ":51820", "data-plane listen address")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("gateway"))
		return
	}

	if err := run(*role, *listenAddr); err != nil {
		log.Fatalf("gateway: fatal: %v", err)
	}
}

func run(role, listenAddr string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("gateway: starting (%s)", buildinfo.String("gateway"))
	log.Printf("gateway: role = %s", role)
	log.Printf("gateway: listen = %s", listenAddr)
	log.Printf("gateway: ready")

	<-ctx.Done()
	log.Printf("gateway: shutting down")
	return nil
}
