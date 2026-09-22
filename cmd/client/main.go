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
		controller  = flag.String("controller", "127.0.0.1:2379", "controller (etcd) endpoint")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("client"))
		return
	}

	if err := run(*controller); err != nil {
		log.Fatalf("client: fatal: %v", err)
	}
}

func run(controller string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("client: starting (%s)", buildinfo.String("client"))
	log.Printf("client: controller = %s", controller)
	log.Printf("client: ready")

	<-ctx.Done()
	log.Printf("client: shutting down")
	return nil
}
