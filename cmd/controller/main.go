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
		showVersion  = flag.Bool("version", false, "print version and exit")
		etcdEndpoint = flag.String("etcd", "127.0.0.1:2379", "etcd endpoint")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(buildinfo.String("controller"))
		return
	}

	if err := run(*etcdEndpoint); err != nil {
		log.Fatalf("controller: fatal: %v", err)
	}
}

func run(etcdEndpoint string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("controller: starting (%s)", buildinfo.String("controller"))
	log.Printf("controller: etcd = %s", etcdEndpoint)
	log.Printf("controller: ready")

	<-ctx.Done()
	log.Printf("controller: shutting down")
	return nil
}
