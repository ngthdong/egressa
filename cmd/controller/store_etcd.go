//go:build etcd

package main

import (
	"fmt"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/ngthdong/egressa/internal/control"
)

func openEtcd(endpoint string) (control.KVStore, func(), error) {
	cli, err := clientv3.New(clientv3.Config{Endpoints: []string{endpoint}, DialTimeout: 5 * time.Second})
	if err != nil {
		return nil, nil, fmt.Errorf("connect to etcd at %s: %w", endpoint, err)
	}
	return control.NewEtcdStore(cli), func() { _ = cli.Close() }, nil
}
