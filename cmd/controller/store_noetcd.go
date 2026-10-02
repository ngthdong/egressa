//go:build !etcd

package main

import (
	"errors"

	"github.com/ngthdong/egressa/internal/control"
)

func openEtcd(string) (control.KVStore, func(), error) {
	return nil, nil, errors.New("this controller was built without etcd support; rebuild with -tags etcd, or use --state-file")
}
