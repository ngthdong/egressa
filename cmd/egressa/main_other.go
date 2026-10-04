//go:build !linux

// Command egressa is the VPN client as users run it. It needs Linux:
// systemd or a detached process, sudo, iproute2 and a Linux TUN device.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "egressa: this client runs on Linux only")
	os.Exit(1)
}
