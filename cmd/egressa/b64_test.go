//go:build linux

package main

import "encoding/base64"

func base64RawURL(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
