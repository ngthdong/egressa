#!/usr/bin/env bash
# Builds the Egressa controller and gateway (linux, static) into ops/artifacts/.
# Used by CD and by first-run.sh. EGRESSA_GOARCH must match the servers
# (uname -m: x86_64=amd64, aarch64=arm64).
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
out="${1:-$repo_root/ops/artifacts}"

case "${EGRESSA_GOARCH:-amd64}" in
  amd64|arm64) ;;
  *)
    echo "EGRESSA_GOARCH must be amd64 or arm64" >&2
    exit 2
    ;;
esac

export GOOS=linux GOARCH="${EGRESSA_GOARCH:-amd64}" CGO_ENABLED=0
cd "$repo_root"
make build
mkdir -p "$out"
install -m 0755 bin/controller bin/gateway "$out/"
( cd "$out" && sha256sum controller gateway )
