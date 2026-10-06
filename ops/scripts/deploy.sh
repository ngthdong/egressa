#!/usr/bin/env bash
# Usage: scripts/deploy.sh check|apply [ansible-playbook args, e.g. --limit vpn-gw1 --tags ufw]
set -euo pipefail
cd "$(dirname "$0")/.."
mode="${1:?usage: deploy.sh check|apply [args]}"; shift || true

ansible-playbook playbooks/site.yml --syntax-check
case "$mode" in
  check) ansible-playbook playbooks/site.yml --check --diff "$@" ;;
  apply) ansible-playbook playbooks/site.yml --diff "$@" && ansible-playbook playbooks/verify.yml "$@" ;;
  *) echo "mode must be check or apply" >&2; exit 2 ;;
esac
