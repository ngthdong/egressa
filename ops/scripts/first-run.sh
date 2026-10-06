#!/usr/bin/env bash
# First bootstrap from your PERSONAL computer, as the admin user (password sudo), before CI/CD exists.
# Keep a second SSH session to each server open while this runs.
set -euo pipefail
cd "$(dirname "$0")/.."
 
: "${CONTROLLER_IP:?export CONTROLLER_IP}" "${GATEWAY1_IP:?export GATEWAY1_IP}" "${GATEWAY2_IP:?export GATEWAY2_IP}"
: "${GRAFANA_ADMIN_PASSWORD:?export GRAFANA_ADMIN_PASSWORD}"   # TELEGRAM_* only needed if telegram_enabled=true
: "${CONTROLLER_URL:?export CONTROLLER_URL (https://host:8080)}"
: "${EGRESSA_GATEWAY_TOKEN:?export EGRESSA_GATEWAY_TOKEN (openssl rand -hex 32)}" "${EGRESSA_CLIENT_TOKEN:?export EGRESSA_CLIENT_TOKEN}"
: "${CONTROLLER_TLS_CERT:?export CONTROLLER_TLS_CERT (PEM text)}" "${CONTROLLER_TLS_KEY:?export CONTROLLER_TLS_KEY (PEM text)}"
export ANSIBLE_REMOTE_USER="${ANSIBLE_REMOTE_USER:-isQHung}"
 
ansible-galaxy collection install -r requirements.yml
echo ">> Building Egressa binaries"
scripts/build-artifacts.sh
echo ">> Syntax check"
ansible-playbook playbooks/site.yml --syntax-check
echo ">> Applying as ${ANSIBLE_REMOTE_USER} (you will be asked for the sudo password)"
ansible-playbook playbooks/site.yml --ask-become-pass --diff "$@"
echo ">> Verify"
ansible-playbook playbooks/verify.yml --ask-become-pass
 