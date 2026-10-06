#!/usr/bin/env bash
# Generates the CI/CD key pair. The private key goes to GitHub Secrets, the public key to
# inventory/group_vars/all.yml (ssh_authorized_keys.deploy). Never commit the private key.
set -euo pipefail
dir="$(mktemp -d)"
ssh-keygen -t ed25519 -N "" -C "github-actions-deploy" -f "$dir/deploy_key" >/dev/null
echo "=== PUBLIC key (paste into ssh_authorized_keys.deploy) ==="
cat "$dir/deploy_key.pub"
echo
echo "=== Set the PRIVATE key as a GitHub secret, then delete it ==="
echo "gh secret set DEPLOY_SSH_PRIVATE_KEY --env production < $dir/deploy_key && shred -u $dir/deploy_key"
echo
echo "=== Known hosts secret (verify the fingerprints out-of-band first) ==="
echo 'ssh-keyscan -p 22 "$CONTROLLER_IP" "$GATEWAY1_IP" "$GATEWAY2_IP" | gh secret set SSH_KNOWN_HOSTS --env production'
