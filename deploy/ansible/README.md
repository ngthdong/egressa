# VPS testbed with Ansible

Deploys egressa on VPS: one controller, two or more gateways and any
number of test clients, from an inventory of IPs.

```sh
cp deploy/ansible/inventory.example.ini deploy/ansible/inventory.ini   # fill in the IPs
ansible-galaxy collection install -r deploy/ansible/requirements.yml
make testbed-up          # make cross, then site.yml
make testbed-status
make scenario S=a        # a, b or c: see deploy/scenarios
make testbed-down
```

The hosts need Ubuntu (22.04 or 24.04) with systemd, root over SSH (or
`ansible_user` with sudo), on x86_64 or arm64. The machine running
Ansible needs `openssl` (for the controller's certificate). Inventory
lines may be names with `ansible_host=<ip>`; the address used everywhere
is `ansible_host`, else the name.

## What site.yml does

1. **Preflight** fails early, saying what to do: `sch_netem` (install
   `linux-modules-extra-$(uname -r)`), `tun`, and with
   `egressa_backend=ipsec` also `xfrm_interface` and `esp4`; whether IP
   forwarding can be turned on; that `make cross` has built the binaries.
   A missing kernel `wireguard` module is only noted: egressa runs
   WireGuard in userspace.
2. **TLS**: on the machine running Ansible, a private CA and a
   certificate for the controller's address (see Secrets).
3. **Common**: chrony (and waits until the clock is within 50 ms: the
   scenarios start on every host at the same second), `vpnctl`, the
   scenarios.
4. **Firewall** (ufw, deny by default): SSH; the metrics port from
   `prometheus_source` only; the controller's API port; on gateways the
   client WireGuard port, all UDP from the other gateways (backbone
   tunnels listen on ports picked at start) and, for IPsec, UDP 500/4500
   and ESP. The probe port (UDP 51900 on the gateway's node IP) is not
   opened here: probes arrive through the tunnel interfaces, and the
   gateway inserts an INPUT rule for exactly that itself and removes it
   when it stops. `deploy/local/testbed.sh` with `FIREWALL=1` applies the
   same rules to the local testbed's gateways, and `TestLocalTestbedFirewall`
   checks every path is still measured behind them.
5. **Controller**, **gateways**, **clients**: binary, secrets, a systemd
   unit (`egressa-controller`, `egressa-gateway`; clients use the
   `egressa.service` that `egressa connect` installs). Gateways with
   `egressa_backend=ipsec` also get strongSwan (`charon-systemd`,
   `strongswan-swanctl`). Gateways are deployed one at a time: after a
   gateway (re)starts, the play waits until it answers `/healthz`, has
   applied the controller's state and every backbone it has is up
   (`egressa_gateway_backbone_up`), so the sessions of the others keep
   running. Clients connect at once, in full tunnel, with bypass routes
   for the SSH session's source and the Prometheus host.

The roles are meant to be idempotent, and `make cross` builds the same
binaries from the same commit (`-trimpath`, the commit's time as build
time), so a second `make testbed-up` with no change in between should end
with `changed=0` on every host and restart nothing.

## Secrets

The gateway token, the client token and the IPsec master key are
generated on the machine running Ansible, in `deploy/ansible/.secrets/`
(git-ignored), and copied to the hosts that need them as root-only
files under `/etc/egressa/`. Each gateway generates its own private key on
the host. Nothing secret is in the inventory or the playbooks.

The controller's API is HTTPS (`egressa_tls: true`, the default): the
tokens and the gateways' public keys cross it.

- By default `roles/tls/files/gen-tls.sh` keeps a private CA and a
  certificate for the controller in `deploy/ansible/.secrets/tls/`, with
  the controller's address (`ansible_host`, an IP) in the subjectAltName.
  It runs on every `make testbed-up` and changes nothing unless the
  address changed or a certificate is within 30 days of expiring. The
  controller gets the certificate and key (root-only files); gateways and
  clients add the CA to the system trust store
  (`/usr/local/share/ca-certificates/egressa-ca.crt`), which the egressa
  binaries read. Keep `ca.key` as secret as the tokens: it can mint a
  certificate every gateway and client trusts.
- Your own certificate (e.g. Let's Encrypt for a DNS name): set
  `egressa_tls_cert_file` and `egressa_tls_key_file` (paths on the
  machine running Ansible) and `egressa_controller_address` to the name
  it is for. No CA is generated or installed then.
- `egressa_tls: false` serves plain HTTP, tokens in the clear.

## Variables

See `group_vars/all.yml`: `egressa_backend` (`wireguard` or `ipsec`),
`egressa_tls*`, ports, the overlay (`egressa_client_subnet`,
`egressa_node_subnet`, `egressa_probe_port`, passed to the controller
explicitly), `egressa_policy` (short flap-guard timers so a scenario's
migrations show within its run time). Per host: `gateway_id=` (required
on gateways), `gateway_roles=` (default `access,egress`), and on clients
`name=` and `exit=` (the egress gateway; default the first gateway).

## Metrics

Every process serves `/metrics` and `/healthz` on port 9101 (not 9100,
which is node_exporter's; set `egressa_metrics_port`), reachable
only from `prometheus_source`. On that host:

```sh
make observability-targets      # deploy/observability/targets/vps.json from the inventory
GRAFANA_ADMIN_PASSWORD=... make observability-up
ssh -L 3300:127.0.0.1:3300 <prometheus host>    # if it is not your machine; then http://127.0.0.1:3300
```
