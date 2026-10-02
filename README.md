# Egressa

Multi-Gateway VPN with Per-User Traffic Path Optimization.

A client keeps a WireGuard tunnel to every access gateway, measures the path
through each one, and moves its session to a better path when one is better by
enough, for long enough. Session ID and virtual IP never change. The egress
gateway (the public IP the Internet sees) only changes if no path to it works,
so open TCP connections survive every other move.

```
client ──► access gateway ──backbone──► egress gateway ──► Internet
```

A detour such as `client → SG → HK` is compared with the direct path
`client → HK` end to end. The backbone segment `SG → HK` counts against the
detour, so a fast first hop does not win if the backbone behind it is slow.

## Components

| Binary       | Role |
|--------------|------|
| `controller` | Control plane. Registers gateways, opens sessions, and commits migrations with an epoch compare-and-swap. HTTP API (`internal/api`). |
| `gateway`    | Runs on each gateway host: client tunnel, one backbone tunnel per other gateway, policy routing, NAT (egress only), epoch fencing, backbone probing. Needs root. |
| `client`     | Runs on the user's machine: one tunnel to every access gateway, probes through each, the migration decision. Needs root. |

## Running

Build with `make build`; the binaries go to `bin/`.

**Controller** (one, reachable by every gateway and client):

```sh
export EGRESSA_GATEWAY_TOKEN=$(openssl rand -hex 32)
export EGRESSA_CLIENT_TOKEN=$(openssl rand -hex 32)
bin/controller --listen :8080 --state-file /var/lib/egressa/controller.json \
    --tls-cert cert.pem --tls-key key.pem
```

It keeps its state in the file (or, built with `-tags etcd`, in etcd via
`--etcd host:2379`). Without TLS, run it on a private network only. It can
also load a policy file with `--policy policy.json`: cost weights, decision
thresholds and flap-guard timers; see `control.PolicyDocument`.

**Gateway** (on each region's host; give it the gateway token):

```sh
EGRESSA_GATEWAY_TOKEN=... bin/gateway --id hk --controller https://ctl:8080 \
    --role access,egress --endpoint <public-ip>:51820 --uplink eth0
```

Open UDP 51820 and the backbone ports, which are random UDP ports, to the
other gateways. On exit, the gateway removes every route, rule and iptables
entry it added.

**Client** (give it the client token):

```sh
EGRESSA_CLIENT_TOKEN=... bin/client --controller https://ctl:8080 --egress hk --full-tunnel
```

The client keeps its key and session in `--state-file`
(`/var/lib/egressa/client.json`), so a restart gets the same session and
virtual IP back. `--full-tunnel` sends all traffic through the VPN. The
gateways and the controller stay reachable directly, and the original route
is restored on exit. Every 10 s it logs the cost of each path.

`EGRESSA_WG_DEBUG=1` makes the gateway or client log every WireGuard handshake
and keepalive.

`bin/client --connect --gateway-pubkey ... --gateway-endpoint ...` is the old
static mode: one gateway, no controller, no path selection.

## Tests

```sh
make test-race                           # unit tests
go test -v -run TestManagedMigration ./internal/e2e/
```

The end-to-end test runs the real binaries: a controller, gateways `hk` and
`sg`, a client and an "Internet" server, each in its own network namespace.
Without root, it re-executes itself in an unprivileged user namespace. It
shapes the links with netem and checks four things:

1. The direct path degrades: the client moves to the detour, keeping egress `hk`.
2. The backbone degrades: the client moves back.
3. The direct path is mildly worse, but the detour's backbone is slow: the client stays.
4. The direct path dies: the client cuts over at once.

Through all four, one TCP connection stays open, and the server always sees
`hk`'s address.

## Limits (current version)

- One controller. Clients keep working when it is down, but cannot migrate
  until it is back.
- The data plane is WireGuard. The IPsec backend (`internal/ipsec`) is not wired
  into the binaries yet.
- The client chooses its egress at session start; it changes only when no path to
  it works, and that breaks open connections.
- Gateways and sessions are never deleted; a stopped gateway is only marked not alive.
- Destination groups and traffic classes (`measurement.DestinationGroups`) are not
  used yet: the path is chosen per session, not per destination.
