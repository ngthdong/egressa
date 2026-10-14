# Metrics

Every binary serves Prometheus metrics on `/metrics` when started with
`--metrics-listen <addr>` (`egressa run` takes `metrics_listen` in
`/etc/egressa/client.conf`). The port has no authentication: bind it to a
private address and let only the Prometheus host reach it.

Conventions: times are in seconds, ratios in 0..1. Label values come from a
fixed set or from gateway IDs; no label ever holds a session ID, a virtual
IP, a URL or an error message. Gauges are exported from the newest snapshot
an agent took, so a gateway or path that leaves the agent's state leaves the
next scrape. Every process also exports the Go runtime (`go_*`) and process
(`process_*`) collectors.

This table is checked against the code: `internal/telemetry`'s tests fail if
a metric is registered but not listed here, or listed but not registered.

## All processes

| Metric | Type | Unit | Labels | Meaning |
|---|---|---|---|---|
| `egressa_build_info` | gauge | 1 | `role`, `version`, `commit` | Always 1; which build runs where |

## Client

| Metric | Type | Unit | Labels | Meaning |
|---|---|---|---|---|
| `egressa_client_segment_rtt_seconds` | gauge | s | `gateway`, `percentile` (`50`, `95`) | RTT from the client to an access gateway, measured through the tunnel |
| `egressa_client_segment_loss_ratio` | gauge | ratio | `gateway` | Probe loss to an access gateway |
| `egressa_client_segment_confidence` | gauge | 0..1 | `gateway` | Trust in that measurement (sample count times freshness) |
| `egressa_client_path_cost_seconds` | gauge | s | `access`, `egress` | Cost of a usable path: median RTT plus tail and loss penalties over its segments |
| `egressa_client_path_usable` | gauge | 0/1 | `access`, `egress` | The cost is finite (no loss or capacity gate) and every segment is measured |
| `egressa_client_path_reachable` | gauge | 0/1 | `access`, `egress` | The client heard back through the access gateway recently: a warm standby |
| `egressa_client_path_delta_lower_seconds` | gauge | s | `access`, `egress` | Lower confidence bound of Cost(current) − Cost(this path); above the threshold, the path is better enough to move to |
| `egressa_client_decision_threshold_seconds` | gauge | s | | Improvement a migration must clear: migration cost plus safety margin |
| `egressa_client_active_path` | gauge | 0/1 | `access`, `egress` | 1 for the path the session is on |
| `egressa_client_session_epoch` | gauge | count | | The session's epoch; it rises by one per migration |
| `egressa_client_current_path_dead` | gauge | 0/1 | | The current path stopped answering (cut over at once) |
| `egressa_client_controller_up` | gauge | 0/1 | | The client's last request to the controller got an answer |
| `egressa_client_decisions_total` | counter | | `outcome` (`stay`, `confirming`, `migrate`, `no_alternative`) | Decision passes (every 500 ms); `confirming` means a better path is waiting on the flap guard |
| `egressa_client_migrations_total` | counter | | `cause` (`better_path`, `access_dead`, `egress_change`, `external`), `result` (`committed`, `conflict`, `failed`) | Migrations |
| `egressa_client_migration_duration_seconds` | histogram | s | `cause` | From the decision to the new path in use, committed migrations only |

## Gateway

| Metric | Type | Unit | Labels | Meaning |
|---|---|---|---|---|
| `egressa_gateway_backbone_rtt_seconds` | gauge | s | `peer`, `percentile` (`50`, `95`) | RTT over the backbone tunnel to a peer gateway |
| `egressa_gateway_backbone_loss_ratio` | gauge | ratio | `peer` | Probe loss over that backbone |
| `egressa_gateway_backbone_up` | gauge | 0/1 | `peer` | That backbone tunnel has completed a handshake |
| `egressa_gateway_sessions` | gauge | count | `role` (`access`, `egress`) | Sessions this gateway carries |
| `egressa_gateway_fenced_packets_total` | counter | | | Client packets dropped for an epoch older than their session's (WireGuard clients) |
| `egressa_gateway_state_version` | gauge | count | | Controller state version last applied |
| `egressa_gateway_controller_up` | gauge | 0/1 | | The gateway's last request to the controller got an answer |
| `egressa_gateway_apply_errors_total` | counter | | | Passes that failed to make the host match the controller's state |
| `egressa_gateway_link_reports_total` | counter | | `result` (`ok`, `error`) | Backbone reports (the heartbeat) sent to the controller |

## Controller

| Metric | Type | Unit | Labels | Meaning |
|---|---|---|---|---|
| `egressa_controller_http_requests_total` | counter | | `route` (mux pattern or `unmatched`), `code` | API requests |
| `egressa_controller_http_request_duration_seconds` | histogram | s | `route` | API request duration, without the two state long polls |
| `egressa_controller_gateways` | gauge | count | `alive` (`true`, `false`) | Registered gateways (the members), by whether they report |
| `egressa_controller_sessions` | gauge | count | | Sessions in the store |
| `egressa_controller_state_version` | gauge | count | | Version of the state served; rises on every change |
| `egressa_controller_migrations_total` | counter | | `result` (`committed`, `conflict`, `rejected`, `error`) | Migration requests; `conflict` is a lost compare-and-swap on the epoch |

## What is not a metric

- **Jitter** is not exported on its own. The spread between the 95th and 50th
  percentile of `egressa_client_segment_rtt_seconds` (and of the backbone
  RTT) is the measure of variation the decision uses, and dashboards show it
  as jitter.
- **Flap guard state** is not exported as such: `egressa_client_decisions_total{outcome="confirming"}`
  rising means a better path is waiting for the confirmation window or the
  minimum residence time.
- **Migration phases** are not metrics but spans in the logs (`migration.decide`,
  `.commit`, `.cas`, `.apply`, `.switch`); `vpnctl trace` prints them as a
  timeline.
- **IPsec SAs** (client → access gateway) are not exported; `ip xfrm state`
  and `swanctl --list-sas` show them.
