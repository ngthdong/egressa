#!/usr/bin/env bash
# egressa local testbed: the whole system on one machine, in network
# namespaces, running the real binaries.
#
#   deploy/local/testbed.sh up | down | status
#
#   egtb-ctl    controller        WAN 10.77.0.2     mgmt 10.79.0.2
#   egtb-gw<n>  gateway gw<n>     WAN 10.77.0.1<n>  mgmt 10.79.0.1<n>  Internet 10.78.0.1<n>
#   egtb-cli    client            WAN 10.77.0.100   mgmt 10.79.0.100
#   egtb-inet   Internet target   Internet 10.78.0.10 (HTTP on :8000)
#
# The client reaches 10.78.0.0/24 only through the VPN. The host sits on
# the management bridge (10.79.0.1), from which Prometheus scrapes every
# process's /metrics on :9100.
#
# Settings (environment):
#   GATEWAYS=2|3          number of gateways (default 2)
#   BACKEND=auto|wireguard|ipsec
#                         client -> access gateway data plane (default auto:
#                         IPsec when the kernel and charon allow, else
#                         WireGuard, saying why)
#   RUN_DIR               state, logs, secrets (default deploy/local/.run)
#   BIN_DIR               prebuilt binaries (default: built into RUN_DIR/bin)
#   TARGETS_FILE          Prometheus file_sd targets written on up (default
#                         deploy/observability/targets/local.json)
#   CHARON, CHARON_PRELOAD  charon binary and an LD_PRELOADed vici plugin,
#                         for hosts whose charon lacks vici or is confined
#   FIREWALL=1            give each gateway the host firewall the Ansible
#                         firewall role sets up on a VPS (INPUT policy DROP,
#                         only its openings), before the gateway starts
#
# Needs root (CAP_NET_ADMIN on the host): sudo make testbed-local-up.
# `up` twice is harmless; `down` clears everything, also after a failed up.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
RUN_DIR=${RUN_DIR:-$HERE/.run}
GATEWAYS=${GATEWAYS:-2}
BACKEND=${BACKEND:-auto}
TARGETS_FILE=${TARGETS_FILE:-$REPO/deploy/observability/targets/local.json}
FIREWALL=${FIREWALL:-0}
P=egtb

WAN_NET=10.77.0
INET_NET=10.78.0
MGMT_NET=10.79.0
CTL_URL="http://$WAN_NET.2:8080"

log() { printf '[testbed] %s\n' "$*" >&2; }
die() { log "error: $*"; exit 1; }

gw_ids() { local i; for ((i = 1; i <= GATEWAYS; i++)); do echo "gw$i"; done; }
in_ns() { local ns=$1; shift; nsenter --net="/run/netns/$P-$ns" -- "$@"; }
ns_exists() { ip netns list 2>/dev/null | awk '{print $1}' | grep -qx "$P-$1"; }
link_exists() { ip link show "$1" >/dev/null 2>&1; }

need_root() {
	[[ $(id -u) -eq 0 ]] || die "needs root: sudo make testbed-local-$1"
	for t in ip tc nsenter iptables; do
		command -v "$t" >/dev/null || die "$t is missing (install iproute2 / iptables / util-linux)"
	done
	[[ -c /dev/net/tun ]] || die "/dev/net/tun is missing: the kernel has no TUN support"
}


# probe runs a command in a throwaway namespace; it says whether the
# kernel can do what the command asks.
probe() {
	local ns=$P-probe ok=0
	ip netns del "$ns" 2>/dev/null || true
	ip netns add "$ns" || die "cannot create network namespaces"
	nsenter --net="/run/netns/$ns" -- ip link set lo up
	if nsenter --net="/run/netns/$ns" -- "$@" >/dev/null 2>&1; then ok=1; fi
	ip netns del "$ns"
	[[ $ok == 1 ]]
}

check_netem() {
	probe sh -c 'tc qdisc add dev lo root netem delay 1ms' ||
		die "the kernel cannot load sch_netem; on Ubuntu install linux-modules-extra-$(uname -r)"
}

find_charon() {
	[[ -n ${CHARON:-} ]] && { echo "$CHARON"; return; }
	local p
	for p in /usr/lib/ipsec/charon /usr/libexec/ipsec/charon /usr/lib/strongswan/charon /usr/libexec/strongswan/charon; do
		[[ -x $p ]] && { echo "$p"; return; }
	done
}

# pick_backend prints the backend to use, logging why when it falls back.
pick_backend() {
	case $BACKEND in
	wireguard) echo wireguard; return ;;
	ipsec | auto) ;;
	*) die "BACKEND must be auto, wireguard or ipsec, not $BACKEND" ;;
	esac
	local why=""
	if ! probe ip link add x0 type xfrm if_id 1; then
		why="the kernel has no XFRM interfaces (xfrm_interface)"
	elif ! probe ip xfrm state add src 192.0.2.1 dst 192.0.2.2 proto esp spi 0x100 reqid 1 mode tunnel \
		aead 'rfc4106(gcm(aes))' 0x0000000000000000000000000000000000000000 128; then
		why="the kernel has no ESP with AES-GCM (esp4)"
	elif [[ -z $(find_charon) ]]; then
		why="there is no charon (install strongswan-charon and strongswan-swanctl)"
	elif [[ -z ${CHARON_PRELOAD:-} ]] && ! ls /usr/lib/ipsec/plugins/libstrongswan-vici.so >/dev/null 2>&1 &&
		! ls /usr/lib/*/ipsec/plugins/libstrongswan-vici.so >/dev/null 2>&1; then
		why="charon has no vici plugin (install strongswan-swanctl)"
	fi
	if [[ -n $why ]]; then
		[[ $BACKEND == ipsec ]] && die "BACKEND=ipsec, but $why"
		log "IPsec is not available: $why; the client uses WireGuard instead"
		echo wireguard
		return
	fi
	echo ipsec
}

# --- binaries and secrets ---------------------------------------------------

binaries() {
	if [[ -n ${BIN_DIR:-} ]]; then
		echo "$BIN_DIR"
		return
	fi
	local bin=$RUN_DIR/bin
	if [[ ! -x $bin/egressa || ! -x $bin/gateway || ! -x $bin/controller || ! -x $bin/vpnctl ]]; then
		command -v go >/dev/null || die "go is not installed; build the binaries and set BIN_DIR"
		log "building the binaries into $bin"
		mkdir -p "$bin"
		(cd "$REPO" && CGO_ENABLED=0 go build -o "$bin/" ./cmd/controller ./cmd/gateway ./cmd/egressa ./cmd/vpnctl) >&2
	fi
	echo "$bin"
}

secret() {
	local f=$RUN_DIR/secrets/$1
	if [[ ! -s $f ]]; then
		mkdir -p "$RUN_DIR/secrets"
		chmod 700 "$RUN_DIR/secrets"
		(umask 077 && od -An -tx1 -N32 /dev/urandom | tr -d ' \n' >"$f")
	fi
	cat "$f"
}

# --- network ----------------------------------------------------------------

ensure_bridge() {
	link_exists "$1" || ip link add "$1" type bridge
	ip link set "$1" up
}

ensure_ns() {
	ns_exists "$1" || ip netns add "$P-$1"
	in_ns "$1" ip link set lo up
}

# ensure_link NS DEV BRIDGE ADDR: a veth with DEV inside NS, on BRIDGE.
ensure_link() {
	local ns=$1 dev=$2 br=$3 addr=$4 host="$P-$1-${2:0:1}"
	if ! in_ns "$ns" ip link show "$dev" >/dev/null 2>&1; then
		ip link del "$host" 2>/dev/null || true
		ip link add "$host" type veth peer name "$dev" netns "$P-$ns"
	fi
	ip link set "$host" master "$br"
	ip link set "$host" up
	in_ns "$ns" ip addr replace "$addr/24" dev "$dev"
	in_ns "$ns" ip link set "$dev" up
}

# With br_netfilter loaded (Docker loads it), frames crossing our bridges
# go through the host's FORWARD chain, whose policy Docker sets to DROP.
FWD_RULE=(FORWARD -i "$P-+" -o "$P-+" -j ACCEPT)

network_up() {
	ensure_bridge "$P-wan"
	ensure_bridge "$P-net"
	ensure_bridge "$P-mgmt"
	iptables -C "${FWD_RULE[@]}" 2>/dev/null || iptables -I "${FWD_RULE[@]}"
	ip addr replace "$MGMT_NET.1/24" dev "$P-mgmt"
	local i
	ensure_ns ctl
	ensure_link ctl wan0 "$P-wan" "$WAN_NET.2"
	ensure_link ctl mgmt0 "$P-mgmt" "$MGMT_NET.2"
	for ((i = 1; i <= GATEWAYS; i++)); do
		ensure_ns "gw$i"
		ensure_link "gw$i" wan0 "$P-wan" "$WAN_NET.1$i"
		ensure_link "gw$i" inet0 "$P-net" "$INET_NET.1$i"
		ensure_link "gw$i" mgmt0 "$P-mgmt" "$MGMT_NET.1$i"
	done
	ensure_ns cli
	ensure_link cli wan0 "$P-wan" "$WAN_NET.100"
	ensure_link cli mgmt0 "$P-mgmt" "$MGMT_NET.100"
	ensure_ns inet
	ensure_link inet inet0 "$P-net" "$INET_NET.10"
}

# --- processes --------------------------------------------------------------

running() { [[ -s $RUN_DIR/pids/$1 ]] && kill -0 "$(cat "$RUN_DIR/pids/$1")" 2>/dev/null; }

# start NAME NS CMD...: runs CMD inside NS in the background, once.
start() {
	local name=$1 ns=$2
	shift 2
	if running "$name"; then
		return
	fi
	mkdir -p "$RUN_DIR/pids" "$RUN_DIR/logs"
	# exec all the way down (nsenter and setsid exec too), so the pid
	# recorded is the program's own, not a wrapper's that a kill would
	# leave the program running behind.
	(exec nsenter --net="/run/netns/$P-$ns" -- setsid "$@" >>"$RUN_DIR/logs/$name.log" 2>&1 </dev/null) &
	echo $! >"$RUN_DIR/pids/$name"
}

wait_for() {
	local what=$1 tries=$2
	shift 2
	local i
	for ((i = 0; i < tries; i++)); do
		"$@" >/dev/null 2>&1 && return 0
		sleep 0.5
	done
	die "$what did not come up; see $RUN_DIR/logs"
}

start_charon() {
	local ns=$1 dir=$RUN_DIR/charon/$1 charon
	charon=$(find_charon)
	mkdir -p "$dir"
	cat >"$dir/strongswan.conf" <<EOF
charon {
  load_modular = yes
  install_routes = no
  install_virtual_ip = no
  plugins {
    include /etc/strongswan.d/charon/*.conf
    vici {
      load = yes
      socket = unix://$dir/charon.vici
    }
  }
  filelog {
    egressa {
      path = $RUN_DIR/logs/charon-$ns.log
      default = 1
      flush_line = yes
    }
  }
}
EOF
	# shellcheck disable=SC2016 # expanded by the inner sh
	local script='mount -t tmpfs tmpfs /run && exec "$0"'
	local args=("$charon")
	if [[ -n ${CHARON_PRELOAD:-} ]]; then
		# shellcheck disable=SC2016
		script='mount -t tmpfs tmpfs /run && export LD_PRELOAD="$1" && exec "$0"'
		args+=("$CHARON_PRELOAD")
	fi
	STRONGSWAN_CONF=$dir/strongswan.conf start "charon-$ns" "$ns" unshare -m -- sh -c "$script" "${args[@]}"
	wait_for "charon in $ns" 40 test -S "$dir/charon.vici"
}

# firewall_gateway N gives gateway gwN's namespace what
# deploy/ansible/roles/firewall gives a gateway VPS: INPUT policy DROP, and
# only loopback, replies, the client WireGuard port, all UDP from the
# other gateways (backbone), the metrics port from the management network
# (the Prometheus host) and, for IPsec, IKE, NAT-T and ESP. Keep the two in
# step. The gateway itself opens the probe port on its tunnel interfaces.
# It goes in a chain of its own, so a second up does not touch the rules
# the running gateway inserted into INPUT.
firewall_gateway() {
	local n=$1 backend=$2 ns="gw$1" j
	in_ns "$ns" iptables -N egtb-fw 2>/dev/null || true
	in_ns "$ns" iptables -F egtb-fw
	in_ns "$ns" iptables -A egtb-fw -i lo -j ACCEPT
	in_ns "$ns" iptables -A egtb-fw -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	in_ns "$ns" iptables -A egtb-fw -p udp --dport 51820 -j ACCEPT
	for ((j = 1; j <= GATEWAYS; j++)); do
		[[ $j == "$n" ]] || in_ns "$ns" iptables -A egtb-fw -p udp -s "$WAN_NET.1$j" -j ACCEPT
	done
	in_ns "$ns" iptables -A egtb-fw -p tcp -s "$MGMT_NET.0/24" --dport 9100 -j ACCEPT
	if [[ $backend == ipsec ]]; then
		in_ns "$ns" iptables -A egtb-fw -p udp -m multiport --dports 500,4500 -j ACCEPT
		in_ns "$ns" iptables -A egtb-fw -p esp -j ACCEPT
	fi
	in_ns "$ns" iptables -C INPUT -j egtb-fw 2>/dev/null || in_ns "$ns" iptables -A INPUT -j egtb-fw
	in_ns "$ns" iptables -P INPUT DROP
}

write_policy() {
	# Short timers, so a scenario shows a migration within seconds.
	cat >"$RUN_DIR/policy.json" <<'EOF'
{
  "version": 1,
  "decision": {"Z": 1.645, "MigrationCost": 5000, "SafetyMargin": 5000},
  "flap_guard": {"ConfirmationWindow": 2000000000, "MinResidence": 10000000000, "Cooldown": 5000000000}
}
EOF
}

# target prints one Prometheus file_sd target group: ADDR JOB NODE.
target() {
	printf '  {"targets": ["%s:9100"], "labels": {"job": "egressa-%s", "node": "%s", "testbed": "local"}}' "$1" "$2" "$3"
}

write_targets() {
	# Prometheus file_sd targets for deploy/observability.
	local i
	mkdir -p "$(dirname "$TARGETS_FILE")"
	{
		echo "["
		target "$MGMT_NET.2" controller controller
		echo ","
		for ((i = 1; i <= GATEWAYS; i++)); do
			target "$MGMT_NET.1$i" gateway "gw$i"
			echo ","
		done
		target "$MGMT_NET.100" client client
		printf '\n]\n'
	} >"$TARGETS_FILE.tmp"
	mv "$TARGETS_FILE.tmp" "$TARGETS_FILE"
}

client_env() {
	echo EGRESSA_CONF="$RUN_DIR/state/client.conf" EGRESSA_STATE="$RUN_DIR/state/client.json" \
		EGRESSA_STATUS="$RUN_DIR/state/status.json" EGRESSA_LOG="$RUN_DIR/logs/client.log" \
		EGRESSA_SERVICE=process EGRESSA_VICI_SOCKET="$RUN_DIR/charon/cli/charon.vici"
}

egressa_cli() {
	local bin
	bin=$(binaries)
	# shellcheck disable=SC2046
	in_ns cli env $(client_env) "$bin/egressa" "$@"
}

cmd_up() {
	need_root up
	check_netem
	local bin backend i
	bin=$(binaries)
	backend=$(pick_backend)
	mkdir -p "$RUN_DIR/state" "$RUN_DIR/logs"
	network_up
	write_policy
	local gwtok cltok ipkey
	gwtok=$(secret gateway.token)
	cltok=$(secret client.token)
	ipkey=$(secret ipsec.key)

	EGRESSA_GATEWAY_TOKEN=$gwtok EGRESSA_CLIENT_TOKEN=$cltok EGRESSA_IPSEC_KEY=$ipkey \
		start controller ctl "$bin/controller" --listen 0.0.0.0:8080 --state-file "$RUN_DIR/state/controller.json" \
		--policy "$RUN_DIR/policy.json" --log-format json --metrics-listen "$MGMT_NET.2:9100"
	wait_for controller 40 in_ns ctl bash -c "exec 3<>/dev/tcp/$WAN_NET.2/8080"

	local ipsec_flags=()
	for ((i = 1; i <= GATEWAYS; i++)); do
		ipsec_flags=()
		# Before the gateway starts, so no flow predates the firewall
		# (conntrack would let it through and hide a missing opening).
		if [[ $FIREWALL == 1 ]]; then
			firewall_gateway "$i" "$backend"
		fi
		if [[ $backend == ipsec ]]; then
			start_charon "gw$i"
			ipsec_flags=(--ipsec --vici-socket "$RUN_DIR/charon/gw$i/charon.vici")
		fi
		EGRESSA_GATEWAY_TOKEN=$gwtok start "gw$i" "gw$i" "$bin/gateway" --id "gw$i" --controller "$CTL_URL" \
			--role access,egress --endpoint "$WAN_NET.1$i:51820" --uplink inet0 \
			--private-key-file "$RUN_DIR/state/gw$i.key" --log-format json --metrics-listen "$MGMT_NET.1$i:9100" \
			"${ipsec_flags[@]}"
	done
	for ((i = 1; i <= GATEWAYS; i++)); do
		wait_for "gateway gw$i" 60 grep -q '"msg":"ready"' "$RUN_DIR/logs/gw$i.log"
	done

	if command -v python3 >/dev/null; then
		mkdir -p "$RUN_DIR/www" && echo "hello from the Internet target" >"$RUN_DIR/www/index.html"
		start inet inet python3 -m http.server --bind "$INET_NET.10" 8000 --directory "$RUN_DIR/www"
	fi

	if [[ $backend == ipsec ]]; then
		start_charon cli
	fi
	# The client's settings, as `egressa join` would write them, plus
	# where it serves its metrics and the host (Prometheus) kept off the
	# VPN.
	(umask 077 && printf '{"controller": "%s", "token": "%s", "metrics_listen": "%s.100:9100", "log_format": "json", "bypass": ["%s.1"]}\n' \
		"$CTL_URL" "$cltok" "$MGMT_NET" "$MGMT_NET" >"$RUN_DIR/state/client.conf")
	local connect=(connect -gw1)
	[[ $backend == ipsec ]] && connect+=(--ipsec)
	egressa_cli "${connect[@]}" >&2
	write_targets
	log "up: $GATEWAYS gateways$([[ $FIREWALL == 1 ]] && echo ' behind a firewall'), client on $backend; metrics on $MGMT_NET.{2,11..1$GATEWAYS,100}:9100"
}

cmd_down() {
	need_root down
	local ns pid
	# The client first, so it restores its namespace's routing.
	if ns_exists cli && [[ -e $RUN_DIR/state/status.json ]]; then
		egressa_cli disconnect >/dev/null 2>&1 || true
	fi
	# Then everything else running in our namespaces: gateways remove
	# their rules and NAT on SIGTERM.
	for ns in $(ip netns list 2>/dev/null | awk '{print $1}' | grep "^$P-" || true); do
		for pid in $(ip netns pids "$ns" 2>/dev/null); do kill -TERM "$pid" 2>/dev/null || true; done
	done
	local i
	for ((i = 0; i < 20; i++)); do
		local left=""
		for ns in $(ip netns list 2>/dev/null | awk '{print $1}' | grep "^$P-" || true); do
			left+=$(ip netns pids "$ns" 2>/dev/null)
		done
		[[ -z $left ]] && break
		sleep 0.5
	done
	for ns in $(ip netns list 2>/dev/null | awk '{print $1}' | grep "^$P-" || true); do
		for pid in $(ip netns pids "$ns" 2>/dev/null); do kill -KILL "$pid" 2>/dev/null || true; done
		ip netns del "$ns" 2>/dev/null || true
	done
	# Host side: the bridges and any veth end left over.
	for dev in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep "^$P-" || true); do
		ip link del "$dev" 2>/dev/null || true
	done
	while iptables -D "${FWD_RULE[@]}" 2>/dev/null; do :; done
	rm -rf "$RUN_DIR/pids" "$RUN_DIR/charon" "$RUN_DIR/state/status.json"
	rm -f "$TARGETS_FILE"
	log "down: no $P-* namespace, interface or process left"
}

cmd_status() {
	local i ip
	if ! ip netns list 2>/dev/null | grep -q "^$P-"; then
		echo "testbed: down"
		return
	fi
	echo "namespaces: $(ip netns list | awk '{print $1}' | grep "^$P-" | tr '\n' ' ')"
	for f in "$RUN_DIR"/pids/*; do
		[[ -e $f ]] || continue
		local name
		name=$(basename "$f")
		if running "$name"; then echo "  $name: running (pid $(cat "$f"))"; else echo "  $name: STOPPED"; fi
	done
	for ip in "$MGMT_NET.2" $(for ((i = 1; i <= GATEWAYS; i++)); do echo "$MGMT_NET.1$i"; done) "$MGMT_NET.100"; do
		echo "  $ip:9100/healthz: $(curl -fsS --max-time 2 "http://$ip:9100/healthz" 2>/dev/null || echo unreachable)"
	done
	if [[ $(id -u) -eq 0 ]] && ns_exists cli; then
		egressa_cli status || true
	fi
}

case ${1:-} in
up) cmd_up ;;
down) cmd_down ;;
status) cmd_status ;;
*)
	echo "usage: $0 up|down|status" >&2
	exit 2
	;;
esac
