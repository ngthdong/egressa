#!/usr/bin/env bash
# Writes custom metrics for the node_exporter textfile collector.
set -euo pipefail

OUT_DIR=/var/lib/node_exporter/textfile
TMP="$(mktemp "${OUT_DIR}/.ops.XXXXXX")"
trap 'rm -f "$TMP"' EXIT

{
  echo "# TYPE ops_reboot_required gauge"
  if [ -f /var/run/reboot-required ]; then echo "ops_reboot_required 1"; else echo "ops_reboot_required 0"; fi

  echo "# TYPE ops_pending_updates gauge"
  pending="$(apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst' || true)"
  echo "ops_pending_updates ${pending:-0}"

  if command -v fail2ban-client >/dev/null 2>&1; then
    echo "# TYPE ops_fail2ban_banned gauge"
    jails="$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p' | tr -d ',')"
    for jail in $jails; do
      n="$(fail2ban-client status "$jail" 2>/dev/null | awk -F'\t' '/Currently banned/ {print $NF}')"
      echo "ops_fail2ban_banned{jail=\"${jail}\"} ${n:-0}"
    done
  fi

  report=/var/log/lynis-report.dat
  if [ -r "$report" ]; then
    idx="$(awk -F= '/^hardening_index=/ {print $2}' "$report" || true)"
    if [ -n "${idx:-}" ]; then
      echo "# TYPE ops_lynis_hardening_index gauge"
      echo "ops_lynis_hardening_index ${idx}"
      echo "ops_lynis_report_timestamp_seconds $(stat -c %Y "$report")"
    fi
  fi
} > "$TMP"

chmod 0644 "$TMP"
mv "$TMP" "${OUT_DIR}/ops.prom"
trap - EXIT
