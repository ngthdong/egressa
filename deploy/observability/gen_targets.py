#!/usr/bin/env python3
"""Write Prometheus file_sd targets for the hosts of an Ansible inventory.

    gen_targets.py deploy/ansible/inventory.ini > deploy/observability/targets/vps.json

The inventory is the one deploy/ansible uses: groups controller, gateways
and clients, one IP per line, with gateway_id= on gateways and an optional
name= on clients. The metrics port is Ansible's egressa_metrics_port (the
older metrics_port= is still read), from the host's line, its group's
[<group>:vars] or [all:vars], else the playbooks' default, 9101.
"""
import json
import shlex
import sys

ROLES = {"controller": "controller", "gateways": "gateway", "clients": "client"}
DEFAULT_PORT = "9101"  # deploy/ansible/roles/egressa/defaults/main.yml


def parse(lines):
    """Returns ([(group, host, vars)], {group: vars}) of an INI inventory."""
    hosts, group_vars = [], {}
    section = None
    for raw in lines:
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            section = line.strip("[]").strip()
            continue
        if section is None or section.endswith(":children"):
            continue
        if section.endswith(":vars"):
            key, sep, value = line.partition("=")
            if sep:
                group_vars.setdefault(section[: -len(":vars")], {})[key.strip()] = value.strip()
            continue
        host, *rest = shlex.split(line)
        hosts.append((section, host, dict(kv.split("=", 1) for kv in rest if "=" in kv)))
    return hosts, group_vars


def port_of(hv, group, group_vars):
    for scope in (hv, group_vars.get(group, {}), group_vars.get("all", {})):
        for key in ("egressa_metrics_port", "metrics_port"):
            if key in scope:
                return scope[key]
    return DEFAULT_PORT


def targets(lines):
    hosts, group_vars = parse(lines)
    out = []
    for group, host, hv in hosts:
        role = ROLES.get(group)
        if role is None:
            continue
        if role == "gateway" and "gateway_id" not in hv:
            raise SystemExit(f"gateway {host} has no gateway_id=")
        node = {"controller": "controller", "gateway": hv.get("gateway_id"),
                "client": hv.get("name", host)}[role]
        addr = hv.get("ansible_host", host)
        out.append({"targets": [f"{addr}:{port_of(hv, group, group_vars)}"],
                    "labels": {"job": f"egressa-{role}", "node": node, "testbed": "vps"}})
    if not out:
        raise SystemExit("no controller, gateways or clients in the inventory")
    return out


def main(argv):
    if len(argv) != 2:
        raise SystemExit(__doc__)
    with open(argv[1], encoding="utf-8") as f:
        json.dump(targets(f), sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(sys.argv)
