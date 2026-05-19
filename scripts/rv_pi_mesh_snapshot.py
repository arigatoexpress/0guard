#!/usr/bin/env python3
"""Collect a public-safe Raspberry Pi mesh snapshot for ZeroGuard.

The collector is intentionally read-only. It probes the already-staged RV Pi
runtime, records Ethernet peer reachability, and writes a git-ignored JSON file
the workbench can ingest. It never reads secrets, never changes network config,
never starts services, and never sends Telegram messages.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "0guard.rv_pi_mesh_snapshot.v1"
DEFAULT_OUT = "content/rv_pi_mesh.local.json"
DEFAULT_PRIMARY_SSH = "ari@rvpi-a.local"
DEFAULT_PRIMARY_HEALTH_URL = "http://rvpi-a.local:8765/health"
DEFAULT_PRIMARY_WIFI = "192.168.1.111"
DEFAULT_PEER_WIFI = "192.168.1.144"
DEFAULT_PRIMARY_ETH = "10.77.4.11"
DEFAULT_PEER_ETH = "10.77.4.12"
SSH_BASE = [
    "ssh",
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=6",
]


def main() -> int:
    parser = argparse.ArgumentParser(description="RV Raspberry Pi mesh snapshot")
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--primary-ssh", default=DEFAULT_PRIMARY_SSH)
    parser.add_argument("--primary-health-url", default=DEFAULT_PRIMARY_HEALTH_URL)
    parser.add_argument("--primary-wifi", default=DEFAULT_PRIMARY_WIFI)
    parser.add_argument("--peer-wifi", default=DEFAULT_PEER_WIFI)
    parser.add_argument("--primary-eth", default=DEFAULT_PRIMARY_ETH)
    parser.add_argument("--peer-eth", default=DEFAULT_PEER_ETH)
    args = parser.parse_args()

    snapshot = build_snapshot(args)
    out_path = Path(args.out).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(f"{out_path.suffix}.tmp")
    tmp_path.write_text(json.dumps(snapshot, sort_keys=True, indent=2), encoding="utf-8")
    tmp_path.replace(out_path)
    print(json.dumps(snapshot, sort_keys=True))
    return 0 if snapshot["cluster"]["primaryReachable"] else 2


def build_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    primary = read_primary(args)
    peer = read_peer_from_primary(args)
    blockers = cluster_blockers(primary, peer)
    return {
        "schema": SCHEMA,
        "generatedAt": utc_now(),
        "mode": "rv_pi_lan_ethernet_snapshot",
        "nodes": {
            "rvpi-a": primary,
            "rvpi-b": peer,
        },
        "cluster": {
            "primaryReachable": primary.get("reachable") is True,
            "ethernetCarrierReady": primary.get("eth0", {}).get("carrier") is True,
            "peerEthernetReachable": peer.get("ethernetReachable") is True,
            "peerIdentityVerified": peer.get("identityVerified") is True,
            "edgeApiReady": primary.get("edgeApiReady") is True,
            "clusterReady": not blockers,
            "blockers": blockers,
            "recommendedAction": (
                "install_or_authorize_rvpi_b_runtime_over_eth"
                if "rvpi_b_identity_unverified" in blockers
                else "keep_collecting_edge_heartbeats"
            ),
        },
        "safety": {
            "readOnly": True,
            "privateKeysRead": False,
            "privateKeysReturned": False,
            "walletSignaturesEnabled": False,
            "telegramSendsEnabled": False,
            "networkConfigChanged": False,
            "servicesStarted": False,
        },
    }


def read_primary(args: argparse.Namespace) -> dict[str, Any]:
    health = http_json(args.primary_health_url)
    health_json = health.get("json") if isinstance(health.get("json"), dict) else {}
    hostname = ssh_text(args.primary_ssh, "hostname")
    ip_addr = ssh_json(args.primary_ssh, "ip -j addr")
    ip_link = ssh_json(args.primary_ssh, "ip -j link")
    services = read_services(args.primary_ssh)
    peer_check = parse_peer_check(ssh_text(args.primary_ssh, "command -v ari-peer-check >/dev/null && ari-peer-check || true").get("stdout", ""))
    status_text = ssh_text(args.primary_ssh, "command -v ari-status >/dev/null && ari-status || true")
    memory = ssh_text(args.primary_ssh, "free -b | awk '/^Mem:/ {print $2}'")
    disk = ssh_text(args.primary_ssh, "df -B1 / | awk 'NR==2 {print $2, $3, $4, $5}'")
    eth = interface_summary("eth0", ip_addr.get("json"), ip_link.get("json"))
    wlan = interface_summary("wlan0", ip_addr.get("json"), ip_link.get("json"))
    return {
        "id": "rvpi-a",
        "host": "rvpi-a.local",
        "sshTarget": args.primary_ssh,
        "wifiIpv4": first_ipv4(wlan),
        "ethernetIpv4": first_ipv4(eth),
        "reachable": hostname.get("returncode") == 0 or health.get("ok") is True,
        "hostname": hostname.get("stdout", "").strip() or health_json.get("hostname"),
        "role": health_json.get("role", "primary"),
        "status": "online" if health.get("ok") else "ssh_only" if hostname.get("returncode") == 0 else "unreachable",
        "edgeApiReady": health.get("ok") is True,
        "health": public_payload(health.get("json")),
        "services": services,
        "eth0": eth,
        "wlan0": wlan,
        "peerCheck": peer_check,
        "statusText": status_text.get("stdout", "").strip(),
        "memoryGiB": bytes_to_gib(parse_int(memory.get("stdout"))),
        "rootDisk": parse_disk(disk.get("stdout", "")),
        "safeRole": "sentinel_probe_and_evidence_cache",
    }


def read_peer_from_primary(args: argparse.Namespace) -> dict[str, Any]:
    ports = {
        str(port): remote_tcp_probe(args.primary_ssh, args.peer_eth, port)
        for port in (22, 8765, 1883, 9100)
    }
    health_from_primary = ssh_text(
        args.primary_ssh,
        f"curl -fsS --connect-timeout 4 http://{args.peer_eth}:8765/health 2>/dev/null || true",
    )
    health = parse_json_or_none(health_from_primary.get("stdout", ""))
    peer_wifi_probe = remote_tcp_probe(args.primary_ssh, args.peer_wifi, 22)
    return {
        "id": "rvpi-b",
        "host": "rvpi-b.local",
        "expectedWifiIpv4": args.peer_wifi,
        "ethernetIpv4": args.peer_eth,
        "status": peer_status(ports, health),
        "ethernetReachable": ports["22"]["ok"] is True,
        "wifiReachableFromPrimary": peer_wifi_probe["ok"],
        "identityVerified": bool(health and health.get("hostname") == "rvpi-b"),
        "edgeApiReady": bool(health),
        "health": public_payload(health),
        "tcpFromRvpiA": ports,
        "safeRole": "standby_evidence_cache_when_authorized",
        "blocker": None if health else "ssh_or_runtime_authorization_needed_before_mutation",
    }


def cluster_blockers(primary: dict[str, Any], peer: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    if not primary.get("reachable"):
        blockers.append("rvpi_a_unreachable")
    if not primary.get("edgeApiReady"):
        blockers.append("rvpi_a_edge_api_not_ready")
    if primary.get("eth0", {}).get("carrier") is not True:
        blockers.append("ethernet_carrier_missing")
    if not peer.get("ethernetReachable"):
        blockers.append("rvpi_b_not_reachable_over_ethernet")
    if not peer.get("identityVerified"):
        blockers.append("rvpi_b_identity_unverified")
    if not peer.get("edgeApiReady"):
        blockers.append("rvpi_b_edge_api_not_ready")
    return blockers


def ssh_text(target: str, command: str) -> dict[str, Any]:
    return run([*SSH_BASE, target, command], timeout=10)


def ssh_json(target: str, command: str) -> dict[str, Any]:
    result = ssh_text(target, command)
    result["json"] = parse_json_or_none(result.get("stdout", ""))
    return result


def run(command: list[str], *, timeout: float) -> dict[str, Any]:
    start = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "latencyMs": int((time.monotonic() - start) * 1000),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "returncode": 124,
            "stdout": exc.stdout or "",
            "stderr": "TimeoutExpired",
            "latencyMs": int((time.monotonic() - start) * 1000),
        }


def http_json(url: str) -> dict[str, Any]:
    started = time.monotonic()
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return {"ok": True, "json": payload, "latencyMs": int((time.monotonic() - started) * 1000)}
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return {
            "ok": False,
            "json": None,
            "error": f"{type(exc).__name__}: {exc}",
            "latencyMs": int((time.monotonic() - started) * 1000),
        }


def remote_tcp_probe(target: str, host: str, port: int) -> dict[str, Any]:
    result = ssh_text(target, f"nc -z -w 2 {host} {port}")
    return {
        "host": host,
        "port": port,
        "ok": result["returncode"] == 0,
        "latencyMs": result["latencyMs"],
    }


def read_services(target: str) -> dict[str, str]:
    names = ["ssh", "avahi-daemon", "docker", "mosquitto", "prometheus-node-exporter", "ari-edge-api", "ari-peer-watch.timer"]
    quoted = " ".join(names)
    result = ssh_text(target, f"systemctl is-active {quoted} 2>/dev/null || true")
    lines = [line.strip() for line in result.get("stdout", "").splitlines()]
    return {name: lines[index] if index < len(lines) else "unknown" for index, name in enumerate(names)}


def interface_summary(name: str, addr_payload: Any, link_payload: Any) -> dict[str, Any]:
    addr = find_interface(name, addr_payload)
    link = find_interface(name, link_payload)
    addresses = []
    if isinstance(addr, dict):
        for item in addr.get("addr_info") or []:
            if isinstance(item, dict):
                local = item.get("local")
                family = item.get("family")
                if local:
                    addresses.append({"family": family, "local": local, "prefixlen": item.get("prefixlen")})
    flags = link.get("flags") if isinstance(link, dict) else []
    return {
        "name": name,
        "operstate": link.get("operstate") if isinstance(link, dict) else None,
        "mac": link.get("address") if isinstance(link, dict) else None,
        "carrier": "LOWER_UP" in (flags or []),
        "addresses": addresses,
    }


def find_interface(name: str, payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, list):
        return None
    for item in payload:
        if isinstance(item, dict) and item.get("ifname") == name:
            return item
    return None


def first_ipv4(interface: dict[str, Any]) -> str | None:
    for addr in interface.get("addresses") or []:
        if addr.get("family") == "inet":
            return addr.get("local")
    return None


def parse_peer_check(output: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            parsed[parts[0]] = {
                "status": parts[1],
                "target": parts[2] if len(parts) >= 3 else None,
                "ok": parts[1] == "ok" or parts[1] == "1",
            }
    return parsed


def parse_disk(output: str) -> dict[str, Any]:
    parts = output.split()
    if len(parts) < 4:
        return {}
    return {
        "sizeGiB": bytes_to_gib(parse_int(parts[0])),
        "usedGiB": bytes_to_gib(parse_int(parts[1])),
        "availableGiB": bytes_to_gib(parse_int(parts[2])),
        "usedPercent": parts[3],
    }


def peer_status(ports: dict[str, dict[str, Any]], health: dict[str, Any] | None) -> str:
    if health and health.get("hostname") == "rvpi-b":
        return "online_verified"
    if ports.get("22", {}).get("ok"):
        return "ethernet_ssh_reachable_identity_unverified"
    return "not_reached"


def parse_json_or_none(value: str) -> Any:
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return None


def public_payload(payload: Any) -> Any:
    if not isinstance(payload, dict):
        return payload
    forbidden = {"token", "secret", "password", "private_key", "mnemonic"}
    return {key: value for key, value in payload.items() if key.lower() not in forbidden}


def parse_int(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(str(value).strip().split()[0])
    except ValueError:
        return None


def bytes_to_gib(value: int | None) -> float | None:
    if value is None:
        return None
    return round(value / (1024**3), 2)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
