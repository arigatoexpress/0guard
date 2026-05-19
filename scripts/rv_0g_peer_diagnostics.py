#!/usr/bin/env python3
"""Collect redacted diagnostics for the RV 0G storage peer-depth issue.

This probe is intentionally read-only. It inspects public networking posture,
zgs status, redacted config fields, and filtered logs, then writes a JSON file
that is safe to surface in ZeroGuard. It must not read private-key files, print
miner keys, restart services, or change node state.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import rv_0g_storage_soak_snapshot as soak


SCHEMA = "0guard.rv_0g_peer_diagnostics.v1"
DEFAULT_OUT = "content/rv_0g_peer_diagnostics.local.json"
DEFAULT_STORAGE_DIR = "/home/arigato/0g/storage-mainnet"
SENSITIVE_RE = re.compile(
    r"(?i)(private[_-]?key|miner[_-]?key|mnemonic|secret|token|password)\s*[:=]\s*['\"]?[^'\"\s,}]+"
)
HEX_SECRET_RE = re.compile(r"(?i)\b0x[a-f0-9]{64}\b")


def main() -> int:
    parser = argparse.ArgumentParser(description="RV 0G storage peer diagnostics")
    parser.add_argument("--host", default=soak.DEFAULT_HOST)
    parser.add_argument("--wsl-distro", default=soak.DEFAULT_WSL_DISTRO)
    parser.add_argument("--storage-dir", default=DEFAULT_STORAGE_DIR)
    parser.add_argument("--storage-rpc", default=soak.DEFAULT_STORAGE_RPC)
    parser.add_argument("--out", default=DEFAULT_OUT)
    args = parser.parse_args()

    diagnostics = build_diagnostics(args)
    out_path = Path(args.out).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(f"{out_path.suffix}.tmp")
    tmp_path.write_text(json.dumps(diagnostics, sort_keys=True, indent=2), encoding="utf-8")
    tmp_path.replace(out_path)
    print(json.dumps(diagnostics, sort_keys=True))
    return 0 if diagnostics["health"]["sshReachable"] else 2


def build_diagnostics(args: argparse.Namespace) -> dict[str, Any]:
    status = read_storage_status(args)
    config = read_redacted_config(args)
    process = soak.read_process(args)
    sockets = read_listening_sockets(args)
    logs = read_filtered_logs(args)
    frp = read_frp_summary(args)
    diagnosis = diagnose_peer_depth(
        connected_peers=status.get("connectedPeers"),
        config=config,
        sockets=sockets,
        logs=logs,
        process=process,
        frp=frp,
    )

    return {
        "schema": SCHEMA,
        "generatedAt": utc_now(),
        "host": args.host,
        "wslDistro": args.wsl_distro,
        "storageDir": args.storage_dir,
        "zgsVersion": read_zgs_version(args),
        "process": process,
        "storageRpc": status,
        "redactedConfig": config,
        "listeningSockets": sockets,
        "frp": frp,
        "filteredLogs": logs,
        "diagnosis": diagnosis,
        "health": {
            "sshReachable": process.get("status") != "ssh_failed",
            "zgsRunning": process.get("running") is True,
            "peerDepthReady": diagnosis["peerDepthReady"],
            "blockedBy": diagnosis["blockedBy"],
        },
        "safety": {
            "readOnly": True,
            "privateKeysRead": False,
            "privateKeysReturned": False,
            "redactedConfigOnly": True,
            "serviceRestarted": False,
            "transactionSigningEnabled": False,
            "transactionBroadcastingEnabled": False,
            "moneyMovementEnabled": False,
        },
    }


def read_zgs_version(args: argparse.Namespace) -> str | None:
    result = wsl_in_storage_dir(args, "./bin/zgs_node --version 2>/dev/null || true")
    return sanitize(result["stdout"]).strip() or None


def read_storage_status(args: argparse.Namespace) -> dict[str, Any]:
    return soak.read_remote_storage_rpc(args)


def read_redacted_config(args: argparse.Namespace) -> dict[str, Any]:
    command = remote_python_command(
        r"""
from pathlib import Path
allowed_prefixes = (
    'network_', 'blockchain_rpc_endpoint', 'log_contract_address',
    'mine_contract_address', 'reward_contract_address',
    'log_sync_start_block_number', 'auto_sync_enabled', 'shard_position',
    'db_', 'rpc_', 'boot_nodes', 'trusted_setup_file', 'log_config_file',
)
blocked = ('private', 'secret', 'token', 'password', 'mnemonic', 'miner_key')
path = Path('config.funded.local.toml')
if not path.exists():
    print('status=missing')
else:
    print('status=loaded')
    for raw in path.read_text(encoding='utf-8', errors='replace').splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key = line.split('=', 1)[0].strip().lower()
        if any(term in key for term in blocked):
            continue
        if key.startswith(allowed_prefixes):
            print(line)
"""
    )
    result = wsl_in_storage_dir(args, command)
    lines = [sanitize(line.strip()) for line in result["stdout"].splitlines() if line.strip()]
    return {
        "status": _status_line_value(lines) or ("loaded" if result["returncode"] == 0 else "degraded"),
        "entries": [line for line in lines if not line.startswith("status=")],
        "stderr": sanitize(result["stderr"]).strip() or None,
        "sensitiveKeysReturned": False,
    }


def read_listening_sockets(args: argparse.Namespace) -> dict[str, Any]:
    command = remote_python_command(
        r"""
import subprocess
ports = (':1234', ':5678', ':34000')
for mode in ('-lntup', '-lnup'):
    proc = subprocess.run(['ss', '-H', mode], capture_output=True, text=True, check=False)
    for line in proc.stdout.splitlines():
        if any(port in line for port in ports):
            print(line)
"""
    )
    result = soak.wsl(args, command)
    return {
        "status": "ok" if result["returncode"] == 0 else "degraded",
        "entries": [sanitize(line) for line in result["stdout"].splitlines() if line.strip()],
        "stderr": sanitize(result["stderr"]).strip() or None,
    }


def read_filtered_logs(args: argparse.Namespace) -> dict[str, Any]:
    command = remote_python_command(
        r"""
from pathlib import Path
patterns = ('peer', 'disc', 'enr', 'listen', 'dial', 'connect', 'addr', 'nat', 'network', 'boot', 'warn', 'error')
log_dir = Path('log')
files = sorted(log_dir.glob('zgs.log*'), key=lambda p: p.stat().st_mtime if p.exists() else 0)
if not files:
    print('status=no_log_files')
else:
    path = files[-1]
    print(f'status=loaded file={path}')
    try:
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()[-1200:]
    except OSError as exc:
        print(f'error={type(exc).__name__}: {exc}')
        lines = []
    matches = [line for line in lines if any(pattern in line.lower() for pattern in patterns)]
    for line in matches[-120:]:
        print(line)
"""
    )
    result = wsl_in_storage_dir(args, command)
    lines = [sanitize(line) for line in result["stdout"].splitlines() if line.strip()]
    return {
        "status": _status_line_value(lines) or ("loaded" if result["returncode"] == 0 else "degraded"),
        "entries": [line for line in lines if not line.startswith("status=")][:120],
        "stderr": sanitize(result["stderr"]).strip() or None,
    }


def read_frp_summary(args: argparse.Namespace) -> dict[str, Any]:
    command = remote_python_command(
        r"""
from pathlib import Path
allowed_keys = {
    'server_addr', 'server_port', 'type', 'local_ip', 'local_port',
    'remote_port', 'protocol', 'transport.protocol', 'name'
}
blocked = ('private', 'secret', 'token', 'password', 'mnemonic')
for path in sorted(Path('.').glob('**/*frp*')):
    if not path.is_file() or path.stat().st_size > 50000:
        continue
    print(f'file={path}')
    if path.suffix.lower() not in {'.toml', '.ini', '.conf', '.log'}:
        continue
    if path.suffix.lower() == '.log':
        lines = path.read_text(encoding='utf-8', errors='replace').splitlines()[-80:]
        for line in lines[-20:]:
            print(line)
        continue
    for raw in path.read_text(encoding='utf-8', errors='replace').splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key = line.split('=', 1)[0].strip().strip('"').lower()
        if any(term in key for term in blocked):
            print(f'{key}=<redacted>')
        elif key in allowed_keys:
            print(line)
"""
    )
    result = wsl_in_storage_dir(args, command)
    return {
        "status": "ok" if result["returncode"] == 0 else "degraded",
        "entries": [sanitize(line) for line in result["stdout"].splitlines() if line.strip()],
        "stderr": sanitize(result["stderr"]).strip() or None,
    }


def diagnose_peer_depth(
    *,
    connected_peers: Any,
    config: dict[str, Any],
    sockets: dict[str, Any],
    logs: dict[str, Any],
    process: dict[str, Any],
    frp: dict[str, Any],
) -> dict[str, Any]:
    peer_count = int(connected_peers or 0)
    blockers: list[str] = []
    hypotheses: list[dict[str, Any]] = []
    next_checks: list[str] = []
    entries = "\n".join(config.get("entries") or [])
    process_command = str(process.get("command") or "")
    socket_entries = "\n".join(sockets.get("entries") or [])
    socket_status = sockets.get("status") or ("ok" if socket_entries else "not_checked")
    frp_entries = "\n".join(frp.get("entries") or [])

    if not process.get("running"):
        blockers.append("zgs_node_not_running")
    if peer_count < 8:
        blockers.append("connected_peers_below_target_8")
        hypotheses.append(
            {
                "id": "shallow_peer_discovery",
                "confidence": "medium",
                "why": "The node is synced and reachable over TCP, but peer depth remains low.",
            }
        )
    if "network_enr_address" not in entries and "--network-enr-address" not in process_command:
        blockers.append("network_enr_address_not_visible_in_config")
        next_checks.append("Confirm the start script passes --network-enr-address with the relay IP.")
    if socket_status != "ok":
        blockers.append("socket_probe_degraded")
        next_checks.append("Rerun the peer diagnostic collector after fixing the WSL socket probe.")
    elif ":1234" not in socket_entries:
        blockers.append("local_p2p_port_not_listening")
    if "udp" not in frp_entries.lower():
        hypotheses.append(
            {
                "id": "udp_relay_not_confirmed",
                "confidence": "medium",
                "why": "0G storage docs require TCP and UDP 1234; this diagnostic can see TCP but only config/log evidence for UDP.",
            }
        )
        next_checks.append("Verify FRP has both TCP and UDP 1234 proxies and that the server-side firewall allows UDP 1234.")
    if "boot_nodes" not in entries:
        hypotheses.append(
            {
                "id": "bootnode_visibility_unknown",
                "confidence": "low",
                "why": "The redacted config did not expose boot_nodes, so discovery may depend on defaults or CLI flags.",
            }
        )
        next_checks.append("Confirm boot_nodes match current 0G mainnet storage documentation.")

    next_checks.extend(
        [
            "Keep collecting peer diagnostics every 30-60 minutes to see whether peer count rises naturally after sync.",
            "Only consider a controlled node restart after confirming UDP relay and bootnode config; do not restart during active DB writes without a rollback note.",
        ]
    )
    return {
        "peerDepthReady": peer_count >= 8,
        "connectedPeers": peer_count,
        "targetPeers": 8,
        "blockedBy": blockers,
        "hypotheses": hypotheses,
        "nextChecks": dedupe(next_checks),
    }


def wsl_in_storage_dir(args: argparse.Namespace, command: str) -> dict[str, Any]:
    return soak.wsl(args, f"cd {soak.shell_quote(args.storage_dir)} && {command}")


def remote_python_command(code: str) -> str:
    encoded = base64.b64encode(code.strip().encode("utf-8")).decode("ascii")
    return f"python3 -c 'import base64; exec(base64.b64decode(\"{encoded}\"))'"


def sanitize(value: str) -> str:
    redacted = SENSITIVE_RE.sub(lambda match: match.group(1) + "=<redacted>", value)
    redacted = HEX_SECRET_RE.sub("<redacted-hex-secret>", redacted)
    return redacted.replace("\x00", "")


def _status_line_value(lines: list[str]) -> str | None:
    for line in lines:
        if line.startswith("status="):
            return line.split("=", 1)[1].split()[0]
    return None


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
