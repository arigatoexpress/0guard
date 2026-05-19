#!/usr/bin/env python3
"""Collect a public-safe RV 0G storage-node soak snapshot.

The collector is intentionally read-only. It uses SSH, WSL commands, public
TCP probes, and 0G JSON-RPC balance reads, then writes a redacted JSON file the
ZeroGuard workbench can ingest. It never prints or exports private keys, never
signs, never broadcasts, and never sends messages.
"""

from __future__ import annotations

import argparse
import json
import socket
import subprocess
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "0guard.rv_0g_storage_soak_snapshot.v1"
DEFAULT_HOST = "aribs@192.168.1.61"
DEFAULT_WSL_DISTRO = "Ubuntu-24.04"
DEFAULT_RELAY_HOST = "35.254.123.37"
DEFAULT_STORAGE_RPC = "http://127.0.0.1:5678"
DEFAULT_MAINNET_RPC = "https://evmrpc.0g.ai"
DEFAULT_OUT = "content/rv_0g_storage_soak.local.json"
DEFAULT_DEPLOYER = "0x885b0892D241Cb5033C9995e09cA521d54f936b5"
DEFAULT_ACTIVE_MINER = "0xf5c1c3eb88c262adb451c1ce3b1c391f7d968ecd"
DEFAULT_PREVIOUS_MINER = "0x8c497E41405C924D81dB24aB033CAca71ED559E9"
DEFAULT_PREVIOUS_SIGNER = "0x6De500690f88A920Db7976b161034fC835b96A49"


def main() -> int:
    parser = argparse.ArgumentParser(description="RV 0G storage soak snapshot")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--wsl-distro", default=DEFAULT_WSL_DISTRO)
    parser.add_argument("--relay-host", default=DEFAULT_RELAY_HOST)
    parser.add_argument("--storage-rpc", default=DEFAULT_STORAGE_RPC)
    parser.add_argument("--mainnet-rpc", default=DEFAULT_MAINNET_RPC)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--deployer-address", default=DEFAULT_DEPLOYER)
    parser.add_argument("--active-miner-address", default=DEFAULT_ACTIVE_MINER)
    parser.add_argument("--previous-miner-address", default=DEFAULT_PREVIOUS_MINER)
    parser.add_argument("--previous-signer-address", default=DEFAULT_PREVIOUS_SIGNER)
    args = parser.parse_args()

    snapshot = build_snapshot(args)
    out_path = Path(args.out).expanduser()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(f"{out_path.suffix}.tmp")
    tmp_path.write_text(json.dumps(snapshot, sort_keys=True, indent=2), encoding="utf-8")
    tmp_path.replace(out_path)
    print(json.dumps(snapshot, sort_keys=True))
    return 0 if snapshot["health"]["sshReachable"] else 2


def build_snapshot(args: argparse.Namespace) -> dict[str, Any]:
    latest_block = parse_hex_int(
        json_rpc(
            args.mainnet_rpc,
            {"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []},
        ).get("result")
    )
    storage_rpc = read_remote_storage_rpc(args)
    log_height = storage_rpc.get("logSyncHeight")
    sync_gap = latest_block - int(log_height) if latest_block is not None and log_height else None
    tasks = read_task_states(args)
    process = read_process(args)
    disk = read_disk(args)
    config = read_config_presence(args)
    balances = read_balances(args)
    relay = {
        "tcp1234": tcp_probe(args.relay_host, 1234),
        "tcp34000": tcp_probe(args.relay_host, 34000),
        "tcp5678": tcp_probe(args.relay_host, 5678),
        "udp1234": udp_send_probe(args.relay_host, 1234),
    }
    expansion_blockers = expansion_blockers_for(
        storage_rpc=storage_rpc,
        relay=relay,
        tasks=tasks,
        process=process,
        config=config,
        sync_gap=sync_gap,
        balances=balances,
    )
    active_balance = balances.get("activeMiner", {}).get("balanceOg")
    return {
        "schema": SCHEMA,
        "generatedAt": utc_now(),
        "host": args.host,
        "wslDistro": args.wsl_distro,
        "network": "0G mainnet",
        "chainId": 16661,
        "mainnetRpc": {
            "url": args.mainnet_rpc,
            "latestBlock": latest_block,
        },
        "process": process,
        "scheduledTasks": tasks,
        "publicRelay": relay,
        "storageRpc": storage_rpc,
        "sync": {
            "latestMainnetBlock": latest_block,
            "logSyncHeight": log_height,
            "syncGapBlocks": sync_gap,
            "nextTxSeq": storage_rpc.get("nextTxSeq"),
        },
        "disk": disk,
        "config": config,
        "balances": balances,
        "funding": {
            "activeMinerAddress": args.active_miner_address,
            "activeMinerBalanceOg": active_balance,
            "onlyPriorTestFundingObserved": active_balance == 0.25
            and balances.get("previousMiner", {}).get("balanceOg") == 0
            and balances.get("previousSigner", {}).get("balanceOg") == 0,
            "largeTransferDetected": any(
                (entry.get("balanceOg") or 0) >= 100
                for key, entry in balances.items()
                if key != "deployer"
            ),
            "hundredOgTransferSent": any(
                99 <= (entry.get("balanceOg") or 0) <= 101
                for key, entry in balances.items()
                if key != "deployer"
            ),
            "recommendedAction": "continue_soak_no_additional_funding",
        },
        "health": {
            "sshReachable": process.get("status") != "ssh_failed",
            "zgsRunning": process.get("running") is True,
            "relayTcpOpen": relay["tcp1234"]["ok"] is True,
            "rpcOk": storage_rpc.get("status") == "ok",
            "expansionReady": not expansion_blockers,
            "expansionBlockers": expansion_blockers,
        },
        "safety": {
            "readOnly": True,
            "privateKeysRead": False,
            "privateKeysReturned": False,
            "walletSignaturesEnabled": False,
            "transactionBroadcastingEnabled": False,
            "moneyMovementEnabled": False,
            "telegramSendsEnabled": False,
        },
    }


def read_remote_storage_rpc(args: argparse.Namespace) -> dict[str, Any]:
    result = read_remote_zgs_rpc(args, "zgs_getStatus")
    if result["returncode"] != 0:
        return {
            "status": "degraded",
            "error": result["stderr"] or result["stdout"] or "zgs_getStatus failed",
        }
    try:
        body = json.loads(result["stdout"])
    except json.JSONDecodeError as exc:
        return {"status": "degraded", "error": f"JSONDecodeError: {exc}"}
    rpc_result = body.get("result")
    if not isinstance(rpc_result, dict):
        return {"status": "degraded", "error": "zgs_getStatus returned no result object"}
    shard_config = read_remote_shard_config(args)
    identity = rpc_result.get("networkIdentity") or {}
    status = "ok"
    if identity.get("chainId") != 16661:
        status = "chain_id_mismatch"
    return {
        "status": status,
        "connectedPeers": rpc_result.get("connectedPeers"),
        "logSyncHeight": rpc_result.get("logSyncHeight"),
        "logSyncBlock": rpc_result.get("logSyncBlock"),
        "nextTxSeq": rpc_result.get("nextTxSeq"),
        "networkIdentity": identity,
        "shardConfig": shard_config,
    }


def read_remote_shard_config(args: argparse.Namespace) -> dict[str, Any] | None:
    result = read_remote_zgs_rpc(args, "zgs_getShardConfig")
    if result["returncode"] != 0:
        return None
    try:
        body = json.loads(result["stdout"])
    except json.JSONDecodeError:
        return None
    rpc_result = body.get("result")
    return rpc_result if isinstance(rpc_result, dict) else None


def read_remote_zgs_rpc(args: argparse.Namespace, method: str) -> dict[str, Any]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": [],
    }
    command = (
        f"curl -sS -m 5 -H 'Content-Type: application/json' "
        f"-d '{json.dumps(payload)}' {shell_quote(args.storage_rpc)}"
    )
    return wsl(args, command)


def read_task_states(args: argparse.Namespace) -> dict[str, Any]:
    names = [
        "0GStorageMainnetFunded",
        "0GStorageRelayFrpc",
        "0GStorageMainnetNoKey",
        "0GDaRelayTunnel",
    ]
    states = {}
    for name in names:
        result = ssh(args.host, f'cmd.exe /c schtasks /query /tn "\\{name}" /fo LIST /v')
        states[name] = parse_schtasks_list(result["stdout"]) | {
            "queryOk": result["returncode"] == 0,
        }
    return states


def read_process(args: argparse.Namespace) -> dict[str, Any]:
    result = wsl(args, "pgrep -af zgs_node || true")
    if result["returncode"] != 0 and not result["stdout"]:
        return {"status": "ssh_failed", "running": False, "error": result["stderr"]}
    lines = [line.strip() for line in result["stdout"].splitlines() if "zgs_node" in line]
    return {
        "status": "running" if lines else "not_running",
        "running": bool(lines),
        "command": redact_command(lines[0]) if lines else None,
    }


def read_disk(args: argparse.Namespace) -> dict[str, Any]:
    size = wsl(args, "du -sh /home/arigato/0g/storage-mainnet/db 2>/dev/null | cut -f1")
    df = wsl(args, "df -h /home/arigato/0g/storage-mainnet/db 2>/dev/null | tail -1")
    return {
        "dbSizeHuman": size["stdout"].strip() or None,
        "filesystem": df["stdout"].strip() or None,
    }


def read_config_presence(args: argparse.Namespace) -> dict[str, Any]:
    miner_key = wsl(
        args,
        "grep -Eq '^[[:space:]]*miner_key[[:space:]]*=' "
        "/home/arigato/0g/storage-mainnet/config.funded.local.toml "
        "&& echo yes || echo no",
    )
    miner_id = wsl(
        args,
        "grep -Eq '^[[:space:]]*miner_id[[:space:]]*=' "
        "/home/arigato/0g/storage-mainnet/config.funded.local.toml "
        "&& echo yes || echo no",
    )
    return {
        "path": "/home/arigato/0g/storage-mainnet/config.funded.local.toml",
        "fundedConfigPresent": True,
        "minerKeyPresent": miner_key["stdout"].strip() == "yes",
        "minerIdPresent": miner_id["stdout"].strip() == "yes",
        "privateKeyMaterialReturned": False,
    }


def read_balances(args: argparse.Namespace) -> dict[str, Any]:
    addresses = {
        "deployer": args.deployer_address,
        "activeMiner": args.active_miner_address,
        "previousMiner": args.previous_miner_address,
        "previousSigner": args.previous_signer_address,
    }
    balances = {}
    for role, address in addresses.items():
        balances[role] = balance_for(args.mainnet_rpc, address)
    return balances


def balance_for(rpc: str, address: str) -> dict[str, Any]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getBalance",
        "params": [address, "latest"],
    }
    body = json_rpc(rpc, payload)
    raw = body.get("result")
    wei = parse_hex_int(raw)
    return {
        "address": address,
        "status": "ok" if wei is not None else "degraded",
        "balanceWei": str(wei) if wei is not None else None,
        "balanceOg": wei / 10**18 if wei is not None else None,
        "error": body.get("error"),
    }


def expansion_blockers_for(
    *,
    storage_rpc: dict[str, Any],
    relay: dict[str, Any],
    tasks: dict[str, Any],
    process: dict[str, Any],
    config: dict[str, Any],
    sync_gap: int | None,
    balances: dict[str, Any],
) -> list[str]:
    blockers: list[str] = []
    if not process.get("running"):
        blockers.append("zgs_node_not_running")
    if storage_rpc.get("status") != "ok":
        blockers.append("storage_rpc_not_ok")
    if (storage_rpc.get("connectedPeers") or 0) < 8:
        blockers.append("connected_peers_below_target_8")
    if not relay.get("tcp1234", {}).get("ok"):
        blockers.append("public_storage_tcp_relay_unreachable")
    if sync_gap is None or sync_gap > 100_000:
        blockers.append("storage_log_sync_gap_too_large")
    if tasks.get("0GStorageMainnetFunded", {}).get("Status") != "Running":
        blockers.append("funded_storage_task_not_running")
    if tasks.get("0GStorageRelayFrpc", {}).get("Status") != "Running":
        blockers.append("storage_relay_task_not_running")
    if tasks.get("0GDaRelayTunnel", {}).get("Status") != "Running":
        blockers.append("adjacent_da_relay_task_not_running")
    if not config.get("minerKeyPresent"):
        blockers.append("active_config_missing_miner_key")
    if (balances.get("activeMiner", {}).get("balanceOg") or 0) < 0.25:
        blockers.append("active_miner_below_test_funding")
    if balances.get("activeMiner", {}).get("balanceOg") != 0.25:
        blockers.append("active_miner_balance_not_prior_test_amount")
    return blockers


def ssh(host: str, command: str) -> dict[str, Any]:
    proc = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=6", host, command],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return {
        "returncode": proc.returncode,
        "stdout": strip_nuls(proc.stdout),
        "stderr": strip_nuls(proc.stderr),
    }


def wsl(args: argparse.Namespace, command: str) -> dict[str, Any]:
    return ssh(
        args.host,
        f'wsl.exe -d {args.wsl_distro} -- bash -lc "{windows_bash_quote(command)}"',
    )


def json_rpc(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    return body if isinstance(body, dict) else {"error": "non_object_response"}


def tcp_probe(host: str, port: int) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=5):
            return {"ok": True, "latencyMs": int((time.perf_counter() - started) * 1000)}
    except OSError as exc:
        return {
            "ok": False,
            "latencyMs": int((time.perf_counter() - started) * 1000),
            "error": f"{type(exc).__name__}: {exc}",
        }


def udp_send_probe(host: str, port: int) -> dict[str, Any]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(b"zeroguard-probe", (host, port))
    except OSError as exc:
        return {"sent": False, "error": f"{type(exc).__name__}: {exc}"}
    finally:
        try:
            sock.close()
        except UnboundLocalError:
            pass
    return {
        "sent": True,
        "verified": False,
        "note": "UDP send succeeded; protocol-level response is not expected from this probe.",
    }


def parse_schtasks_list(raw: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def redact_command(command: str) -> str:
    parts = command.split()
    redacted = []
    skip_next = False
    for part in parts:
        if skip_next:
            redacted.append("<redacted>")
            skip_next = False
            continue
        redacted.append(part)
        if part in {"--miner-key", "--private-key"}:
            skip_next = True
    return " ".join(redacted)


def parse_hex_int(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def windows_bash_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def strip_nuls(value: str) -> str:
    return value.replace("\x00", "")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
