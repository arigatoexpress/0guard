#!/usr/bin/env python3
"""Tiny Raspberry Pi sentinel for ZeroGuard node-health evidence.

This script performs read-only probes and writes a local heartbeat JSON file.
It does not send Telegram messages, broadcast transactions, hold keys, or make
funding decisions.
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


DEFAULT_STORAGE_RPC = "http://35.254.123.37:5678"
DEFAULT_MAINNET_RPC = "https://evmrpc.0g.ai"
DEFAULT_OUT = "~/zeroguard-pi-sentinel/state/heartbeat.json"


def main() -> int:
    parser = argparse.ArgumentParser(description="ZeroGuard Pi sentinel")
    parser.add_argument("--storage-rpc", default=DEFAULT_STORAGE_RPC)
    parser.add_argument("--mainnet-rpc", default=DEFAULT_MAINNET_RPC)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--interval", type=int, default=300)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    while True:
        heartbeat = build_heartbeat(args.storage_rpc, args.mainnet_rpc)
        write_json(Path(args.out).expanduser(), heartbeat)
        print(json.dumps(heartbeat, sort_keys=True))
        if args.once:
            return 0
        time.sleep(max(args.interval, 30))


def build_heartbeat(storage_rpc: str, mainnet_rpc: str) -> dict[str, Any]:
    storage_status = json_rpc(
        storage_rpc,
        {"jsonrpc": "2.0", "method": "zgs_getStatus", "params": [], "id": 1},
    )
    block_status = json_rpc(
        mainnet_rpc,
        {"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 2},
    )
    storage_result = storage_status.get("result") if storage_status.get("ok") else {}
    if not isinstance(storage_result, dict):
        storage_result = {}
    latest_block = parse_hex_int(block_status.get("result")) if block_status.get("ok") else None
    log_height = storage_result.get("logSyncHeight")
    sync_gap = latest_block - int(log_height) if latest_block is not None and log_height else None
    return {
        "schema": "0guard.pi_sentinel_heartbeat.v1",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "storageRpc": {
            "url": storage_rpc,
            "ok": storage_status.get("ok", False),
            "connectedPeers": storage_result.get("connectedPeers"),
            "logSyncHeight": log_height,
            "nextTxSeq": storage_result.get("nextTxSeq"),
            "networkIdentity": storage_result.get("networkIdentity"),
            "error": storage_status.get("error"),
        },
        "mainnetRpc": {
            "url": mainnet_rpc,
            "ok": block_status.get("ok", False),
            "latestBlock": latest_block,
            "error": block_status.get("error"),
        },
        "syncGapBlocks": sync_gap,
        "relay": {
            "tcp1234": tcp_probe("35.254.123.37", 1234),
            "tcp5678": tcp_probe("35.254.123.37", 5678),
            "tcp50051": tcp_probe("35.254.123.37", 50051),
        },
        "interfaces": interface_snapshot(),
        "safety": {
            "readOnly": True,
            "telegramSendsEnabled": False,
            "transactionBroadcastingEnabled": False,
            "moneyMovementEnabled": False,
            "privateKeysLoaded": False,
        },
    }


def json_rpc(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    started = time.perf_counter()
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
        return {
            "ok": False,
            "latencyMs": int((time.perf_counter() - started) * 1000),
            "error": f"{type(exc).__name__}: {exc}",
        }
    if isinstance(body, dict) and "error" in body:
        return {
            "ok": False,
            "latencyMs": int((time.perf_counter() - started) * 1000),
            "error": str(body["error"]),
        }
    return {
        "ok": True,
        "latencyMs": int((time.perf_counter() - started) * 1000),
        "result": body.get("result") if isinstance(body, dict) else None,
    }


def tcp_probe(host: str, port: int) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=3):
            return {"ok": True, "latencyMs": int((time.perf_counter() - started) * 1000)}
    except OSError as exc:
        return {
            "ok": False,
            "latencyMs": int((time.perf_counter() - started) * 1000),
            "error": f"{type(exc).__name__}: {exc}",
        }


def interface_snapshot() -> list[dict[str, Any]]:
    try:
        proc = subprocess.run(
            ["ip", "-j", "addr"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        payload = json.loads(proc.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return []
    interfaces = []
    for item in payload if isinstance(payload, list) else []:
        interfaces.append(
            {
                "ifname": item.get("ifname"),
                "operstate": item.get("operstate"),
                "addr_info": [
                    {
                        "family": addr.get("family"),
                        "local": addr.get("local"),
                        "prefixlen": addr.get("prefixlen"),
                    }
                    for addr in item.get("addr_info", [])
                    if addr.get("family") in {"inet", "inet6"}
                ],
            }
        )
    return interfaces


def parse_hex_int(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(f"{path.suffix}.tmp")
    tmp.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")
    tmp.replace(path)


if __name__ == "__main__":
    raise SystemExit(main())
