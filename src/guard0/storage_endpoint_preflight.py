"""Read-only 0G Storage endpoint preflight checks.

This module is for operator-run endpoint validation before a reviewed live
upload. It can call the public chain RPC and ask the locked TypeScript SDK to
select storage nodes from the indexer. It never reads signer material, uploads,
downloads payloads, signs, broadcasts, or moves funds.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
STORAGE_ENDPOINT_PREFLIGHT_SCHEMA = "0guard.0g_storage_endpoint_preflight.v1"
DEFAULT_TESTNET_CHAIN_RPC = "https://evmrpc-testnet.0g.ai"
DEFAULT_TESTNET_INDEXER_RPC = "https://indexer-storage-testnet-turbo.0g.ai"
DEFAULT_TESTNET_CHAIN_ID = 16602
STORAGE_SDK_PACKAGE_PATH = (
    REPO_ROOT / "node_modules" / "@0gfoundation" / "0g-storage-ts-sdk"
)


def build_storage_endpoint_preflight(
    *,
    chain_rpc: str | None = None,
    indexer_rpc: str | None = None,
    expected_chain_id: int = DEFAULT_TESTNET_CHAIN_ID,
    timeout_seconds: float = 15,
    select_nodes: bool = True,
) -> dict[str, Any]:
    """Return a read-only endpoint readiness summary for the storage SDK lane."""

    chain_rpc_url = (chain_rpc or os.getenv("ZG_STORAGE_CHAIN_RPC") or DEFAULT_TESTNET_CHAIN_RPC).strip()
    indexer_rpc_url = (
        indexer_rpc or os.getenv("ZG_STORAGE_INDEXER_RPC") or DEFAULT_TESTNET_INDEXER_RPC
    ).strip()
    chain = _probe_chain_rpc(chain_rpc_url, expected_chain_id, timeout_seconds)
    sdk_present = STORAGE_SDK_PACKAGE_PATH.exists()
    indexer = _probe_indexer_with_sdk(indexer_rpc_url, timeout_seconds, select_nodes, sdk_present)

    blockers: list[str] = []
    if not chain["ok"]:
        blockers.extend(chain["blockers"])
    if not sdk_present:
        blockers.append("storage_sdk_runtime_not_present")
    if not indexer["ok"]:
        blockers.extend(indexer["blockers"])

    return {
        "schema": STORAGE_ENDPOINT_PREFLIGHT_SCHEMA,
        "generatedAt": _now(),
        "mode": "read_only_endpoint_probe_no_upload",
        "status": "ready_for_signer_review" if not blockers else "blocked_endpoint_probe_failed",
        "readyForSignerReview": not blockers,
        "blockers": blockers,
        "chainRpc": chain,
        "indexerRpc": indexer,
        "sdkRuntime": {
            "packageName": "@0gfoundation/0g-storage-ts-sdk",
            "packagePresent": sdk_present,
            "packagePath": "node_modules/@0gfoundation/0g-storage-ts-sdk",
            "nodeRuntimePresent": shutil.which("node") is not None,
        },
        "safety": {
            "readOnly": True,
            "networkCalls": True,
            "privateKeysRead": False,
            "privateKeysReturned": False,
            "liveStorageUpload": False,
            "liveStorageGatewayReadback": False,
            "transactionSigningEnabled": False,
            "transactionBroadcastingEnabled": False,
            "moneyMovementEnabled": False,
            "paymentHeadersStored": False,
        },
        "nextStepIfReady": (
            "Prepare signer custody, upload budget, explicit live-upload env gate, "
            "and external upload/readback proof recording outside the workbench."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only 0G Storage endpoint preflight")
    parser.add_argument(
        "--chain-rpc",
        default=None,
        help="0G chain RPC URL; defaults to ZG_STORAGE_CHAIN_RPC or Galileo testnet.",
    )
    parser.add_argument(
        "--indexer-rpc",
        default=None,
        help="0G Storage indexer URL; defaults to ZG_STORAGE_INDEXER_RPC or Galileo turbo.",
    )
    parser.add_argument(
        "--expected-chain-id",
        type=int,
        default=DEFAULT_TESTNET_CHAIN_ID,
        help="Expected decimal chain id.",
    )
    parser.add_argument("--timeout", type=float, default=15, help="Network timeout in seconds.")
    parser.add_argument(
        "--skip-node-selection",
        action="store_true",
        help="Skip the SDK indexer.selectNodes read-only probe.",
    )
    args = parser.parse_args(argv)

    result = build_storage_endpoint_preflight(
        chain_rpc=args.chain_rpc,
        indexer_rpc=args.indexer_rpc,
        expected_chain_id=args.expected_chain_id,
        timeout_seconds=args.timeout,
        select_nodes=not args.skip_node_selection,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["readyForSignerReview"] else 1


def _probe_chain_rpc(url: str, expected_chain_id: int, timeout_seconds: float) -> dict[str, Any]:
    payload = json.dumps(
        {"jsonrpc": "2.0", "method": "eth_chainId", "params": [], "id": 1}
    ).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (OSError, TimeoutError, urllib.error.URLError, json.JSONDecodeError) as exc:
        return {
            "url": url,
            "method": "eth_chainId",
            "ok": False,
            "blockers": ["chain_rpc_unreachable"],
            "errorType": type(exc).__name__,
            "error": _safe_error(exc),
        }

    result = body.get("result")
    try:
        chain_id = int(str(result), 16)
    except (TypeError, ValueError):
        chain_id = None
    chain_id_matches = chain_id == expected_chain_id
    return {
        "url": url,
        "method": "eth_chainId",
        "ok": chain_id_matches,
        "blockers": [] if chain_id_matches else ["chain_id_mismatch"],
        "expectedChainId": expected_chain_id,
        "chainId": chain_id,
        "rawChainId": result,
    }


def _probe_indexer_with_sdk(
    url: str,
    timeout_seconds: float,
    select_nodes: bool,
    sdk_present: bool,
) -> dict[str, Any]:
    if not select_nodes:
        return {
            "url": url,
            "ok": True,
            "blockers": [],
            "nodeSelectionAttempted": False,
            "reason": "skipped_by_operator",
        }
    if shutil.which("node") is None:
        return {
            "url": url,
            "ok": False,
            "blockers": ["node_runtime_not_present"],
            "nodeSelectionAttempted": False,
        }
    if not sdk_present:
        return {
            "url": url,
            "ok": False,
            "blockers": ["storage_sdk_runtime_not_present"],
            "nodeSelectionAttempted": False,
        }

    script = """
import { Indexer } from '@0gfoundation/0g-storage-ts-sdk';
const indexer = new Indexer(process.env.ZG_ENDPOINT_PREFLIGHT_INDEXER_RPC);
const [nodes, err] = await indexer.selectNodes(1);
if (err !== null) {
  console.log(JSON.stringify({ ok: false, error: String(err) }));
} else {
  console.log(JSON.stringify({
    ok: Array.isArray(nodes) && nodes.length > 0,
    selectedNodeCount: Array.isArray(nodes) ? nodes.length : 0,
    selectedNodeUrls: Array.isArray(nodes) ? nodes.map((node) => node.url).slice(0, 5) : []
  }));
}
""".strip()
    env = {
        "PATH": os.getenv("PATH", ""),
        "ZG_ENDPOINT_PREFLIGHT_INDEXER_RPC": url,
    }
    try:
        completed = subprocess.run(
            ["node", "--input-type=module", "-e", script],
            cwd=REPO_ROOT,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout_seconds + 5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "url": url,
            "ok": False,
            "blockers": ["indexer_node_selection_failed"],
            "nodeSelectionAttempted": True,
            "errorType": type(exc).__name__,
            "error": _safe_error(exc),
        }
    try:
        payload = json.loads((completed.stdout or "{}").strip())
    except json.JSONDecodeError as exc:
        return {
            "url": url,
            "ok": False,
            "blockers": ["indexer_node_selection_failed"],
            "nodeSelectionAttempted": True,
            "errorType": type(exc).__name__,
            "error": _safe_error(exc),
            "exitCode": completed.returncode,
        }
    ok = bool(payload.get("ok")) and completed.returncode == 0
    return {
        "url": url,
        "ok": ok,
        "blockers": [] if ok else ["indexer_node_selection_failed"],
        "nodeSelectionAttempted": True,
        "selectedNodeCount": int(payload.get("selectedNodeCount") or 0),
        "selectedNodeUrls": payload.get("selectedNodeUrls") or [],
        "exitCode": completed.returncode,
        "error": "" if ok else str(payload.get("error") or completed.stderr or "")[:200],
    }


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _safe_error(exc: BaseException) -> str:
    return str(exc).replace("\n", " ")[:200]


if __name__ == "__main__":
    raise SystemExit(main())

