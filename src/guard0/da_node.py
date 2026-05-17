"""Read-only 0G node telemetry and Telegram digest previews."""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Protocol

import requests
from web3 import Web3

DA_NODE_STATUS_SCHEMA = "0guard.0g_da_node_status.v1"
DA_NODE_TELEGRAM_PREVIEW_SCHEMA = "0guard.telegram_da_node_preview.v1"
STORAGE_NODE_STATUS_SCHEMA = "0guard.0g_storage_node_status.v1"
STORAGE_NODE_TELEGRAM_PREVIEW_SCHEMA = "0guard.telegram_storage_node_preview.v1"
DEFAULT_DA_RPC = "https://evmrpc-testnet.0g.ai"
DEFAULT_DA_CHAIN_ID = 16602
DEFAULT_DA_ENTRANCE_ADDRESS = "0x857C0A28A8634614BB2C96039Cf4a20AFF709Aa9"
DEFAULT_MINIMUM_NODE_OG = 10
DEFAULT_TOKENS_PER_VOTE = 30
DEFAULT_SOCKET = "35.254.123.37:34000"
DEFAULT_SIGNER_ADDRESS = "0x6De500690f88A920Db7976b161034fC835b96A49"
DEFAULT_MINER_ADDRESS = "0x8c497E41405C924D81dB24aB033CAca71ED559E9"
DEFAULT_STORAGE_RPC = "http://127.0.0.1:5678"
DEFAULT_STORAGE_CHAIN_ID = 16661
DEFAULT_STORAGE_FLOW_ADDRESS = "0x62d4144db0f0a6fbbaeb6296c785c71b3d57c526"
DEFAULT_STORAGE_SOCKET = "35.254.123.37:1234"
DEFAULT_STORAGE_MIN_PEERS = 1

EVM_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
SENSITIVE_KEY_RE = re.compile(r"(private|secret|mnemonic|token|password)", re.IGNORECASE)


class BalanceReader(Protocol):
    def __call__(self, rpc: str, address: str, timeout_seconds: float) -> dict[str, Any]:
        """Return a balance readback for an address."""


class StorageStatusReader(Protocol):
    def __call__(self, rpc: str, timeout_seconds: float) -> dict[str, Any]:
        """Return a read-only storage node JSON-RPC status packet."""


def build_da_node_status(
    *,
    live: bool = False,
    status_file: str | None = None,
    timeout_seconds: float = 4.0,
    balance_reader: BalanceReader | None = None,
) -> dict[str, Any]:
    """Build a public, no-secret DA node status packet."""

    cfg = _da_node_config(status_file=status_file)
    file_status = _load_status_file(cfg["statusFile"]) if cfg["statusFile"] else None
    started = time.perf_counter()
    rpc_status = _rpc_status_unknown(cfg)
    balances = _configured_balances(cfg)

    if live:
        rpc_status = _read_rpc_status(cfg, timeout_seconds=timeout_seconds)
        reader = balance_reader or _read_balance
        for role in ("signer", "miner"):
            address = cfg["addresses"][role]
            if address["configured"]:
                balances[role] = reader(cfg["rpc"], address["address"], timeout_seconds)

    readiness = _readiness(cfg, rpc_status, balances, file_status)
    return {
        "schema": DA_NODE_STATUS_SCHEMA,
        "generatedAt": _utc_now(),
        "mode": "live_rpc_read_only" if live else "configured_snapshot",
        "node": {
            "name": cfg["nodeName"],
            "host": cfg["host"],
            "publicSocket": cfg["publicSocket"],
            "relay": {
                "host": cfg["relayHost"],
                "port": cfg["relayPort"],
                "expectedPublicSocket": cfg["publicSocket"],
            },
            "config": {
                "rpc": cfg["rpc"],
                "expectedChainId": cfg["chainId"],
                "daEntranceAddress": cfg["daEntranceAddress"],
                "minimumNodeOg": cfg["minimumNodeOg"],
                "tokensPerVote": cfg["tokensPerVote"],
            },
            "addresses": cfg["addresses"],
        },
        "rpc": rpc_status,
        "balances": balances,
        "fileStatus": file_status,
        "readiness": readiness,
        "yield": {
            "status": "not_claimed_without_reward_source",
            "estimatedMonthlyOg": None,
            "reason": (
                "This read-only probe does not infer DA yield. Add an official reward "
                "contract/indexer source before showing revenue."
            ),
        },
        "telegramDigest": da_node_digest_policy(readiness),
        "latencyMs": int((time.perf_counter() - started) * 1000),
        "safety": _safety(live=live),
    }


def build_storage_node_status(
    *,
    live: bool = False,
    status_file: str | None = None,
    timeout_seconds: float = 4.0,
    status_reader: StorageStatusReader | None = None,
) -> dict[str, Any]:
    """Build a public, no-secret 0G storage node status packet."""

    cfg = _storage_node_config(status_file=status_file)
    file_status = _load_status_file(cfg["statusFile"]) if cfg["statusFile"] else None
    started = time.perf_counter()
    rpc_status = _storage_rpc_status_unknown(cfg)

    if live:
        reader = status_reader or _read_storage_status
        rpc_status = reader(cfg["rpc"], timeout_seconds)

    readiness = _storage_readiness(cfg, rpc_status, file_status)
    return {
        "schema": STORAGE_NODE_STATUS_SCHEMA,
        "generatedAt": _utc_now(),
        "mode": "live_storage_rpc_read_only" if live else "configured_snapshot",
        "node": {
            "name": cfg["nodeName"],
            "host": cfg["host"],
            "network": "0g_mainnet",
            "publicSocket": cfg["publicSocket"],
            "relay": {
                "host": cfg["relayHost"],
                "port": cfg["relayPort"],
                "expectedPublicSocket": cfg["publicSocket"],
            },
            "config": {
                "rpc": cfg["rpc"],
                "expectedChainId": cfg["chainId"],
                "expectedFlowAddress": cfg["flowAddress"],
                "minimumConnectedPeers": cfg["minimumPeers"],
                "noKeyMode": cfg["noKeyMode"],
            },
        },
        "storageRpc": rpc_status,
        "fileStatus": file_status,
        "readiness": readiness,
        "funding": {
            "status": "not_ready_for_mainnet_funds" if cfg["noKeyMode"] else "operator_review_required",
            "mainnetFundingRecommended": False,
            "reason": (
                "This storage node is intentionally staged in no-key mode until a soak, exact "
                "recipient, exact amount, and explicit transaction confirmation are complete."
            ),
        },
        "yield": {
            "status": "not_inferred_without_official_reward_source",
            "estimatedMonthlyOg": None,
        },
        "telegramDigest": storage_node_digest_policy(readiness),
        "latencyMs": int((time.perf_counter() - started) * 1000),
        "safety": _safety(live=live),
    }


def build_telegram_da_node_preview(
    status: dict[str, Any] | None = None,
    *,
    live: bool = False,
    opt_in_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a Telegram-safe DA node digest preview without sending it."""

    node_status = status or build_da_node_status(live=live)
    readiness = node_status.get("readiness") or {}
    balances = node_status.get("balances") or {}
    signer = balances.get("signer") or {}
    miner = balances.get("miner") or {}
    node = node_status.get("node") or {}
    digest_policy = da_node_digest_policy(readiness)
    message = "\n".join(
        [
            "0guard DA node update",
            f"Status: {readiness.get('status', 'unknown')}",
            f"Socket: {(node.get('publicSocket') or 'not configured')}",
            f"Signer balance: {_balance_label(signer)}",
            f"Miner balance: {_balance_label(miner)}",
            f"Yield: {(node_status.get('yield') or {}).get('status', 'not reported')}",
            "Delivery: preview only; no Telegram message was sent.",
        ]
    )

    return {
        "schema": DA_NODE_TELEGRAM_PREVIEW_SCHEMA,
        "delivery": "preview_no_send",
        "telegram_send": False,
        "network_calls": bool((node_status.get("safety") or {}).get("networkCalls")),
        "mode": "da_node_digest_preview",
        "opt_in_status": (opt_in_record or {}).get("status", "not_attached"),
        "record_id": (opt_in_record or {}).get("record_id"),
        "message": message,
        "summary": {
            "status": readiness.get("status"),
            "blockedBy": readiness.get("blockedBy", []),
            "publicSocket": node.get("publicSocket"),
            "signerBalanceOg": signer.get("balanceOg"),
            "minerBalanceOg": miner.get("balanceOg"),
            "yieldStatus": (node_status.get("yield") or {}).get("status"),
        },
        "digestPolicy": digest_policy,
        "nodeStatus": node_status,
        "safety": {
            "telegramSendsEnabled": False,
            "workbenchCanSend": False,
            "transactionSigningEnabled": False,
            "moneyMovementEnabled": False,
            "privateKeyRequired": False,
        },
    }


def build_telegram_storage_node_preview(
    status: dict[str, Any] | None = None,
    *,
    live: bool = False,
    opt_in_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a Telegram-safe storage node digest preview without sending it."""

    node_status = status or build_storage_node_status(live=live)
    readiness = node_status.get("readiness") or {}
    storage_rpc = node_status.get("storageRpc") or {}
    identity = storage_rpc.get("networkIdentity") or {}
    node = node_status.get("node") or {}
    message = "\n".join(
        [
            "0guard storage node update",
            f"Status: {readiness.get('status', 'unknown')}",
            f"Socket: {(node.get('publicSocket') or 'not configured')}",
            f"Peers: {storage_rpc.get('connectedPeers', 'not checked')}",
            f"Chain: {identity.get('chainId', storage_rpc.get('expectedChainId', 'unknown'))}",
            f"Log sync height: {storage_rpc.get('logSyncHeight', 'not checked')}",
            f"Funding: {(node_status.get('funding') or {}).get('status', 'not reported')}",
            "Delivery: preview only; no Telegram message was sent.",
        ]
    )
    return {
        "schema": STORAGE_NODE_TELEGRAM_PREVIEW_SCHEMA,
        "delivery": "preview_no_send",
        "telegram_send": False,
        "network_calls": bool((node_status.get("safety") or {}).get("networkCalls")),
        "mode": "storage_node_digest_preview",
        "opt_in_status": (opt_in_record or {}).get("status", "not_attached"),
        "record_id": (opt_in_record or {}).get("record_id"),
        "message": message,
        "summary": {
            "status": readiness.get("status"),
            "blockedBy": readiness.get("blockedBy", []),
            "publicSocket": node.get("publicSocket"),
            "connectedPeers": storage_rpc.get("connectedPeers"),
            "logSyncHeight": storage_rpc.get("logSyncHeight"),
            "fundingStatus": (node_status.get("funding") or {}).get("status"),
        },
        "digestPolicy": storage_node_digest_policy(readiness),
        "nodeStatus": node_status,
        "safety": {
            "telegramSendsEnabled": False,
            "workbenchCanSend": False,
            "transactionSigningEnabled": False,
            "moneyMovementEnabled": False,
            "privateKeyRequired": False,
        },
    }


def da_node_digest_policy(readiness: dict[str, Any]) -> dict[str, Any]:
    """Return the no-spam delivery policy used by Telegram previews."""

    status = readiness.get("status", "unknown") if isinstance(readiness, dict) else "unknown"
    urgent = status in {"degraded", "blocked", "down"}
    return {
        "enabled": False,
        "wouldSendFromWorkbench": False,
        "minIntervalSeconds": 3600,
        "maxMessagesPerDay": 6,
        "sendOnlyOnStateChange": True,
        "urgentStatuses": ["degraded", "blocked", "down"],
        "currentStatusUrgent": urgent,
        "shouldSendNow": False,
        "reason": "Preview-only until an operator enables a separate send worker.",
    }


def storage_node_digest_policy(readiness: dict[str, Any]) -> dict[str, Any]:
    """Return the no-spam delivery policy used by storage node previews."""

    status = readiness.get("status", "unknown") if isinstance(readiness, dict) else "unknown"
    urgent = status in {"blocked", "degraded", "down"}
    return {
        "enabled": False,
        "wouldSendFromWorkbench": False,
        "minIntervalSeconds": 3600,
        "maxMessagesPerDay": 6,
        "sendOnlyOnStateChange": True,
        "urgentStatuses": ["blocked", "degraded", "down"],
        "currentStatusUrgent": urgent,
        "shouldSendNow": False,
        "reason": "Preview-only until an operator enables a separate send worker.",
    }


def _da_node_config(*, status_file: str | None) -> dict[str, Any]:
    explicit_status_file = status_file or os.getenv("ZG_DA_NODE_STATUS_PATH", "").strip()
    signer = _public_address(os.getenv("ZG_DA_NODE_SIGNER_ADDRESS"), DEFAULT_SIGNER_ADDRESS)
    miner = _public_address(os.getenv("ZG_DA_NODE_MINER_ADDRESS"), DEFAULT_MINER_ADDRESS)
    public_socket = os.getenv("ZG_DA_NODE_PUBLIC_SOCKET", DEFAULT_SOCKET).strip()
    relay_host, relay_port = _split_socket(public_socket)
    return {
        "nodeName": os.getenv("ZG_DA_NODE_NAME", "ari-windows-0g-da"),
        "host": os.getenv("ZG_DA_NODE_HOST", "DESKTOP-HFCK6U9"),
        "publicSocket": public_socket,
        "relayHost": os.getenv("ZG_DA_NODE_RELAY_HOST", relay_host),
        "relayPort": int(os.getenv("ZG_DA_NODE_RELAY_PORT", str(relay_port))),
        "rpc": os.getenv("ZG_DA_NODE_RPC", DEFAULT_DA_RPC),
        "chainId": int(os.getenv("ZG_DA_NODE_CHAIN_ID", str(DEFAULT_DA_CHAIN_ID))),
        "daEntranceAddress": os.getenv("ZG_DA_NODE_DA_ENTRANCE", DEFAULT_DA_ENTRANCE_ADDRESS),
        "minimumNodeOg": float(os.getenv("ZG_DA_NODE_MINIMUM_OG", str(DEFAULT_MINIMUM_NODE_OG))),
        "tokensPerVote": float(os.getenv("ZG_DA_NODE_TOKENS_PER_VOTE", str(DEFAULT_TOKENS_PER_VOTE))),
        "statusFile": explicit_status_file,
        "addresses": {
            "signer": {"address": signer, "configured": bool(signer)},
            "miner": {"address": miner, "configured": bool(miner)},
        },
    }


def _storage_node_config(*, status_file: str | None) -> dict[str, Any]:
    explicit_status_file = status_file or os.getenv("ZG_STORAGE_NODE_STATUS_PATH", "").strip()
    public_socket = os.getenv("ZG_STORAGE_NODE_PUBLIC_SOCKET", DEFAULT_STORAGE_SOCKET).strip()
    relay_host, relay_port = _split_socket(public_socket, default_port=1234)
    return {
        "nodeName": os.getenv("ZG_STORAGE_NODE_NAME", "ari-windows-0g-storage-mainnet"),
        "host": os.getenv("ZG_STORAGE_NODE_HOST", "DESKTOP-HFCK6U9"),
        "publicSocket": public_socket,
        "relayHost": os.getenv("ZG_STORAGE_NODE_RELAY_HOST", relay_host),
        "relayPort": int(os.getenv("ZG_STORAGE_NODE_RELAY_PORT", str(relay_port))),
        "rpc": os.getenv("ZG_STORAGE_NODE_RPC", DEFAULT_STORAGE_RPC),
        "chainId": int(os.getenv("ZG_STORAGE_NODE_CHAIN_ID", str(DEFAULT_STORAGE_CHAIN_ID))),
        "flowAddress": os.getenv("ZG_STORAGE_NODE_FLOW_ADDRESS", DEFAULT_STORAGE_FLOW_ADDRESS),
        "minimumPeers": int(os.getenv("ZG_STORAGE_NODE_MIN_PEERS", str(DEFAULT_STORAGE_MIN_PEERS))),
        "noKeyMode": os.getenv("ZG_STORAGE_NODE_NO_KEY_MODE", "1").strip().lower()
        not in {"0", "false", "no"},
        "statusFile": explicit_status_file,
    }


def _readiness(
    cfg: dict[str, Any],
    rpc_status: dict[str, Any],
    balances: dict[str, Any],
    file_status: dict[str, Any] | None,
) -> dict[str, Any]:
    blockers: list[str] = []
    if not cfg["publicSocket"]:
        blockers.append("public_socket_missing")
    if rpc_status["status"] == "chain_id_mismatch":
        blockers.append("chain_id_mismatch")
    if rpc_status["status"] == "degraded":
        blockers.append("rpc_degraded")

    signer = balances.get("signer") or {}
    if signer.get("balanceWei") == "0":
        blockers.append("signer_zero_balance")
    elif signer.get("balanceOg") is None:
        blockers.append(
            "signer_balance_not_checked"
            if signer.get("status") == "not_checked"
            else "signer_balance_unavailable"
        )
    elif signer.get("balanceOg") is not None and signer["balanceOg"] < cfg["minimumNodeOg"]:
        blockers.append("signer_below_minimum_node_og")

    if file_status and file_status.get("containerStatus") in {"running", "healthy"}:
        container_status = file_status["containerStatus"]
    else:
        container_status = (file_status or {}).get("containerStatus", "not_reported")

    return {
        "status": "ready" if not blockers else "blocked",
        "blockedBy": blockers,
        "containerStatus": container_status,
        "relayReady": bool(cfg["publicSocket"]),
        "fundingReady": not any(blocker.startswith("signer_") for blocker in blockers),
        "liveStartRecommended": not blockers,
    }


def _storage_readiness(
    cfg: dict[str, Any],
    rpc_status: dict[str, Any],
    file_status: dict[str, Any] | None,
) -> dict[str, Any]:
    blockers: list[str] = []
    if not cfg["publicSocket"]:
        blockers.append("public_socket_missing")
    if rpc_status["status"] == "not_checked":
        blockers.append("storage_rpc_not_checked")
    if rpc_status["status"] == "degraded":
        blockers.append("storage_rpc_degraded")
    if rpc_status["status"] == "chain_id_mismatch":
        blockers.append("chain_id_mismatch")
    if rpc_status["status"] == "flow_address_mismatch":
        blockers.append("flow_address_mismatch")
    if (
        rpc_status.get("connectedPeers") is not None
        and rpc_status["connectedPeers"] < cfg["minimumPeers"]
    ):
        blockers.append("insufficient_connected_peers")

    if file_status and file_status.get("processStatus") in {"running", "healthy"}:
        process_status = file_status["processStatus"]
    else:
        process_status = (file_status or {}).get("processStatus", "not_reported")

    status = "ready_for_no_key_soak" if not blockers else "blocked"
    return {
        "status": status,
        "blockedBy": blockers,
        "processStatus": process_status,
        "relayReady": bool(cfg["publicSocket"]),
        "peerReady": "insufficient_connected_peers" not in blockers,
        "noKeyMode": cfg["noKeyMode"],
        "mainnetFundingReady": False,
        "liveFundingRecommended": False,
    }


def _configured_balances(cfg: dict[str, Any]) -> dict[str, Any]:
    return {
        role: {
            "address": cfg["addresses"][role]["address"],
            "status": "not_checked",
            "balanceWei": None,
            "balanceOg": None,
            "source": "configured_snapshot",
        }
        for role in ("signer", "miner")
    }


def _read_storage_status(rpc: str, timeout_seconds: float) -> dict[str, Any]:
    started = time.perf_counter()
    status = _storage_rpc_status_unknown(_storage_node_config(status_file=None))
    try:
        response = requests.post(
            rpc,
            json={"jsonrpc": "2.0", "id": 1, "method": "zgs_getStatus", "params": []},
            timeout=timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("error"):
            raise ValueError(payload["error"])
        result = payload.get("result")
        if not isinstance(result, dict):
            raise ValueError("zgs_getStatus returned no result object")

        identity = result.get("networkIdentity") or {}
        observed_chain_id = identity.get("chainId")
        observed_flow = str(identity.get("flowAddress") or "").lower()
        expected_flow = str(status["expectedFlowAddress"]).lower()
        if observed_chain_id != status["expectedChainId"]:
            node_status = "chain_id_mismatch"
        elif observed_flow and observed_flow != expected_flow:
            node_status = "flow_address_mismatch"
        else:
            node_status = "ok"

        status.update(
            {
                "status": node_status,
                "connectedPeers": int(result.get("connectedPeers", 0)),
                "logSyncHeight": result.get("logSyncHeight"),
                "logSyncBlock": result.get("logSyncBlock"),
                "nextTxSeq": result.get("nextTxSeq"),
                "networkIdentity": identity,
                "latencyMs": int((time.perf_counter() - started) * 1000),
            }
        )
    except Exception as exc:  # pragma: no cover - live network dependent
        status.update(
            {
                "status": "degraded",
                "latencyMs": int((time.perf_counter() - started) * 1000),
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
    return status


def _read_rpc_status(cfg: dict[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
    started = time.perf_counter()
    status = _rpc_status_unknown(cfg)
    try:
        w3 = Web3(Web3.HTTPProvider(cfg["rpc"], request_kwargs={"timeout": timeout_seconds}))
        observed_chain_id = int(w3.eth.chain_id)
        status.update(
            {
                "status": "ok"
                if observed_chain_id == cfg["chainId"]
                else "chain_id_mismatch",
                "observedChainId": observed_chain_id,
                "latestBlockNumber": int(w3.eth.block_number),
                "latencyMs": int((time.perf_counter() - started) * 1000),
            }
        )
    except Exception as exc:  # pragma: no cover - live network dependent
        status.update(
            {
                "status": "degraded",
                "latencyMs": int((time.perf_counter() - started) * 1000),
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
    return status


def _read_balance(rpc: str, address: str, timeout_seconds: float) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": timeout_seconds}))
        balance_wei = int(w3.eth.get_balance(Web3.to_checksum_address(address)))
        return {
            "address": address,
            "status": "ok",
            "balanceWei": str(balance_wei),
            "balanceOg": balance_wei / 10**18,
            "source": "live_rpc_read_only",
            "latencyMs": int((time.perf_counter() - started) * 1000),
        }
    except Exception as exc:  # pragma: no cover - live network dependent
        return {
            "address": address,
            "status": "degraded",
            "balanceWei": None,
            "balanceOg": None,
            "source": "live_rpc_read_only",
            "latencyMs": int((time.perf_counter() - started) * 1000),
            "error": f"{type(exc).__name__}: {exc}",
        }


def _rpc_status_unknown(cfg: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "not_checked",
        "rpc": cfg["rpc"],
        "expectedChainId": cfg["chainId"],
        "observedChainId": None,
        "latestBlockNumber": None,
        "latencyMs": None,
        "error": None,
    }


def _storage_rpc_status_unknown(cfg: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "not_checked",
        "rpc": cfg["rpc"],
        "expectedChainId": cfg["chainId"],
        "expectedFlowAddress": cfg["flowAddress"],
        "connectedPeers": None,
        "logSyncHeight": None,
        "logSyncBlock": None,
        "nextTxSeq": None,
        "networkIdentity": None,
        "latencyMs": None,
        "error": None,
    }


def _load_status_file(raw_path: str) -> dict[str, Any] | None:
    path = Path(raw_path).expanduser()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {
            "path": str(path),
            "status": "unavailable",
            "safe": True,
            "telegram_send": False,
        }
    if not isinstance(payload, dict):
        return {"path": str(path), "status": "invalid_shape", "safe": True}
    safe_payload = _strip_sensitive(payload)
    safe_payload["path"] = str(path)
    safe_payload["status"] = safe_payload.get("status", "loaded")
    safe_payload["safe"] = True
    safe_payload["telegram_send"] = False
    return safe_payload


def _strip_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _strip_sensitive(item)
            for key, item in value.items()
            if not SENSITIVE_KEY_RE.search(str(key))
        }
    if isinstance(value, list):
        return [_strip_sensitive(item) for item in value]
    return value


def _public_address(value: str | None, default: str) -> str:
    address = (value or default).strip()
    return address if EVM_ADDRESS_RE.match(address) else ""


def _split_socket(socket: str, *, default_port: int = 34000) -> tuple[str, int]:
    host, _, raw_port = socket.partition(":")
    try:
        port = int(raw_port)
    except ValueError:
        port = default_port
    return host, port


def _balance_label(balance: dict[str, Any]) -> str:
    if balance.get("balanceOg") is None:
        return str(balance.get("status") or "not checked")
    return f"{balance['balanceOg']:.6f} OG"


def _safety(*, live: bool) -> dict[str, Any]:
    return {
        "readOnly": True,
        "networkCalls": bool(live),
        "privateKeyRequired": False,
        "privateKeysReturned": False,
        "signingEnabled": False,
        "broadcastingEnabled": False,
        "moneyMovementEnabled": False,
        "telegramSendsEnabled": False,
    }


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
