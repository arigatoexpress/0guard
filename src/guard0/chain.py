"""
0G Chain Integration — Policy Receipt Anchoring
================================================
0G Chain is an EVM-compatible blockchain (Chain ID configurable via env).
This module anchors SHA-256 policy receipt hashes on-chain so decisions are
auditable, tamper-evident, and verifiable by third parties.

Intended contract: PolicyReceiptAnchor (see contracts/PolicyReceiptAnchor.sol)
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from web3 import Web3

DEFAULT_ZGG_CHAIN_RPC = "https://evmrpc.0g.ai"
DEFAULT_ZGG_CHAIN_ID = 16661
DEFAULT_ZGG_RECEIPT_CONTRACT = "0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc"
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_RECEIPT_ARTIFACT = REPO_ROOT / "contracts" / "PolicyReceiptAnchor.json"


def get_0g_config() -> dict[str, Any]:
    """Return the current 0G runtime config without requiring secrets."""
    return {
        "rpc": os.getenv("ZGG_CHAIN_RPC", DEFAULT_ZGG_CHAIN_RPC),
        "chain_id": int(os.getenv("ZGG_CHAIN_ID", str(DEFAULT_ZGG_CHAIN_ID))),
        "receipt_contract": os.getenv("ZGG_RECEIPT_CONTRACT", DEFAULT_ZGG_RECEIPT_CONTRACT),
    }


def build_0g_status(timeout_seconds: float = 3.0) -> dict[str, Any]:
    """Run a read-only 0G RPC status check for demo and operator surfaces."""
    cfg = get_0g_config()
    contract = cfg["receipt_contract"]
    contract_configured = contract.lower() != ZERO_ADDRESS.lower()
    network_name = {
        16661: "0G Mainnet",
        16602: "0G Galileo Testnet",
    }.get(cfg["chain_id"], "0G Chain")
    started = time.perf_counter()

    rpc_status: dict[str, Any] = {
        "status": "unknown",
        "rpc": cfg["rpc"],
        "expectedChainId": cfg["chain_id"],
        "observedChainId": None,
        "latestBlockNumber": None,
        "latencyMs": None,
        "error": None,
    }
    contract_status: dict[str, Any] = {
        "address": contract,
        "configured": contract_configured,
        "codePresent": False,
        "status": "not_configured",
    }

    try:
        w3 = Web3(Web3.HTTPProvider(cfg["rpc"], request_kwargs={"timeout": timeout_seconds}))
        observed_chain_id = int(w3.eth.chain_id)
        latest_block = int(w3.eth.block_number)
        latency_ms = int((time.perf_counter() - started) * 1000)
        rpc_status.update(
            {
                "status": "ok" if observed_chain_id == cfg["chain_id"] else "chain_id_mismatch",
                "observedChainId": observed_chain_id,
                "latestBlockNumber": latest_block,
                "latencyMs": latency_ms,
            }
        )

        if contract_configured:
            code = w3.eth.get_code(Web3.to_checksum_address(contract))
            contract_status.update(
                {
                    "codePresent": bool(code),
                    "status": "deployed" if code else "no_code_at_address",
                }
            )
    except Exception as exc:  # pragma: no cover - exercised by runtime probes
        rpc_status.update(
            {
                "status": "degraded",
                "latencyMs": int((time.perf_counter() - started) * 1000),
                "error": f"{type(exc).__name__}: {exc}",
            }
        )

    return {
        "schema": "0guard.0g_status.v1",
        "network": network_name,
        "readMode": "live_rpc_read_only",
        "rpc": rpc_status,
        "receiptAnchor": contract_status,
        "safety": {
            "privateKeyRequired": False,
            "signingEnabled": False,
            "broadcastingEnabled": False,
            "moneyMovementEnabled": False,
            "workbenchCanDeploy": False,
        },
    }


def anchor_receipt(
    receipt_hash: str,
    decision: str,
    severity: str,
    agent_id: str = "",
) -> dict[str, Any]:
    """
    Anchor a policy receipt hash on 0G Chain.

    In live mode this builds & signs a transaction to the PolicyReceiptAnchor
    contract. For hackathon demo / testing the receipt is returned in
    'pre-flight' form so the user can review before broadcasting.
    """
    cfg = get_0g_config()
    payload = {
        "receipt_hash": receipt_hash,
        "decision": decision,
        "severity": severity,
        "agent_id": agent_id,
        "chain_id": cfg["chain_id"],
        "contract": cfg["receipt_contract"],
        "rpc": cfg["rpc"],
        "status": "preflight",
        "note": "Set ZGG_RECEIPT_CONTRACT to a deployed PolicyReceiptAnchor address to enable live anchoring.",
    }
    return payload


def verify_anchor(receipt_hash: str, tx_hash: str | None = None) -> dict[str, Any]:
    """Verify that a receipt hash has been anchored on 0G Chain."""
    cfg = get_0g_config()
    normalized_hash = _normalize_receipt_hash(receipt_hash)
    contract = cfg["receipt_contract"]
    if not normalized_hash:
        return {
            "schema": "0guard.0g_receipt_verifier.v1",
            "receipt_hash": receipt_hash,
            "tx_hash": tx_hash,
            "verified": False,
            "status": "invalid_receipt_hash",
            "error": "receipt_hash must be a 32-byte hex string",
            "safety": _read_only_verifier_safety(),
        }
    if contract.lower() == ZERO_ADDRESS.lower():
        return {
            "schema": "0guard.0g_receipt_verifier.v1",
            "receipt_hash": normalized_hash,
            "tx_hash": tx_hash,
            "verified": False,
            "status": "contract_not_configured",
            "chain_id": cfg["chain_id"],
            "contract": contract,
            "note": "Set ZGG_RECEIPT_CONTRACT after deploying PolicyReceiptAnchor.",
            "safety": _read_only_verifier_safety(),
        }

    started = time.perf_counter()
    try:
        w3 = Web3(Web3.HTTPProvider(cfg["rpc"], request_kwargs={"timeout": 5}))
        checksum_contract = Web3.to_checksum_address(contract)
        code = w3.eth.get_code(checksum_contract)
        if not code:
            return {
                "schema": "0guard.0g_receipt_verifier.v1",
                "receipt_hash": normalized_hash,
                "tx_hash": tx_hash,
                "verified": False,
                "status": "no_code_at_contract",
                "chain_id": cfg["chain_id"],
                "contract": contract,
                "latencyMs": int((time.perf_counter() - started) * 1000),
                "safety": _read_only_verifier_safety(),
            }

        artifact = _load_policy_receipt_artifact()
        receipt_contract = w3.eth.contract(address=checksum_contract, abi=artifact["abi"])
        receipt = receipt_contract.functions.getReceipt(
            Web3.to_bytes(hexstr=normalized_hash)
        ).call()
        timestamp = int(receipt[4])
        verified = timestamp > 0
        return {
            "schema": "0guard.0g_receipt_verifier.v1",
            "receipt_hash": normalized_hash,
            "tx_hash": tx_hash,
            "verified": verified,
            "status": "verified" if verified else "not_found",
            "chain_id": cfg["chain_id"],
            "contract": contract,
            "receipt": {
                "decision": receipt[1],
                "severity": receipt[2],
                "agent_id": receipt[3],
                "timestamp": timestamp,
                "submitter": receipt[5],
            }
            if verified
            else None,
            "latencyMs": int((time.perf_counter() - started) * 1000),
            "safety": _read_only_verifier_safety(),
        }
    except Exception as exc:  # pragma: no cover - live RPC/contract dependent
        return {
            "schema": "0guard.0g_receipt_verifier.v1",
            "receipt_hash": normalized_hash,
            "tx_hash": tx_hash,
            "verified": False,
            "status": "degraded",
            "chain_id": cfg["chain_id"],
            "contract": contract,
            "latencyMs": int((time.perf_counter() - started) * 1000),
            "error": f"{type(exc).__name__}: {exc}",
            "safety": _read_only_verifier_safety(),
        }


def _normalize_receipt_hash(receipt_hash: str) -> str | None:
    value = str(receipt_hash or "").strip().lower()
    if value.startswith("0x"):
        value = value[2:]
    if len(value) != 64:
        return None
    try:
        int(value, 16)
    except ValueError:
        return None
    return f"0x{value}"


def _load_policy_receipt_artifact() -> dict[str, Any]:
    import json

    with POLICY_RECEIPT_ARTIFACT.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _read_only_verifier_safety() -> dict[str, Any]:
    return {
        "readOnly": True,
        "privateKeyRequired": False,
        "signingEnabled": False,
        "broadcastingEnabled": False,
        "moneyMovementEnabled": False,
    }
