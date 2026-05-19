"""Operational readiness summary for the 0guard service."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guard0.chain import ZERO_ADDRESS, get_0g_config
from guard0.incident_data import detection_coverage, incident_summary
from guard0.reputation_shadow import build_reputation_shadow_cache

READINESS_SCHEMA = "0guard.readyz.v1"
REPO_ROOT = Path(__file__).resolve().parents[2]
MAINNET_PROOF_PATH = REPO_ROOT / "docs" / "hackathon-0g" / "mainnet-proof.json"
DEFAULT_TELEGRAM_OPT_IN_STORE_PATH = REPO_ROOT / "content" / "telegram_opt_ins.local.json"


def production_readiness() -> dict[str, Any]:
    """Return an honest no-side-effect production-readiness profile."""
    cfg = get_0g_config()
    mainnet_proof = _load_mainnet_proof()
    summary = incident_summary()
    coverage = detection_coverage()
    shadow = build_reputation_shadow_cache()
    telegram_store = _telegram_store_detail()
    production_gates = _production_gate_payloads()
    storage = production_gates["storage"]
    pi_mesh = production_gates["pi_mesh"]
    reputation_backfill = production_gates["reputation_backfill"]
    private_compute_smoke = production_gates["private_compute_smoke"]
    storage_upload = production_gates["storage_upload"]
    x402_preflight = production_gates["x402_preflight"]
    x402_policy = production_gates["x402_policy"]

    checks = [
        _check(
            "runtime_health",
            "ok",
            "Flask API can build health/readiness payloads without secrets.",
            {"service": "zg-hack-guard"},
        ),
        _check(
            "mainnet_verifier_profile",
            "ok" if _mainnet_runtime_configured(cfg, mainnet_proof) else "review",
            "0G mainnet verifier env should point at the proven receipt contract.",
            {
                "currentChainId": cfg["chain_id"],
                "currentRpc": cfg["rpc"],
                "receiptContractConfigured": cfg["receipt_contract"].lower()
                != ZERO_ADDRESS.lower(),
                "expectedChainId": mainnet_proof.get("chain_id"),
                "expectedRpc": mainnet_proof.get("rpc"),
                "expectedReceiptContract": mainnet_proof.get("contract_address"),
            },
        ),
        _check(
            "mainnet_proof_file",
            "ok" if mainnet_proof.get("readback", {}).get("verified") else "review",
            "Repository includes a public 0G mainnet deploy and receipt-readback proof.",
            {
                "path": "docs/hackathon-0g/mainnet-proof.json",
                "anchorVerified": bool(mainnet_proof.get("readback", {}).get("verified")),
                "anchorTxHash": mainnet_proof.get("anchor_tx_hash", ""),
                "contractAddress": mainnet_proof.get("contract_address", ""),
            },
        ),
        _check(
            "incident_dataset",
            "ok" if (summary.get("meta") or {}).get("total_incidents") else "review",
            "Incident corpus is loaded and source-linked for detector coverage.",
            {
                "incidentCount": (summary.get("meta") or {}).get("total_incidents"),
                "datasetFingerprint": coverage.get("datasetFingerprint"),
            },
        ),
        _check(
            "detector_coverage",
            "ok" if coverage.get("coverageRatio") == 1.0 else "review",
            "Detector seeds cover the validated incident set used by the public proof page.",
            {
                "coveredCount": coverage.get("coveredCount"),
                "incidentCount": coverage.get("incidentCount"),
                "coverageRatio": coverage.get("coverageRatio"),
            },
        ),
        _check(
            "reputation_shadow_cache",
            "ok" if shadow.get("sourceCount", 0) >= 3 else "review",
            "Derived reputation cache composes reviewed payloads without live fetches or raw resale.",
            {
                "schema": shadow.get("schema"),
                "sourceCount": shadow.get("sourceCount"),
                "derivedSignalCount": shadow.get("derivedSignalCount"),
                "decision": (shadow.get("probePreview") or {}).get("decision", {}).get("decision"),
                "rawPayloadsReturned": shadow.get("sourceRights", {}).get("rawPayloadsReturned"),
            },
        ),
        _check(
            "telegram_state_store",
            "ok" if telegram_store["persistentStoreConfigured"] else "review",
            "Telegram opt-in state persists to a local git-ignored JSON store unless an external store is configured.",
            {
                **telegram_store,
                "outboundSendsEnabled": False,
                "operatorNextStep": (
                    "wire Firestore/Cloud SQL before high-volume production sends"
                    if not telegram_store["persistentStoreConfigured"]
                    else "promote this file-backed store only for low-volume previews; use Firestore/Cloud SQL for scale"
                ),
            },
        ),
        _check(
            "storage_node_funded_soak",
            "ok" if _storage_soak_ready(storage) else "review",
            "RV Windows 0G mainnet storage node must be synced, peered, relayed, and funded only within the reviewed budget.",
            _storage_soak_detail(storage),
        ),
        _check(
            "pi_mesh_cluster",
            "ok" if (pi_mesh.get("readiness") or {}).get("clusterReady") else "review",
            "Raspberry Pi sentinels should be reachable over the private Ethernet mesh without secrets or sends.",
            {
                "mode": pi_mesh.get("mode"),
                "clusterReady": (pi_mesh.get("readiness") or {}).get("clusterReady"),
                "blockers": (pi_mesh.get("readiness") or {}).get("blockers"),
                "nodeCount": len(pi_mesh.get("observedNodes") or []),
                "telegramSendsEnabled": (pi_mesh.get("safety") or {}).get(
                    "telegramSendsEnabled"
                ),
            },
        ),
        _check(
            "telegram_live_identity",
            "ok" if _telegram_identity_configured() else "review",
            "Production bot identity and webhook proof must be loaded server-side before live Telegram operations.",
            {
                "botTokenConfigured": _telegram_identity_configured(),
                "webhookSecretConfigured": bool(
                    os.getenv("TELEGRAM_WEBHOOK_SECRET_TOKEN", "").strip()
                    or os.getenv("ZG_TELEGRAM_WEBHOOK_SECRET", "").strip()
                ),
                "outboundSendsEnabled": False,
                "operatorNextStep": (
                    "load TELEGRAM_BOT_TOKEN and read back /api/telegram/status?live=1"
                    if not _telegram_identity_configured()
                    else "verify getMe/webhook readback while keeping sends disabled"
                ),
            },
        ),
        _check(
            "reputation_backfill_artifact",
            "ok" if reputation_backfill.get("status") == "ready" else "review",
            "At least one rights-cleared reputation worker output should be fresh and derived-only.",
            {
                "status": reputation_backfill.get("status"),
                "latestRunExists": reputation_backfill.get("latestRunExists"),
                "latestAgeSeconds": reputation_backfill.get("latestAgeSeconds"),
                "ttlSeconds": reputation_backfill.get("ttlSeconds"),
                "derivedEvidenceCount": reputation_backfill.get("derivedEvidenceCount"),
                "parsedDomainCount": reputation_backfill.get("parsedDomainCount"),
                "rawPayloadsReturned": reputation_backfill.get("rawPayloadsReturned"),
                "supervisorInstalled": (
                    reputation_backfill.get("scheduleManifest") or {}
                ).get("supervisorInstalled"),
            },
        ),
        _check(
            "storage_upload_readback",
            "ok" if _storage_upload_live_readback_complete(storage_upload) else "review",
            "0G Storage claims need live upload and download/readback proof, not only local hashes.",
            {
                "manifestSchema": storage_upload.get("schema"),
                "bundleFileCount": (storage_upload.get("bundle") or {}).get("fileCount"),
                "localReadbackAllMatched": (
                    storage_upload.get("readbackVerifier") or {}
                ).get("allMatched"),
                "liveStorageUpload": (storage_upload.get("safety") or {}).get(
                    "liveStorageUpload"
                ),
                "liveStorageGatewayReadback": (storage_upload.get("safety") or {}).get(
                    "liveStorageGatewayReadback"
                ),
                "operatorRequired": (storage_upload.get("uploadPlan") or {}).get(
                    "operatorRequired"
                ),
            },
        ),
        _check(
            "private_compute_paid_smoke",
            "ok" if _private_compute_smoke_complete(private_compute_smoke) else "review",
            "0G Private Computer integration needs a server-side key, budget gate, and one prompt-minimized paid smoke before production claims.",
            {
                "status": private_compute_smoke.get("status"),
                "blockers": private_compute_smoke.get("blockers"),
                "apiKeyConfigured": (
                    private_compute_smoke.get("router") or {}
                ).get("apiKeyConfigured"),
                "paidInferenceAllowedByEnv": (
                    private_compute_smoke.get("router") or {}
                ).get("paidInferenceAllowedByEnv"),
                "budgetUsd": (private_compute_smoke.get("router") or {}).get("budgetUsd"),
                "inferenceExecuted": (private_compute_smoke.get("safety") or {}).get(
                    "inferenceExecuted"
                ),
                "promptSafeForInference": (private_compute_smoke.get("safety") or {}).get(
                    "promptSafeForInference"
                ),
            },
        ),
        _check(
            "x402_settlement_path",
            "ok" if _x402_settlement_enabled(x402_preflight) else "review",
            "Machine-payable data routes are production only after testnet/live settlement readback; caps and terms are tracked separately.",
            {
                "status": x402_preflight.get("status"),
                "httpStatus": x402_preflight.get("httpStatus"),
                "settlementPolicySchema": x402_policy.get("schema"),
                "spendCapsConfigured": bool(x402_policy.get("spendCaps")),
                "termsConfigured": bool(x402_policy.get("terms")),
                "payToConfigured": (
                    x402_policy.get("paymentRequirement") or {}
                ).get("payToConfigured"),
                "perRequestMax": (x402_policy.get("spendCaps") or {}).get(
                    "perRequestMaxDisplay"
                ),
                "settlementEnabled": (x402_preflight.get("safety") or {}).get(
                    "x402SettlementEnabled"
                ),
                "settlementAttempted": (
                    x402_preflight.get("paymentReadback") or {}
                ).get("settlementAttempted"),
                "facilitatorCalled": (
                    x402_preflight.get("paymentReadback") or {}
                ).get("facilitatorCalled"),
                "rawPayloadResaleAllowed": (
                    x402_preflight.get("rightsPolicy") or {}
                ).get("rawPayloadResaleAllowed"),
                "policySettlementEnabled": (x402_policy.get("safety") or {}).get(
                    "x402SettlementEnabled"
                ),
            },
        ),
        _check(
            "external_actions",
            "ok",
            "Workbench cannot sign, broadcast, settle, send, post, bridge, swap, or move funds.",
            _safety(),
        ),
    ]
    review_count = sum(1 for check in checks if check["status"] == "review")
    hard_gates = [check["id"] for check in checks if check["status"] == "review"]
    return {
        "schema": READINESS_SCHEMA,
        "generatedAt": _now(),
        "mode": "operational_readiness_no_side_effects",
        "ok": review_count == 0,
        "status": "production_review" if review_count else "production_ready",
        "readiness": "production_review" if review_count else "production_ready",
        "productionHealthy": review_count == 0,
        "reviewCount": review_count,
        "hardGates": hard_gates,
        "checks": checks,
        "operatorPromotions": [
            {
                "rank": 1,
                "id": "configure_mainnet_runtime_env",
                "why": "Align fresh runtimes with the already proven 0G mainnet contract.",
                "env": {
                    "ZGG_CHAIN_RPC": mainnet_proof.get("rpc") or "https://evmrpc.0g.ai",
                    "ZGG_CHAIN_ID": str(mainnet_proof.get("chain_id") or 16661),
                    "ZGG_RECEIPT_CONTRACT": mainnet_proof.get("contract_address") or "",
                },
                "requiresSecret": False,
            },
            {
                "rank": 2,
                "id": "persistent_telegram_opt_in_store",
                "why": "The local JSON store is enough for this workstation; managed storage is cleaner for Cloud Run.",
                "suggestedOptions": ["Firestore", "SQLite volume", "Cloud SQL"],
                "requiresSecret": True,
            },
            {
                "rank": 3,
                "id": "storage_node_expansion_watch",
                "why": "The storage node is nearly synced but still below the peer target for larger mainnet expansion.",
                "requiresSecret": False,
                "blockedBy": (storage.get("readiness") or {}).get("blockedBy") or [],
            },
            {
                "rank": 4,
                "id": "first_reviewed_connector_worker",
                "why": "Refresh the shadow cache from one reviewed source before claiming continuous live protection.",
                "suggestedFirstSources": [
                    "phishdestroy_destroylist",
                    "cryptoscamdb",
                    "forta_labelled_datasets",
                ],
                "requiresSecret": False,
            },
        ],
        "safety": _safety(),
    }


def _mainnet_runtime_configured(cfg: dict[str, Any], proof: dict[str, Any]) -> bool:
    return (
        cfg["chain_id"] == proof.get("chain_id")
        and cfg["rpc"] == proof.get("rpc")
        and cfg["receipt_contract"].lower() == str(proof.get("contract_address", "")).lower()
    )


def _load_mainnet_proof() -> dict[str, Any]:
    try:
        return json.loads(MAINNET_PROOF_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _production_gate_payloads() -> dict[str, dict[str, Any]]:
    # Keep imports local so the broad production matrix can import readiness without
    # getting tangled in an eager circular import.
    from guard0.da_node import DEFAULT_STORAGE_STATUS_PATH, build_storage_node_status
    from guard0.peer_protection import DEFAULT_PI_MESH_STATUS_PATH, build_pi_mesh_plan
    from guard0.private_compute_adapter import build_private_compute_smoke_preview
    from guard0.reputation_backfill import (
        DEFAULT_REPUTATION_BACKFILL_PATH,
        build_reputation_backfill_status,
    )
    from guard0.storage_upload_manifest import build_storage_upload_manifest
    from guard0.x402_guard import build_x402_settlement_policy, build_x402_wallet_preflight_dry_run

    return {
        "storage": _safe_payload(
            "storage_node_status",
            lambda: build_storage_node_status(
                live=False,
                status_file=DEFAULT_STORAGE_STATUS_PATH,
            ),
        ),
        "pi_mesh": _safe_payload(
            "pi_mesh_status",
            lambda: build_pi_mesh_plan(status_file=DEFAULT_PI_MESH_STATUS_PATH),
        ),
        "reputation_backfill": _safe_payload(
            "reputation_backfill_status",
            lambda: build_reputation_backfill_status(DEFAULT_REPUTATION_BACKFILL_PATH),
        ),
        "private_compute_smoke": _safe_payload(
            "private_compute_smoke_preview",
            build_private_compute_smoke_preview,
        ),
        "storage_upload": _safe_payload("storage_upload_manifest", build_storage_upload_manifest),
        "x402_preflight": _safe_payload(
            "x402_wallet_preflight_dry_run",
            build_x402_wallet_preflight_dry_run,
        ),
        "x402_policy": _safe_payload("x402_settlement_policy", build_x402_settlement_policy),
    }


def _safe_payload(name: str, builder: Any) -> dict[str, Any]:
    try:
        payload = builder()
    except Exception as exc:  # pragma: no cover - defensive readiness fallback
        return {
            "schema": f"0guard.{name}.unavailable",
            "status": "unavailable",
            "error": f"{type(exc).__name__}: {exc}",
        }
    return payload if isinstance(payload, dict) else {"status": "invalid_payload", "source": name}


def _storage_soak_ready(storage: dict[str, Any]) -> bool:
    readiness = storage.get("readiness") or {}
    funded = storage.get("fundedSoak") or {}
    return (
        readiness.get("largeFundingExpansionReady") is True
        and readiness.get("processStatus") == "running"
        and funded.get("onlyPriorTestFundingObserved") is True
        and funded.get("hundredOgTransferSent") is False
    )


def _storage_soak_detail(storage: dict[str, Any]) -> dict[str, Any]:
    readiness = storage.get("readiness") or {}
    sync = storage.get("sync") or {}
    funding = storage.get("fundingSummary") or storage.get("funding") or {}
    return {
        "mode": storage.get("mode"),
        "status": readiness.get("status") or storage.get("status"),
        "processStatus": readiness.get("processStatus") or storage.get("processStatus"),
        "blockedBy": readiness.get("blockedBy") or storage.get("blockers") or [],
        "connectedPeers": sync.get("connectedPeers"),
        "logSyncHeight": sync.get("logSyncHeight"),
        "latestMainnetBlock": sync.get("latestMainnetBlock"),
        "syncGapBlocks": sync.get("syncGapBlocks"),
        "nextTxSeq": sync.get("nextTxSeq"),
        "dbSizeHuman": sync.get("dbSizeHuman"),
        "activeMinerAddress": funding.get("activeMinerAddress"),
        "activeMinerBalanceOg": funding.get("activeMinerBalanceOg"),
        "onlyPriorTestFundingObserved": funding.get("onlyPriorTestFundingObserved"),
        "hundredOgTransferSent": funding.get("hundredOgTransferSent"),
        "largeTransferDetected": funding.get("largeTransferDetected"),
        "largeFundingExpansionReady": readiness.get("largeFundingExpansionReady"),
        "mainnetFundingRecommended": funding.get("mainnetFundingRecommended"),
    }


def _telegram_identity_configured() -> bool:
    return bool(
        os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        or os.getenv("ZG_TELEGRAM_BOT_TOKEN", "").strip()
    )


def _storage_upload_live_readback_complete(payload: dict[str, Any]) -> bool:
    safety = payload.get("safety") or {}
    return (
        safety.get("liveStorageUpload") is True
        and safety.get("liveStorageGatewayReadback") is True
        and (payload.get("readbackVerifier") or {}).get("allMatched") is True
    )


def _private_compute_smoke_complete(payload: dict[str, Any]) -> bool:
    safety = payload.get("safety") or {}
    return (
        safety.get("inferenceExecuted") is True
        and safety.get("paidInferenceEnabled") is True
        and safety.get("promptSafeForInference") is True
    )


def _x402_settlement_enabled(payload: dict[str, Any]) -> bool:
    safety = payload.get("safety") or {}
    readback = payload.get("paymentReadback") or {}
    return (
        safety.get("x402SettlementEnabled") is True
        and readback.get("settlementAttempted") is True
        and readback.get("facilitatorCalled") is True
    )


def _telegram_store_detail() -> dict[str, Any]:
    raw_path = os.getenv("TELEGRAM_OPT_IN_STORE_PATH", "").strip()
    raw_url = os.getenv("TELEGRAM_OPT_IN_STORE_URL", "").strip()
    file_url_configured = raw_url.startswith("file://")
    default_path = not raw_path and not raw_url
    persistent = bool(raw_path or file_url_configured or default_path)
    if persistent and default_path:
        mode = "local_json_default"
    elif persistent:
        mode = "local_json"
    elif raw_url:
        mode = "external_adapter_pending"
    else:
        mode = "in_memory"
    return {
        "persistentStoreConfigured": persistent,
        "storeMode": mode,
        "storePath": str(DEFAULT_TELEGRAM_OPT_IN_STORE_PATH) if default_path else raw_path,
        "defaultLocalStore": default_path,
        "externalStoreConfigured": bool(raw_url and not file_url_configured),
        "secretDisplayEnabled": False,
        "networkCalls": False,
    }


def _check(check_id: str, status: str, summary: str, detail: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": check_id,
        "status": status,
        "summary": summary,
        "detail": detail,
    }


def _safety() -> dict[str, bool]:
    return {
        "readOnly": True,
        "networkCalls": False,
        "liveConnectorFetch": False,
        "telegramSendsEnabled": False,
        "socialPostingEnabled": False,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "paymentSettlementEnabled": False,
        "exchangeOrdersEnabled": False,
        "bridgingEnabled": False,
        "moneyMovementEnabled": False,
        "secretDisplayEnabled": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
