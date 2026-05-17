"""Unified native preflight for 0guard integration surfaces.

This module is the product seam between 0G receipts, policy evaluation, TON
risk passports, Ika/dWallet signing preflights, and external guardrails. It is
not an execution adapter: it never signs, broadcasts, bridges, pays, sends, or
uploads. It prepares one deterministic verdict that other hackathon demos and
agent frameworks can call before they touch a signer.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from guard0.external_guardrails import evaluate_external_guardrail
from guard0.ika import evaluate_ika_signing_request
from guard0.policy import evaluate_intent
from guard0.reputation import build_reputation_probe
from guard0.ton import build_ton_wallet_risk_preview

NATIVE_PREFLIGHT_SCHEMA = "0guard.native_preflight.v1"
HACKATHON_STRATEGY_SCHEMA = "0guard.hackathon_strategy.v1"

_IKA_SURFACES = {
    "ika",
    "ika_dwallets",
    "ikavery",
    "mpckit",
    "odws",
    "clear_msig_ika",
    "encrypt",
    "encrypt_pre_alpha",
}
_EXTERNAL_SURFACES = {
    "x402",
    "x402_payment",
    "virtuals",
    "virtuals_base",
    "base_mainnet",
    "arbitrum",
    "arbitrum_one",
    "arbitrum_nova",
    "arbitrum_sepolia",
    "arbitrum_orbit",
    "arbitrum_stylus",
    "metamask",
    "metamask_wallet",
    "metamask_connect",
    "metamask_snap",
    "metamask_delegation",
    "metamask_smart_accounts",
    "lighter",
    "lighter_exchange",
    "chainlink_ccip",
    "ccip",
    "layerzero",
    "layerzero_v2",
    "wormhole",
    "wormhole_ntt",
    "celestia",
    "celestia_blobstream",
    *_IKA_SURFACES,
}


def build_native_preflight(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return one no-side-effect verdict across native wallet/signing surfaces."""
    body = payload or {}
    if not isinstance(body, dict):
        raise ValueError("payload must be an object")

    intent = _coerce_intent(body)
    surface = _surface(body, intent)
    chain = _norm(body.get("chain") or body.get("caip2") or intent.get("chain") or "eip155:1")
    operation = _norm_id(body.get("operation") or body.get("action") or intent.get("action") or "preview")
    source_project = _norm_id(body.get("sourceProject") or body.get("source_project") or surface)
    live_signing = _truthy(body.get("liveSigning") or body.get("live_signing"))
    live_transaction = _truthy(body.get("liveTransaction") or body.get("live_transaction"))
    message_hex = str(
        body.get("messageHex")
        or body.get("message_hex")
        or body.get("calldata")
        or intent.get("calldata")
        or intent.get("data")
        or ""
    ).strip()
    target = str(body.get("target") or body.get("to") or intent.get("to") or intent.get("target_contract") or "").strip()
    value_eth = _float_value(body.get("valueEth") or body.get("value_eth") or body.get("value") or intent.get("value_eth"))

    policy_intent = {
        **intent,
        "action": _policy_action(operation),
        "mode": "live_transaction" if live_signing or live_transaction else intent.get("mode", "preview"),
        "requires_signature": _requires_signature(operation) or bool(intent.get("requires_signature")),
        "target_contract": target,
        "to": target,
        "chain_id": _chain_id(chain),
        "value_eth": value_eth,
        "calldata": message_hex,
        "prompt_text": str(
            body.get("intentText")
            or body.get("intent_text")
            or intent.get("prompt_text")
            or intent.get("text")
            or ""
        ),
        "app": f"native-preflight:{surface}",
    }
    core_policy = evaluate_intent(policy_intent).to_dict()
    components: list[dict[str, Any]] = [_component("core_policy", core_policy["decision"], core_policy)]

    if _should_run_ika(surface=surface, source_project=source_project, operation=operation):
        ika_result = evaluate_ika_signing_request(
            {
                "chain": chain,
                "operation": operation,
                "sourceProject": source_project,
                "environment": policy_intent["mode"],
                "messageHex": message_hex,
                "target": target,
                "valueEth": value_eth,
                "intentText": policy_intent["prompt_text"],
                "liveSigning": live_signing or live_transaction,
                "sensitiveData": _truthy(body.get("sensitiveData") or body.get("sensitive_data")),
            }
        )
        components.append(_component("ika_preflight", ika_result["decision"], ika_result))

    external_target = _external_target(body=body, surface=surface)
    if external_target:
        guardrail = evaluate_external_guardrail(
            {
                "target_id": external_target,
                "action": operation,
                "intent_text": policy_intent["prompt_text"],
                "config": {
                    **(body.get("config") if isinstance(body.get("config"), dict) else {}),
                    "chain": chain,
                    "sourceProject": source_project,
                    "liveSigning": live_signing or live_transaction,
                    "messageHex": message_hex,
                    "target": target,
                    "valueEth": value_eth,
                },
            }
        )
        components.append(_component("external_guardrail", guardrail["decision"], guardrail))

    if _should_run_reputation(body):
        reputation = build_reputation_probe(
            {
                "url": body.get("url") or body.get("domain") or body.get("website") or "",
                "address": body.get("address") or target,
                "chain": chain,
                "surface": surface,
                "labels": body.get("labels") or body.get("tags") or [],
                "sourceEvidence": body.get("sourceEvidence") or body.get("evidence") or [],
                "intent": policy_intent,
            }
        )
        components.append(_component("reputation_probe", reputation["decision"]["decision"], reputation))

    ton_address = str(body.get("tonAddress") or body.get("ton_address") or "").strip()
    if surface == "ton" or chain.startswith("ton") or ton_address:
        if ton_address:
            ton_result = build_ton_wallet_risk_preview(
                ton_address,
                intent=policy_intent,
                network=str(body.get("tonNetwork") or body.get("network") or "mainnet"),
                live=False,
                include_activity=False,
            )
            components.append(_component("ton_risk_passport", ton_result["decision"]["decision"], ton_result))
        else:
            components.append(
                _component(
                    "ton_risk_passport",
                    "review",
                    {
                        "schema": "0guard.ton_wallet_risk_preview.required.v1",
                        "decision": {"decision": "review", "severity": "medium"},
                        "reason": "TON surface selected but no TON address was supplied for syntax-only passporting.",
                        "safety": _safety(),
                    },
                )
            )

    decision = _rollup([component["decision"] for component in components])
    receipt_payload = {
        "schema": NATIVE_PREFLIGHT_SCHEMA,
        "surface": surface,
        "chain": chain,
        "operation": operation,
        "decision": decision,
        "componentReceipts": _component_receipts(components),
    }
    receipt_hash = _hash_json(receipt_payload)
    safety = _safety()
    return {
        "schema": NATIVE_PREFLIGHT_SCHEMA,
        "generatedAt": _now(),
        "mode": "read_only_native_preflight",
        "surface": surface,
        "chain": chain,
        "operation": operation,
        "decision": decision,
        "transactionSigningEnabled": safety.get("transactionSigningEnabled", False),
        "zeroGStorageReady": True,
        "componentCount": len(components),
        "components": components,
        "receipt": {
            "hash": receipt_hash,
            "algorithm": "sha256_canonical_json",
            "zeroGChainReady": True,
            "zeroGStorageReady": True,
            "liveAnchorPerformed": False,
            "liveUploadPerformed": False,
        },
        "recommendedNextStep": _recommended_next_step(decision),
        "integrationPosture": {
            "0gFirst": True,
            "nativeAdaptersOnly": True,
            "bridgeAsProductStory": False,
            "signerReachableFrom0guard": False,
        },
        "safety": safety,
    }


def hackathon_strategy() -> dict[str, Any]:
    """Return source-cited, chronological build targets for 0guard expansion."""
    opportunities = [
        {
            "rank": 1,
            "id": "0g_apac_final_review",
            "name": "0G APAC Hackathon final review and awards",
            "timing": {
                "status": "submitted_monitoring",
                "submissionDeadline": "2026-05-16T23:59:00+08:00",
                "preliminaryReview": "2026-05-16 to 2026-05-24 UTC+8",
                "rewardAnnouncement": "2026-05-29",
            },
            "importance": "highest",
            "whyNow": "This is the active submitted project; all follow-on work should strengthen the 0G proof and product story.",
            "0guardBuild": "Keep mainnet receipt proof, 28/28 provenance, no-send Telegram, Ika preflight, and native preflight green.",
            "sources": ["https://www.hackquest.io/hackathons/0G-APAC-Hackathon"],
        },
        {
            "rank": 2,
            "id": "metamask_smart_accounts_1shot_api_dev_cookoff",
            "name": "MetaMask Smart Accounts Kit x 1Shot API Dev Cook Off",
            "timing": {
                "status": "active_on_source_readback_2026-05-17",
                "registrationWindow": "2026-05-15 to 2026-06-15",
                "submissionWindow": "2026-05-15 to 2026-06-15",
                "rewardAnnouncement": "2026-06-22",
            },
            "importance": "highest_next_build",
            "whyNow": "The active requirements match 0guard's strongest product wedge: preflight scoped MetaMask permissions, ERC-7710 x402 payments, and agent actions before the wallet prompt.",
            "0guardBuild": "Ship the Smart Accounts Kit permission firewall demo with bounded ERC-7715 permission review, ERC-7710 x402 payment preview, and 1Shot integration gates.",
            "sources": [
                "https://www.hackquest.io/hackathons/MetaMask-Smart-Accounts-Kit-x-1Shot-API-Dev-Cook-Off",
                "https://docs.metamask.io/smart-accounts-kit/guides/x402/overview/",
                "https://docs.1shotapi.com/x402/index.html",
            ],
        },
        {
            "rank": 3,
            "id": "arbitrum_open_house_london",
            "name": "Arbitrum Open House London Buildathon",
            "timing": {
                "status": "active_on_source_readback_2026-05-16",
                "registrationDeadline": "2026-05-25",
                "submissionDeadline": "2026-06-14",
                "rewardAnnouncement": "2026-06-17",
            },
            "importance": "high",
            "whyNow": "Arbitrum rewards production-grade EVM/L2 apps; 0guard can enter as Stylus/Solidity preflight middleware.",
            "0guardBuild": "Package native preflight around Arbitrum One/Nova/Sepolia, Orbit/Stylus actions, and x402 prepared payments.",
            "sources": [
                "https://www.hackquest.io/hackathons/Arbitrum-Open-House-London-Online-Buildathon",
                "https://openhouse.arbitrum.io/",
                "https://docs.arbitrum.io/build-decentralized-apps/reference/node-providers",
            ],
        },
        {
            "rank": 4,
            "id": "metamask_agent_wallet_security",
            "name": "MetaMask agent-wallet security lane",
            "timing": {
                "status": "superseded_by_active_metamask_1shot_cookoff",
                "nextPublicSubmissionWindow": "ETHGlobal New York remains follow-on distribution",
            },
            "importance": "high",
            "whyNow": "MetaMask Smart Accounts Kit, Snaps, and Connect give 0guard a clean pre-signer integration path for agentic wallets.",
            "0guardBuild": "Gate eth_sendTransaction, signTypedData, permission requests, and delegated execution with /api/native-preflight.",
            "sources": [
                "https://docs.metamask.io/metamask-connect/",
                "https://docs.metamask.io/snaps/features/transaction-insights/",
                "https://docs.metamask.io/smart-accounts-kit/",
            ],
        },
        {
            "rank": 5,
            "id": "ethglobal_new_york_2026",
            "name": "ETHGlobal New York 2026",
            "timing": {
                "status": "upcoming",
                "eventDates": "2026-06-12 to 2026-06-14",
            },
            "importance": "high",
            "whyNow": "Best near-term venue for wallet/agent middleware, proof receipts, and x402 safety integrations.",
            "0guardBuild": "Ship SDK examples for AgentKit, Turnkey, Safe, and EVM apps calling /api/native-preflight before sign.",
            "sources": ["https://ethglobal.com/"],
        },
        {
            "rank": 6,
            "id": "ethglobal_lisbon_2026",
            "name": "ETHGlobal Lisbon 2026",
            "timing": {
                "status": "upcoming",
                "eventDates": "2026-07-24 to 2026-07-26",
            },
            "importance": "medium_high",
            "whyNow": "Good follow-on for hardening the same middleware into a polished developer product.",
            "0guardBuild": "Turn native preflight into a reusable package with examples, docs, and public proof fixtures.",
            "sources": ["https://ethglobal.com/"],
        },
        {
            "rank": 7,
            "id": "arbitrum_open_house_singapore",
            "name": "Arbitrum Open House Singapore",
            "timing": {
                "status": "coming_2026",
                "eventDates": "not_yet_published_on_source_readback_2026-05-15",
            },
            "importance": "medium",
            "whyNow": "Useful later if the London/ETHGlobal slices prove there is ecosystem demand.",
            "0guardBuild": "Carry forward the same no-bridge EVM safety middleware with better telemetry and source adapters.",
            "sources": ["https://openhouse.arbitrum.io/"],
        },
    ]
    return {
        "schema": HACKATHON_STRATEGY_SCHEMA,
        "generatedAt": _now(),
        "sourceCheckedAt": "2026-05-16",
        "thesis": {
            "0gFirst": "0G remains the receipt/provenance layer and the current judging anchor.",
            "portableProduct": "Native preflight is the reusable product: one call before any agent reaches a signer.",
            "doNotForce": "Do not bridge or move assets just to claim interoperability; integrate through native read-only proof, simulation, and pre-signing controls.",
        },
        "opportunityCount": len(opportunities),
        "opportunities": opportunities,
        "nextEngineeringSequence": [
            "Keep the 0G APAC submission and public proof surfaces green through review.",
            "Build SDK examples around /api/native-preflight for Arbitrum/EVM and Ika/dWallet use.",
            "Add a rights-aware reputation adapter before any stronger alerting claims.",
            "Only add live 0G Storage or Compute after operator credentials and rollback notes are reviewed.",
        ],
        "safety": _safety(),
    }


def _coerce_intent(body: dict[str, Any]) -> dict[str, Any]:
    raw = body.get("intent") if isinstance(body.get("intent"), dict) else {}
    return {**raw}


def _surface(body: dict[str, Any], intent: dict[str, Any]) -> str:
    return _norm_id(
        body.get("surface")
        or body.get("targetSurface")
        or body.get("externalTarget")
        or intent.get("surface")
        or intent.get("app")
        or "evm"
    )


def _external_target(*, body: dict[str, Any], surface: str) -> str:
    explicit = _norm_id(body.get("externalTarget") or body.get("target_id") or body.get("targetId"))
    if explicit in _EXTERNAL_SURFACES:
        return explicit
    if surface in _EXTERNAL_SURFACES:
        return surface
    return ""


def _should_run_ika(*, surface: str, source_project: str, operation: str) -> bool:
    return surface in _IKA_SURFACES or source_project in _IKA_SURFACES or "dwallet" in operation


def _should_run_reputation(body: dict[str, Any]) -> bool:
    return any(
        key in body and body.get(key)
        for key in (
            "url",
            "domain",
            "website",
            "address",
            "target",
            "to",
            "labels",
            "tags",
            "sourceEvidence",
            "evidence",
        )
    )


def _component(component_id: str, decision: str, data: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": component_id,
        "decision": decision,
        "schema": data.get("schema"),
        "receiptHash": _extract_receipt(data),
        "data": data,
    }


def _component_receipts(components: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {
            "id": component["id"],
            "decision": component["decision"],
            "schema": str(component.get("schema") or ""),
            "receiptHash": str(component.get("receiptHash") or ""),
        }
        for component in components
    ]


def _extract_receipt(data: dict[str, Any]) -> str:
    receipt = data.get("receipt")
    if isinstance(receipt, dict) and receipt.get("hash"):
        return str(receipt["hash"])
    if data.get("receipt_hash"):
        return str(data["receipt_hash"])
    if data.get("receiptHash"):
        return str(data["receiptHash"])
    return _hash_json(data)


def _rollup(decisions: list[str]) -> str:
    normalized = {_norm(decision) for decision in decisions}
    if "deny" in normalized:
        return "deny"
    if "review" in normalized:
        return "review"
    return "allow"


def _recommended_next_step(decision: str) -> str:
    if decision == "deny":
        return "Block the action before any signer, payment rail, wallet, exchange, or Telegram send is reached."
    if decision == "review":
        return "Keep this as a preview receipt and collect source/config evidence before operator approval."
    return "Read-only context is acceptable; live actions still require a separate explicit operator path."


def _requires_signature(operation: str) -> bool:
    return any(
        token in operation
        for token in ("sign", "send", "swap", "bridge", "sweep", "execute", "approve", "transfer", "pay")
    )


def _policy_action(operation: str) -> str:
    if operation.startswith(("read", "list", "get", "status", "network")):
        return "read_balance"
    if operation.startswith(("preview", "simulate", "dry_run")):
        return "preview"
    return operation


def _chain_id(chain: str) -> int:
    if chain.startswith("eip155:"):
        try:
            return int(chain.split(":", 1)[1])
        except ValueError:
            return 0
    return 0


def _float_value(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _hash_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _norm_id(value: Any) -> str:
    return _norm(value).replace("-", "_")


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}
    return bool(value)


def _safety() -> dict[str, bool]:
    return {
        "readOnly": True,
        "networkCalls": False,
        "walletSignaturesRequested": False,
        "transactionSigningEnabled": False,
        "broadcastingEnabled": False,
        "bridgingEnabled": False,
        "x402SettlementEnabled": False,
        "exchangeActionsEnabled": False,
        "telegramSendsEnabled": False,
        "moneyMovementEnabled": False,
        "rawPayloadsReturned": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
