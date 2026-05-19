"""Dry-run x402 payment contract for ZeroGuard data products.

This module models the HTTP-402 shape for a paid route without verifying,
settling, forwarding, or storing payment headers. It gives the MetaMask/1Shot
hackathon path a real contract to build against while keeping live settlement
explicitly disabled.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

X402_WALLET_PREFLIGHT_DRY_RUN_SCHEMA = "0guard.x402_wallet_preflight_dry_run.v1"
X402_FIXTURE_PAYMENT_HEADER = "fixture-paid-zeroguard-wallet-preflight-v1"


def build_x402_wallet_preflight_dry_run(
    *,
    payment_header: str = "",
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a no-settlement x402 contract response for wallet preflight."""

    request_body = body or {}
    header = str(payment_header or request_body.get("paymentFixture") or "").strip()
    if not header:
        status = "payment_required_dry_run"
        http_status = 402
        accepted = False
        problem = None
    elif header == X402_FIXTURE_PAYMENT_HEADER:
        status = "payment_fixture_accepted_no_settlement"
        http_status = 200
        accepted = True
        problem = None
    else:
        status = "malformed_payment_fixture"
        http_status = 400
        accepted = False
        problem = "Only the documented fixture header is accepted in dry-run mode."

    payload = {
        "schema": X402_WALLET_PREFLIGHT_DRY_RUN_SCHEMA,
        "generatedAt": _now(),
        "mode": "x402_dry_run_no_settlement",
        "status": status,
        "httpStatus": http_status,
        "resource": {
            "productId": "wallet_preflight_verdict",
            "route": "/x402/v1/wallet-preflight",
            "apiRoute": "/api/x402/dry-run/wallet-preflight",
            "method": "POST",
            "responseSchema": "0guard.wallet_preflight_verdict.v1",
        },
        "paymentRequirement": _payment_requirement(),
        "paymentReadback": {
            "paymentHeaderPresent": bool(header),
            "paymentHeaderAccepted": accepted,
            "paymentHeaderHash": _hash_text(header) if header else "",
            "paymentHeaderReturned": False,
            "facilitatorCalled": False,
            "settlementAttempted": False,
            "settlementEnabled": False,
            "problem": problem,
        },
        "dryRunFixture": {
            "headerName": "X-PAYMENT",
            "acceptedValue": X402_FIXTURE_PAYMENT_HEADER,
            "acceptedValueIsNotARealPayment": True,
        },
        "productResponse": _product_response(request_body) if accepted else None,
        "rightsPolicy": _rights_policy(),
        "operatorNext": [
            "Wire this exact contract to a testnet facilitator only after spend limits and refund wording are fixed.",
            "Keep paid responses to derived verdicts, source ids, hashes, and receipt metadata.",
            "Do not retain raw payment headers or treat payment as permission to expose upstream feeds.",
        ],
        "safety": _safety(),
    }
    payload["receipt"] = {
        "hash": _hash_json(
            {
                "schema": payload["schema"],
                "status": payload["status"],
                "resource": payload["resource"],
                "paymentRequirement": payload["paymentRequirement"],
                "paymentHeaderHash": payload["paymentReadback"]["paymentHeaderHash"],
                "rightsPolicy": payload["rightsPolicy"],
            }
        ),
        "algorithm": "sha256_canonical_json",
        "liveAnchorPerformed": False,
        "liveUploadPerformed": False,
    }
    return payload


def _payment_requirement() -> dict[str, Any]:
    return {
        "x402Version": 1,
        "network": "base-sepolia",
        "networkCaip2": "eip155:84532",
        "asset": "USDC",
        "assetCaip19": "eip155:84532/erc20:0x0000000000000000000000000000000000000000",
        "maxAmountRequired": "10000",
        "decimals": 6,
        "displayPrice": "0.01 USDC",
        "payTo": "operator_pay_to_required_before_live_settlement",
        "payToConfigured": False,
        "resource": "https://zeroguard.local/x402/v1/wallet-preflight",
        "description": "ZeroGuard wallet preflight verdict packet",
        "mimeType": "application/json",
        "settlementMode": "dry_run_fixture_only",
        "facilitator": "not_configured",
    }


def _product_response(body: dict[str, Any]) -> dict[str, Any]:
    target = str(body.get("target") or body.get("address") or body.get("url") or "").strip()
    return {
        "schema": "0guard.wallet_preflight_verdict.v1",
        "mode": "fixture_paid_response_no_settlement",
        "targetProvided": bool(target),
        "targetHash": _hash_text(target) if target else "",
        "verdict": {
            "decision": "review",
            "severity": "medium",
            "reasons": [
                "Dry-run x402 fixture accepted.",
                "No live facilitator settlement was performed.",
                "Production verdicts must be generated by deterministic ZeroGuard checks.",
            ],
        },
        "sourceIds": ["zeroguard_dry_run_contract"],
        "rawPayloadResaleAllowed": False,
        "paymentIsNotPermission": True,
    }


def _rights_policy() -> dict[str, bool]:
    return {
        "rawPayloadsReturned": False,
        "rawPayloadResaleAllowed": False,
        "paymentHeadersStored": False,
        "paymentHeadersReturned": False,
        "derivedAnalysisOnly": True,
        "paymentIsNotPermission": True,
    }


def _safety() -> dict[str, bool]:
    return {
        "readOnly": True,
        "networkCalls": False,
        "facilitatorCalled": False,
        "x402SettlementEnabled": False,
        "paymentSettlementEnabled": False,
        "paymentHeaderStored": False,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "moneyMovementEnabled": False,
        "telegramSendsEnabled": False,
        "socialPostingEnabled": False,
    }


def _hash_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
