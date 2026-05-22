"""Disabled-by-default 0G Private Computer inference adapter.

The adapter prepares the exact server-side smoke request shape and prompt-safety
checks, but it never executes paid inference from this workbench route. A future
worker can consume this contract after Router funding, API-key storage, and a
separate operator spend confirmation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guard0.peer_protection import (
    API_REFERENCE_URL,
    CHAT_COMPLETIONS_URL,
    MODEL_ID,
    PAYMENT_LAYER_MAINNET,
    PAYMENT_LAYER_TESTNET,
    ROUTER_AUTH_URL,
    ROUTER_BASE_URL,
    ROUTER_BILLING_URL,
    ROUTER_MODELS_DOC_URL,
    ROUTER_MODELS_URL,
)

PRIVATE_COMPUTE_SMOKE_PREVIEW_SCHEMA = "0guard.0g_private_compute_smoke_preview.v1"
PRIVATE_COMPUTE_PAID_SMOKE_PROOF_SCHEMA = "0guard.0g_private_compute_paid_smoke_proof.v1"
PRIVATE_COMPUTE_PAID_SMOKE_PROOF_VERIFICATION_SCHEMA = (
    "0guard.0g_private_compute_paid_smoke_proof_verification.v1"
)
PRIVATE_COMPUTE_PAID_SMOKE_OPERATOR_PACKET_SCHEMA = (
    "0guard.0g_private_compute_paid_smoke_operator_proof_packet.v1"
)
PRIVATE_COMPUTE_ROUTER_CONTRACT_SCHEMA = "0guard.0g_private_compute_router_contract.v1"
PRIVATE_COMPUTE_FIRST_SMOKE_MAX_COST_USD = 0.25
ROUTER_API_KEY_ENV_NAMES = ("ZG_0G_ROUTER_API_KEY", "ZG_0G_PC_API_KEY", "ZERO_G_API_KEY")
PAID_INFERENCE_GATE_ENV = "ZG_ALLOW_PAID_INFERENCE"
INFERENCE_BUDGET_ENV = "ZG_0G_INFERENCE_BUDGET_USD"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PRIVATE_COMPUTE_PAID_SMOKE_PROOF_PATH = (
    REPO_ROOT / "docs" / "hackathon-0g" / "0g-private-compute-paid-smoke-proof.json"
)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"\b0x[a-fA-F0-9]{64}\b")),
    ("mnemonic_phrase", re.compile(r"\b(?:[a-z]{3,12}\s+){11,23}[a-z]{3,12}\b", re.I)),
    ("api_key", re.compile(r"\b(?:sk|app-sk|zg|og)[-_][A-Za-z0-9_\-]{16,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("payment_header", re.compile(r"\bX-PAYMENT\b|\bpayment\s*header\b", re.I)),
)


def build_private_compute_smoke_preview(
    body: dict[str, Any] | None = None,
    *,
    api_key_configured: bool | None = None,
    paid_inference_allowed: bool | None = None,
    budget_usd: float | None = None,
    paid_smoke_proof_path: str | Path | None = DEFAULT_PRIVATE_COMPUTE_PAID_SMOKE_PROOF_PATH,
) -> dict[str, Any]:
    """Return a no-inference 0G Private Computer smoke contract."""

    request_body = body or {}
    prompt = str(request_body.get("prompt") or _default_prompt())
    scrub = scrub_private_compute_prompt(prompt)
    key_ready = _api_key_configured() if api_key_configured is None else api_key_configured
    paid_allowed = (
        _truthy(os.getenv("ZG_ALLOW_PAID_INFERENCE"))
        if paid_inference_allowed is None
        else paid_inference_allowed
    )
    budget = _budget_usd() if budget_usd is None else float(budget_usd)
    blockers = _private_compute_smoke_blockers(
        prompt_safe=scrub["safeForInference"],
        api_key_configured=key_ready,
        paid_inference_allowed=paid_allowed,
        budget_usd=budget,
    )

    paid_smoke_proof = build_private_compute_paid_smoke_proof_status(paid_smoke_proof_path)
    paid_smoke_verified = paid_smoke_proof.get("verified") is True
    operator_packet = paid_smoke_proof.get("operatorProofPacket") or _paid_smoke_operator_packet(
        paid_smoke_proof_path
    )
    status = (
        "paid_smoke_complete"
        if paid_smoke_verified
        else "ready_for_operator_paid_smoke"
        if not blockers
        else "blocked_before_paid_inference"
    )
    return {
        "schema": PRIVATE_COMPUTE_SMOKE_PREVIEW_SCHEMA,
        "generatedAt": _now(),
        "mode": "adapter_contract_no_inference_call",
        "status": status,
        "blockers": blockers,
        "model": {
            "id": MODEL_ID,
            "servingSurface": "0G Private Computer",
            "authority": "advisory_explanation_only",
        },
        "router": {
            "baseUrl": ROUTER_BASE_URL,
            "chatCompletionsUrl": CHAT_COMPLETIONS_URL,
            "modelsUrl": ROUTER_MODELS_URL,
            "openAiCompatible": True,
            "apiKeyConfigured": key_ready,
            "apiKeyReturned": False,
            "apiKeyEnvNames": list(ROUTER_API_KEY_ENV_NAMES),
            "paidInferenceGateEnv": PAID_INFERENCE_GATE_ENV,
            "budgetEnv": INFERENCE_BUDGET_ENV,
            "budgetUsd": budget,
            "paidInferenceAllowedByEnv": paid_allowed,
            "networkCalls": False,
        },
        "routerContract": _router_contract(
            api_key_configured=key_ready,
            paid_inference_allowed=paid_allowed,
            budget_usd=budget,
        ),
        "promptScrub": scrub,
        "sampleRequest": _sample_request(scrub),
        "paidSmokeProof": paid_smoke_proof,
        "operatorProofPacket": operator_packet,
        "recordProofCommandTemplate": operator_packet["recordProofCommandTemplate"],
        "operatorNext": [
            "Store the Router key server-side only after funding a tiny reviewed Router budget.",
            "Set ZG_ALLOW_PAID_INFERENCE=1 and a positive ZG_0G_INFERENCE_BUDGET_USD only for a controlled smoke.",
            "Run the first paid smoke from a server-side worker, then record only prompt/request/response hashes and receipt metadata.",
            "Use scripts/record_0g_private_compute_paid_smoke.py to create docs/hackathon-0g/0g-private-compute-paid-smoke-proof.json.",
        ],
        "safety": _safety(
            paid_inference_enabled=key_ready and paid_allowed and budget > 0,
            prompt_safe=scrub["safeForInference"],
        ),
    }


def build_private_compute_paid_smoke_proof_status(
    proof_path: str | Path | None = DEFAULT_PRIVATE_COMPUTE_PAID_SMOKE_PROOF_PATH,
) -> dict[str, Any]:
    """Return verification status for an externally performed paid smoke proof."""

    return verify_private_compute_paid_smoke_proof(
        _load_paid_smoke_proof(proof_path) if proof_path else None,
        proof_path=proof_path,
    )


def verify_private_compute_paid_smoke_proof(
    proof: dict[str, Any] | None,
    *,
    proof_path: str | Path | None = None,
) -> dict[str, Any]:
    """Validate a public-safe receipt for one externally performed paid smoke.

    The live call must happen outside this workbench in a server-side
    operator-controlled environment. This verifier accepts only hashes,
    bounded-cost metadata, and explicit no-secret/no-raw-payload flags.
    """

    if not isinstance(proof, dict):
        return _paid_smoke_proof_status(
            "missing",
            "paid_smoke_proof_file_missing",
            proof_path=proof_path,
        )

    budget_usd = _parse_nonnegative_float(proof.get("budgetUsd"))
    cost_usd = _parse_positive_float(proof.get("costUsd"))
    max_cost = PRIVATE_COMPUTE_FIRST_SMOKE_MAX_COST_USD
    checks = {
        "schema": proof.get("schema") == PRIVATE_COMPUTE_PAID_SMOKE_PROOF_SCHEMA,
        "model": proof.get("model") == MODEL_ID,
        "routerBaseUrl": proof.get("routerBaseUrl") == ROUTER_BASE_URL,
        "chatCompletionsUrl": proof.get("chatCompletionsUrl") == CHAT_COMPLETIONS_URL,
        "promptHash": _valid_sha256(proof.get("promptHash")),
        "requestHash": _valid_sha256(proof.get("requestHash")),
        "responseHash": _valid_sha256(proof.get("responseHash")),
        "routerReceiptHash": _valid_sha256(proof.get("routerReceiptHash")),
        "budgetUsdPositive": budget_usd is not None and budget_usd > 0,
        "costUsdPositive": cost_usd is not None and cost_usd > 0,
        "costWithinBudget": (
            budget_usd is not None
            and cost_usd is not None
            and cost_usd <= budget_usd
        ),
        "costWithinFirstSmokeCap": cost_usd is not None and cost_usd <= max_cost,
        "operatorReviewedBudget": proof.get("operatorReviewedBudget") is True,
        "promptSafeForInference": proof.get("promptSafeForInference") is True,
        "paidInferencePerformedExternally": (
            proof.get("paidInferencePerformedExternally") is True
        ),
        "rawPromptStored": proof.get("rawPromptStored") is False,
        "rawPromptReturned": proof.get("rawPromptReturned") is False,
        "rawResponseStored": proof.get("rawResponseStored") is False,
        "rawResponseReturned": proof.get("rawResponseReturned") is False,
        "apiKeyReturned": proof.get("apiKeyReturned") is False,
        "privateKeysReturned": proof.get("privateKeysReturned") is False,
        "paymentHeadersStored": proof.get("paymentHeadersStored") is False,
        "transactionSigningByZeroGuard": proof.get("transactionSigningByZeroGuard") is False,
        "transactionBroadcastingByZeroGuard": (
            proof.get("transactionBroadcastingByZeroGuard") is False
        ),
        "moneyMovementByZeroGuard": proof.get("moneyMovementByZeroGuard") is False,
    }
    verified = all(checks.values())
    return {
        "schema": PRIVATE_COMPUTE_PAID_SMOKE_PROOF_VERIFICATION_SCHEMA,
        "generatedAt": _now(),
        "status": "verified" if verified else "review",
        "verified": verified,
        "proofPresent": True,
        "proofPath": _relative_repo_path(Path(proof_path)) if proof_path else proof.get("proofPath"),
        "model": proof.get("model"),
        "promptHash": proof.get("promptHash"),
        "requestHash": proof.get("requestHash"),
        "responseHash": proof.get("responseHash"),
        "routerReceiptHash": proof.get("routerReceiptHash"),
        "budgetUsd": budget_usd,
        "costUsd": cost_usd,
        "maxFirstSmokeCostUsd": max_cost,
        "routerContract": _router_contract(
            api_key_configured=_api_key_configured(),
            paid_inference_allowed=_truthy(os.getenv(PAID_INFERENCE_GATE_ENV)),
            budget_usd=_budget_usd(),
        ),
        "paidInferencePerformedExternally": (
            proof.get("paidInferencePerformedExternally") is True
        ),
        "checks": checks,
        "safety": {
            **_safety(
                paid_inference_enabled=False,
                prompt_safe=proof.get("promptSafeForInference") is True,
            ),
            "proofVerificationOnly": True,
            "paidInferenceByZeroGuard": False,
            "paidInferencePerformedExternally": (
                proof.get("paidInferencePerformedExternally") is True
            ),
            "rawPromptStored": False,
            "rawPromptReturned": False,
            "rawResponseStored": False,
            "rawResponseReturned": False,
            "paymentHeadersStored": False,
        },
    }


def scrub_private_compute_prompt(prompt: str) -> dict[str, Any]:
    """Hash and redact a prompt preview without returning secrets."""

    text = str(prompt or "")
    findings = [
        {"id": pattern_id, "matched": True}
        for pattern_id, pattern in SECRET_PATTERNS
        if pattern.search(text)
    ]
    redacted = text
    for _, pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    redacted = re.sub(r"\b0x[a-fA-F0-9]{40}\b", "[address]", redacted)
    preview = redacted[:220]
    return {
        "safeForInference": not findings,
        "promptHash": _hash_text(text) if text else "",
        "promptLength": len(text),
        "redactedPreview": preview,
        "rawPromptReturned": False,
        "findings": findings,
        "policy": [
            "reject private keys, mnemonics, API keys, JWTs, and payment headers",
            "redact addresses from previews",
            "send deterministic verdict packets, not private chats or raw paid feeds",
        ],
    }


def _sample_request(scrub: dict[str, Any]) -> dict[str, Any]:
    return {
        "method": "POST",
        "openAiCompatible": True,
        "url": CHAT_COMPLETIONS_URL,
        "headers": {
            "Authorization": "Bearer ${ZG_0G_ROUTER_API_KEY}",
            "Content-Type": "application/json",
        },
        "body": {
            "model": MODEL_ID,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You explain deterministic ZeroGuard risk packets. "
                        "You cannot approve transactions, move funds, or override policy."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        "Summarize the redacted verdict packet whose prompt hash is "
                        f"{scrub['promptHash'][:16]}."
                    ),
                },
            ],
            "stream": False,
            "max_tokens": 512,
            "chat_template_kwargs": {"enable_thinking": False},
        },
        "inferenceExecuted": False,
        "paidInferenceCallPrepared": True,
    }


def _default_prompt() -> str:
    return (
        "ZeroGuard verdict packet: decision=review; reasons=reputation source pending, "
        "x402 dry-run only, storage node still syncing; summarize for an operator."
    )


def _api_key_configured() -> bool:
    return any(bool(os.getenv(env_name)) for env_name in ROUTER_API_KEY_ENV_NAMES)


def _budget_usd() -> float:
    try:
        return float(os.getenv(INFERENCE_BUDGET_ENV, "0") or 0)
    except ValueError:
        return 0.0


def _private_compute_smoke_blockers(
    *,
    prompt_safe: bool,
    api_key_configured: bool,
    paid_inference_allowed: bool,
    budget_usd: float,
) -> list[str]:
    blockers = []
    if not prompt_safe:
        blockers.append("prompt_safety_violation")
    if not api_key_configured:
        blockers.append("router_api_key_missing")
    if not paid_inference_allowed:
        blockers.append("paid_inference_env_gate_disabled")
    if budget_usd <= 0:
        blockers.append("positive_budget_required")
    return blockers


def _safety(*, paid_inference_enabled: bool, prompt_safe: bool) -> dict[str, bool]:
    return {
        "readOnly": True,
        "networkCalls": False,
        "promptSafeForInference": prompt_safe,
        "promptExecutionEnabled": False,
        "paidInferenceEnabled": paid_inference_enabled,
        "inferenceExecuted": False,
        "apiKeyReturned": False,
        "privateKeysReturned": False,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "moneyMovementEnabled": False,
        "telegramSendsEnabled": False,
        "paymentSettlementEnabled": False,
    }


def _load_paid_smoke_proof(path: str | Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    proof_path = Path(path)
    if not proof_path.is_absolute():
        proof_path = REPO_ROOT / proof_path
    try:
        payload = json.loads(proof_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    if isinstance(payload, dict):
        return {**payload, "proofPath": _relative_repo_path(proof_path)}
    return None


def _paid_smoke_proof_status(
    status: str,
    reason: str,
    *,
    proof_path: str | Path | None = None,
) -> dict[str, Any]:
    operator_packet = _paid_smoke_operator_packet(proof_path)
    api_key_configured = _api_key_configured()
    paid_inference_allowed = _truthy(os.getenv("ZG_ALLOW_PAID_INFERENCE"))
    budget_usd = _budget_usd()
    preflight_blockers = _private_compute_smoke_blockers(
        prompt_safe=True,
        api_key_configured=api_key_configured,
        paid_inference_allowed=paid_inference_allowed,
        budget_usd=budget_usd,
    )
    return {
        "schema": PRIVATE_COMPUTE_PAID_SMOKE_PROOF_VERIFICATION_SCHEMA,
        "generatedAt": _now(),
        "status": status,
        "verified": False,
        "proofPresent": False,
        "proofPath": _relative_repo_path(Path(proof_path)) if proof_path else "",
        "reason": reason,
        "blockers": [reason, *preflight_blockers],
        "proofBlockers": [reason],
        "preflightBlockers": preflight_blockers,
        "router": {
            "baseUrl": ROUTER_BASE_URL,
            "chatCompletionsUrl": CHAT_COMPLETIONS_URL,
            "modelsUrl": ROUTER_MODELS_URL,
            "openAiCompatible": True,
            "apiKeyConfigured": api_key_configured,
            "apiKeyReturned": False,
            "apiKeyEnvNames": list(ROUTER_API_KEY_ENV_NAMES),
            "paidInferenceGateEnv": PAID_INFERENCE_GATE_ENV,
            "budgetEnv": INFERENCE_BUDGET_ENV,
            "paidInferenceAllowedByEnv": paid_inference_allowed,
            "budgetUsd": budget_usd,
            "networkCalls": False,
        },
        "routerContract": _router_contract(
            api_key_configured=api_key_configured,
            paid_inference_allowed=paid_inference_allowed,
            budget_usd=budget_usd,
        ),
        "recordProofCommandTemplate": operator_packet["recordProofCommandTemplate"],
        "operatorProofPacket": operator_packet,
        "safety": {
            **_safety(paid_inference_enabled=False, prompt_safe=True),
            "proofVerificationOnly": True,
            "paidInferenceByZeroGuard": False,
            "paidInferencePerformedExternally": False,
            "rawPromptStored": False,
            "rawPromptReturned": False,
            "rawResponseStored": False,
            "rawResponseReturned": False,
            "paymentHeadersStored": False,
        },
    }


def _paid_smoke_operator_packet(proof_path: str | Path | None) -> dict[str, Any]:
    proof_file = (
        _relative_repo_path(Path(proof_path))
        if proof_path
        else "docs/hackathon-0g/0g-private-compute-paid-smoke-proof.json"
    )
    command = " ".join(
        [
            "PYTHONPATH=src .venv/bin/python",
            "scripts/record_0g_private_compute_paid_smoke.py",
            "--prompt-hash <sha256-of-approved-scrubbed-prompt>",
            "--request-hash <sha256-of-router-request-body>",
            "--response-hash <sha256-of-model-response-body>",
            "--router-receipt-hash <sha256-of-router-receipt-or-billing-metadata>",
            f"--budget-usd {PRIVATE_COMPUTE_FIRST_SMOKE_MAX_COST_USD}",
            "--cost-usd <observed-smoke-cost-usd>",
            f"--out {proof_file}",
            "--operator-reviewed-budget",
            "--prompt-safe-for-inference",
            "--paid-inference-performed-externally",
            "--raw-prompt-not-stored",
            "--raw-response-not-stored",
            "--api-key-not-returned",
        ]
    )
    return {
        "schema": PRIVATE_COMPUTE_PAID_SMOKE_OPERATOR_PACKET_SCHEMA,
        "status": "ready_for_external_paid_smoke_proof",
        "proofPath": proof_file,
        "recordProofCommandTemplate": command,
        "model": MODEL_ID,
        "routerBaseUrl": ROUTER_BASE_URL,
        "chatCompletionsUrl": CHAT_COMPLETIONS_URL,
        "routerContract": _router_contract(
            api_key_configured=False,
            paid_inference_allowed=False,
            budget_usd=0.0,
        ),
        "maxFirstSmokeCostUsd": PRIVATE_COMPUTE_FIRST_SMOKE_MAX_COST_USD,
        "promptHashRequired": True,
        "requestHashRequired": True,
        "responseHashRequired": True,
        "routerReceiptHashRequired": True,
        "operatorReviewedBudgetRequired": True,
        "promptSafeForInferenceRequired": True,
        "paidInferencePerformedExternallyRequired": True,
        "rawPromptRequired": False,
        "rawResponseRequired": False,
        "apiKeyRequiredByRecorder": False,
        "apiKeyStoredInProof": False,
        "paidInferenceByZeroGuardEnabled": False,
        "networkCallsByRecorder": False,
        "transactionSigningByZeroGuardEnabled": False,
        "transactionBroadcastingByZeroGuardEnabled": False,
        "moneyMovementByZeroGuardEnabled": False,
    }


def _router_contract(
    *,
    api_key_configured: bool,
    paid_inference_allowed: bool,
    budget_usd: float,
) -> dict[str, Any]:
    return {
        "schema": PRIVATE_COMPUTE_ROUTER_CONTRACT_SCHEMA,
        "source": "official_0g_router_docs_and_live_catalog_contract",
        "openAiCompatible": True,
        "httpMethod": "POST",
        "baseUrl": ROUTER_BASE_URL,
        "chatCompletionsPath": "/chat/completions",
        "chatCompletionsUrl": CHAT_COMPLETIONS_URL,
        "modelsPath": "/models",
        "modelsUrl": ROUTER_MODELS_URL,
        "auth": {
            "header": "Authorization",
            "scheme": "Bearer",
            "headerTemplate": "Authorization: Bearer ${ZG_0G_ROUTER_API_KEY}",
            "apiKeyEnvNames": list(ROUTER_API_KEY_ENV_NAMES),
            "apiKeyConfigured": api_key_configured,
            "apiKeyReturned": False,
            "browserUseAllowed": False,
            "serverSideOnly": True,
            "keyCanSpendDeposited0g": True,
        },
        "budgetGate": {
            "paidInferenceGateEnv": PAID_INFERENCE_GATE_ENV,
            "paidInferenceAllowedByEnv": paid_inference_allowed,
            "budgetEnv": INFERENCE_BUDGET_ENV,
            "budgetUsd": budget_usd,
            "requiresPositiveBudget": True,
            "requiresOperatorReviewedBudget": True,
            "maxFirstSmokeCostUsd": PRIVATE_COMPUTE_FIRST_SMOKE_MAX_COST_USD,
        },
        "modelRequest": {
            "model": MODEL_ID,
            "catalogShouldBeCheckedBeforePaidSmoke": True,
            "disableThinkingParameter": {
                "chat_template_kwargs": {"enable_thinking": False},
            },
            "stream": False,
            "maxTokens": 512,
        },
        "billing": {
            "unit": "neuron_per_token",
            "routerTraceField": "x_0g_trace.billing.total_cost",
            "accountBalancePath": "/account/balance",
            "usageStatsPath": "/account/usage/stats",
            "usageHistoryPath": "/account/usage/history",
            "paymentLayerContracts": {
                "mainnet": PAYMENT_LAYER_MAINNET,
                "testnet": PAYMENT_LAYER_TESTNET,
            },
        },
        "proofRequirements": {
            "paidInferencePerformedExternally": True,
            "recordPromptHash": True,
            "recordRequestHash": True,
            "recordResponseHash": True,
            "recordRouterReceiptHash": True,
            "recordCostUsd": True,
            "recordRawPrompt": False,
            "recordRawResponse": False,
            "recordApiKey": False,
            "recordPaymentHeaders": False,
        },
        "docs": {
            "quickstartUrl": API_REFERENCE_URL,
            "authUrl": ROUTER_AUTH_URL,
            "modelsUrl": ROUTER_MODELS_DOC_URL,
            "billingUrl": ROUTER_BILLING_URL,
        },
        "safety": {
            "readOnly": True,
            "networkCalls": False,
            "inferenceExecuted": False,
            "apiKeyReturned": False,
            "privateKeysReturned": False,
            "transactionSigningEnabled": False,
            "transactionBroadcastingEnabled": False,
            "moneyMovementEnabled": False,
        },
    }


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[a-fA-F0-9]{64}", value.strip()))


def _parse_positive_float(value: Any) -> float | None:
    parsed = _parse_nonnegative_float(value)
    return parsed if parsed is not None and parsed > 0 else None


def _parse_nonnegative_float(value: Any) -> float | None:
    try:
        parsed = float(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _relative_repo_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _hash_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
