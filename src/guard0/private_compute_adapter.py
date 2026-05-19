"""Disabled-by-default 0G Private Computer inference adapter.

The adapter prepares the exact server-side smoke request shape and prompt-safety
checks, but it never executes paid inference from this workbench route. A future
worker can consume this contract after Router funding, API-key storage, and a
separate operator spend confirmation.
"""

from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime, timezone
from typing import Any

from guard0.peer_protection import CHAT_COMPLETIONS_URL, MODEL_ID, ROUTER_BASE_URL

PRIVATE_COMPUTE_SMOKE_PREVIEW_SCHEMA = "0guard.0g_private_compute_smoke_preview.v1"

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
    blockers = []
    if not scrub["safeForInference"]:
        blockers.append("prompt_safety_violation")
    if not key_ready:
        blockers.append("router_api_key_missing")
    if not paid_allowed:
        blockers.append("paid_inference_env_gate_disabled")
    if budget <= 0:
        blockers.append("positive_budget_required")

    status = "ready_for_operator_paid_smoke" if not blockers else "blocked_before_paid_inference"
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
            "apiKeyConfigured": key_ready,
            "apiKeyReturned": False,
            "budgetUsd": budget,
            "paidInferenceAllowedByEnv": paid_allowed,
            "networkCalls": False,
        },
        "promptScrub": scrub,
        "sampleRequest": _sample_request(scrub),
        "operatorNext": [
            "Store the Router key server-side only after funding a tiny reviewed Router budget.",
            "Set ZG_ALLOW_PAID_INFERENCE=1 and a positive ZG_0G_INFERENCE_BUDGET_USD only for a controlled smoke.",
            "Run the first paid smoke from a server-side worker, then store only receipt metadata and the advisory explanation.",
        ],
        "safety": _safety(
            paid_inference_enabled=key_ready and paid_allowed and budget > 0,
            prompt_safe=scrub["safeForInference"],
        ),
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
    return bool(
        os.getenv("ZG_0G_ROUTER_API_KEY")
        or os.getenv("ZG_0G_PC_API_KEY")
        or os.getenv("ZERO_G_API_KEY")
    )


def _budget_usd() -> float:
    try:
        return float(os.getenv("ZG_0G_INFERENCE_BUDGET_USD", "0") or 0)
    except ValueError:
        return 0.0


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


def _truthy(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _hash_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
