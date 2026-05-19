"""Tests for disabled-by-default 0G Private Computer smoke previews."""

import json

from guard0.private_compute_adapter import (
    build_private_compute_smoke_preview,
    scrub_private_compute_prompt,
)


def test_private_compute_smoke_preview_blocks_until_gates_are_present():
    preview = build_private_compute_smoke_preview(
        api_key_configured=False,
        paid_inference_allowed=False,
        budget_usd=0,
    )

    assert preview["schema"] == "0guard.0g_private_compute_smoke_preview.v1"
    assert preview["status"] == "blocked_before_paid_inference"
    assert "router_api_key_missing" in preview["blockers"]
    assert "paid_inference_env_gate_disabled" in preview["blockers"]
    assert "positive_budget_required" in preview["blockers"]
    assert preview["router"]["apiKeyReturned"] is False
    assert preview["sampleRequest"]["inferenceExecuted"] is False
    assert preview["safety"]["paidInferenceEnabled"] is False
    assert preview["safety"]["moneyMovementEnabled"] is False


def test_private_compute_smoke_preview_can_be_ready_without_executing():
    preview = build_private_compute_smoke_preview(
        {"prompt": "Summarize the ZeroGuard review packet."},
        api_key_configured=True,
        paid_inference_allowed=True,
        budget_usd=0.25,
    )

    assert preview["status"] == "ready_for_operator_paid_smoke"
    assert preview["blockers"] == []
    assert preview["promptScrub"]["safeForInference"] is True
    assert preview["sampleRequest"]["paidInferenceCallPrepared"] is True
    assert preview["sampleRequest"]["inferenceExecuted"] is False
    assert preview["safety"]["networkCalls"] is False
    assert preview["safety"]["paidInferenceEnabled"] is True


def test_private_compute_prompt_scrubber_rejects_and_redacts_secrets():
    secret = "0x" + "a" * 64
    prompt = f"Explain this but keep my key {secret} and X-PAYMENT header handy."
    scrub = scrub_private_compute_prompt(prompt)

    assert scrub["safeForInference"] is False
    assert {finding["id"] for finding in scrub["findings"]} >= {"private_key", "payment_header"}
    assert scrub["rawPromptReturned"] is False
    assert secret not in json.dumps(scrub)

    preview = build_private_compute_smoke_preview(
        {"prompt": prompt},
        api_key_configured=True,
        paid_inference_allowed=True,
        budget_usd=1,
    )
    assert preview["status"] == "blocked_before_paid_inference"
    assert "prompt_safety_violation" in preview["blockers"]
    assert preview["safety"]["promptSafeForInference"] is False
    assert secret not in json.dumps(preview)
