"""Tests for disabled-by-default 0G Private Computer smoke previews."""

import json

from guard0.peer_protection import CHAT_COMPLETIONS_URL, MODEL_ID, ROUTER_BASE_URL
from guard0.private_compute_adapter import (
    PRIVATE_COMPUTE_PAID_SMOKE_PROOF_SCHEMA,
    build_private_compute_paid_smoke_proof_status,
    build_private_compute_smoke_preview,
    scrub_private_compute_prompt,
    verify_private_compute_paid_smoke_proof,
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
    assert preview["router"]["openAiCompatible"] is True
    assert preview["router"]["apiKeyEnvNames"] == [
        "ZG_0G_ROUTER_API_KEY",
        "ZG_0G_PC_API_KEY",
        "ZERO_G_API_KEY",
    ]
    assert preview["router"]["paidInferenceGateEnv"] == "ZG_ALLOW_PAID_INFERENCE"
    assert preview["router"]["budgetEnv"] == "ZG_0G_INFERENCE_BUDGET_USD"
    assert preview["routerContract"]["schema"] == (
        "0guard.0g_private_compute_router_contract.v1"
    )
    assert preview["routerContract"]["chatCompletionsPath"] == "/chat/completions"
    assert preview["routerContract"]["auth"]["headerTemplate"] == (
        "Authorization: Bearer ${ZG_0G_ROUTER_API_KEY}"
    )
    assert preview["routerContract"]["auth"]["browserUseAllowed"] is False
    assert preview["routerContract"]["budgetGate"]["maxFirstSmokeCostUsd"] == 0.25
    assert preview["routerContract"]["proofRequirements"]["recordRawPrompt"] is False
    assert preview["paidSmokeProof"]["status"] == "missing"
    assert preview["paidSmokeProof"]["verified"] is False
    assert preview["operatorProofPacket"]["schema"] == (
        "0guard.0g_private_compute_paid_smoke_operator_proof_packet.v1"
    )
    assert "record_0g_private_compute_paid_smoke.py" in preview["recordProofCommandTemplate"]
    assert preview["operatorProofPacket"]["rawPromptRequired"] is False
    assert preview["operatorProofPacket"]["apiKeyStoredInProof"] is False
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
    assert preview["sampleRequest"]["openAiCompatible"] is True
    assert preview["sampleRequest"]["body"]["chat_template_kwargs"] == {
        "enable_thinking": False
    }
    assert preview["routerContract"]["auth"]["apiKeyConfigured"] is True
    assert preview["routerContract"]["budgetGate"]["paidInferenceAllowedByEnv"] is True
    assert preview["routerContract"]["budgetGate"]["budgetUsd"] == 0.25
    assert preview["paidSmokeProof"]["status"] == "missing"
    assert preview["operatorProofPacket"]["status"] == "ready_for_external_paid_smoke_proof"
    assert preview["operatorProofPacket"]["maxFirstSmokeCostUsd"] == 0.25
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


def test_private_compute_paid_smoke_proof_accepts_public_safe_receipt():
    proof = _valid_paid_smoke_proof()

    result = verify_private_compute_paid_smoke_proof(proof)

    assert result["schema"] == "0guard.0g_private_compute_paid_smoke_proof_verification.v1"
    assert result["status"] == "verified"
    assert result["verified"] is True
    assert result["costUsd"] == 0.01
    assert result["routerContract"]["billing"]["routerTraceField"] == (
        "x_0g_trace.billing.total_cost"
    )
    assert result["routerContract"]["proofRequirements"]["recordRouterReceiptHash"] is True
    assert result["checks"]["costWithinFirstSmokeCap"] is True
    assert result["safety"]["paidInferenceByZeroGuard"] is False
    assert result["safety"]["rawPromptReturned"] is False
    assert result["safety"]["rawResponseReturned"] is False


def test_private_compute_paid_smoke_proof_rejects_over_cap_or_raw_storage():
    proof = _valid_paid_smoke_proof()
    proof["costUsd"] = "0.26"
    proof["rawResponseStored"] = True

    result = verify_private_compute_paid_smoke_proof(proof)

    assert result["verified"] is False
    assert result["checks"]["costWithinFirstSmokeCap"] is False
    assert result["checks"]["rawResponseStored"] is False
    assert result["safety"]["paidInferenceByZeroGuard"] is False


def test_private_compute_paid_smoke_missing_status_exposes_operator_packet(
    tmp_path,
    monkeypatch,
):
    monkeypatch.delenv("ZG_0G_ROUTER_API_KEY", raising=False)
    monkeypatch.delenv("ZG_0G_PC_API_KEY", raising=False)
    monkeypatch.delenv("ZERO_G_API_KEY", raising=False)
    monkeypatch.delenv("ZG_ALLOW_PAID_INFERENCE", raising=False)
    monkeypatch.setenv("ZG_0G_INFERENCE_BUDGET_USD", "0")
    proof_path = tmp_path / "missing-proof.json"

    result = build_private_compute_paid_smoke_proof_status(proof_path)

    assert result["status"] == "missing"
    assert result["verified"] is False
    assert result["proofBlockers"] == ["paid_smoke_proof_file_missing"]
    assert result["preflightBlockers"] == [
        "router_api_key_missing",
        "paid_inference_env_gate_disabled",
        "positive_budget_required",
    ]
    assert result["blockers"] == [
        "paid_smoke_proof_file_missing",
        "router_api_key_missing",
        "paid_inference_env_gate_disabled",
        "positive_budget_required",
    ]
    assert result["router"]["apiKeyConfigured"] is False
    assert result["router"]["apiKeyReturned"] is False
    assert result["router"]["networkCalls"] is False
    assert result["routerContract"]["openAiCompatible"] is True
    assert result["routerContract"]["auth"]["apiKeyEnvNames"] == [
        "ZG_0G_ROUTER_API_KEY",
        "ZG_0G_PC_API_KEY",
        "ZERO_G_API_KEY",
    ]
    assert result["routerContract"]["auth"]["apiKeyReturned"] is False
    assert result["routerContract"]["proofRequirements"]["recordApiKey"] is False
    assert "record_0g_private_compute_paid_smoke.py" in result["recordProofCommandTemplate"]
    assert result["operatorProofPacket"]["schema"] == (
        "0guard.0g_private_compute_paid_smoke_operator_proof_packet.v1"
    )
    assert result["operatorProofPacket"]["rawResponseRequired"] is False
    assert result["operatorProofPacket"]["apiKeyRequiredByRecorder"] is False
    assert result["safety"]["paidInferenceByZeroGuard"] is False


def test_private_compute_smoke_preview_surfaces_verified_paid_smoke_proof(tmp_path):
    proof_path = tmp_path / "0g-private-compute-paid-smoke-proof.json"
    proof_path.write_text(json.dumps(_valid_paid_smoke_proof()), encoding="utf-8")

    status = build_private_compute_paid_smoke_proof_status(proof_path)
    preview = build_private_compute_smoke_preview(
        {"prompt": "Summarize the ZeroGuard review packet."},
        api_key_configured=False,
        paid_inference_allowed=False,
        budget_usd=0,
        paid_smoke_proof_path=proof_path,
    )

    assert status["verified"] is True
    assert preview["status"] == "paid_smoke_complete"
    assert preview["paidSmokeProof"]["verified"] is True
    assert preview["paidSmokeProof"]["paidInferencePerformedExternally"] is True
    assert preview["safety"]["inferenceExecuted"] is False


def _valid_paid_smoke_proof() -> dict:
    return {
        "schema": PRIVATE_COMPUTE_PAID_SMOKE_PROOF_SCHEMA,
        "model": MODEL_ID,
        "routerBaseUrl": ROUTER_BASE_URL,
        "chatCompletionsUrl": CHAT_COMPLETIONS_URL,
        "promptHash": "a" * 64,
        "requestHash": "b" * 64,
        "responseHash": "c" * 64,
        "routerReceiptHash": "d" * 64,
        "budgetUsd": "0.25",
        "costUsd": "0.01",
        "operatorReviewedBudget": True,
        "promptSafeForInference": True,
        "paidInferencePerformedExternally": True,
        "rawPromptStored": False,
        "rawPromptReturned": False,
        "rawResponseStored": False,
        "rawResponseReturned": False,
        "apiKeyReturned": False,
        "privateKeysReturned": False,
        "paymentHeadersStored": False,
        "transactionSigningByZeroGuard": False,
        "transactionBroadcastingByZeroGuard": False,
        "moneyMovementByZeroGuard": False,
    }
