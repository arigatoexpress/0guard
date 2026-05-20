"""Tests for x402 dry-run payment route contracts."""

import json

from guard0.x402_guard import (
    X402_FIXTURE_PAYMENT_HEADER,
    X402_SETTLEMENT_PROOF_SCHEMA,
    build_x402_settlement_policy,
    build_x402_settlement_proof_status,
    build_x402_wallet_preflight_dry_run,
    verify_x402_settlement_proof,
)


def test_x402_wallet_preflight_requires_payment_without_settlement():
    payload = build_x402_wallet_preflight_dry_run()

    assert payload["schema"] == "0guard.x402_wallet_preflight_dry_run.v1"
    assert payload["status"] == "payment_required_dry_run"
    assert payload["httpStatus"] == 402
    assert payload["paymentRequirement"]["displayPrice"] == "0.01 USDC"
    assert payload["settlementPolicyRoute"] == "/api/x402/settlement-policy"
    assert payload["paymentRequirement"]["capsRoute"] == "/api/x402/settlement-policy"
    assert payload["paymentReadback"]["facilitatorCalled"] is False
    assert payload["paymentReadback"]["settlementEnabled"] is False
    assert payload["rightsPolicy"]["rawPayloadResaleAllowed"] is False
    assert payload["safety"]["x402SettlementEnabled"] is False
    assert payload["safety"]["moneyMovementEnabled"] is False


def test_x402_wallet_preflight_accepts_only_fixture_payment_header():
    payload = build_x402_wallet_preflight_dry_run(
        payment_header=X402_FIXTURE_PAYMENT_HEADER,
        body={"target": "0x02228b0afcdbEdf8180D96Fc181Da3AF5DD1d1ab"},
    )

    assert payload["status"] == "payment_fixture_accepted_no_settlement"
    assert payload["httpStatus"] == 200
    assert payload["paymentReadback"]["paymentHeaderAccepted"] is True
    assert payload["paymentReadback"]["paymentHeaderReturned"] is False
    assert payload["productResponse"]["rawPayloadResaleAllowed"] is False
    assert payload["productResponse"]["targetHash"]
    assert payload["safety"]["facilitatorCalled"] is False


def test_x402_wallet_preflight_rejects_malformed_payment_without_echo():
    secretish_header = "not-a-real-payment-secret-token"
    payload = build_x402_wallet_preflight_dry_run(payment_header=secretish_header)

    assert payload["status"] == "malformed_payment_fixture"
    assert payload["httpStatus"] == 400
    assert payload["paymentReadback"]["paymentHeaderAccepted"] is False
    assert payload["paymentReadback"]["paymentHeaderHash"]
    encoded = json.dumps(payload)
    assert secretish_header not in encoded
    assert payload["safety"]["paymentSettlementEnabled"] is False


def test_x402_settlement_policy_freezes_caps_terms_and_facilitator_path(monkeypatch):
    monkeypatch.delenv("ZG_X402_PAY_TO_ADDRESS", raising=False)
    policy = build_x402_settlement_policy()

    assert policy["schema"] == "0guard.x402_settlement_policy.v1"
    assert policy["mode"] == "settlement_policy_no_facilitator_call"
    assert policy["status"] == "blocked_before_settlement"
    assert "pay_to_address_missing" in policy["blockers"]
    assert policy["paymentRequirement"]["networkCaip2"] == "eip155:84532"
    assert policy["paymentRequirement"]["payToConfigured"] is False
    assert policy["spendCaps"]["perRequestMaxDisplay"] == "0.01 USDC"
    assert policy["terms"]["rawPayloadResaleAllowed"] is False
    assert "raw payment headers" in policy["terms"]["neverStore"]
    assert policy["facilitators"][0]["endpoint"] == "https://x402.org/facilitator"
    assert policy["facilitators"][0]["apiKeyRequired"] is False
    assert policy["settlementProof"]["status"] == "missing"
    assert policy["settlementProof"]["verified"] is False
    assert "base_sepolia_settlement_proof_missing" in policy["blockers"]
    assert policy["safety"]["facilitatorCalled"] is False
    assert policy["safety"]["x402SettlementEnabled"] is False


def test_x402_settlement_policy_accepts_public_pay_to_without_settling(monkeypatch):
    monkeypatch.setenv("ZG_X402_PAY_TO_ADDRESS", "0x000000000000000000000000000000000000dEaD")
    monkeypatch.setenv("ZG_X402_ENABLE_SETTLEMENT", "1")
    policy = build_x402_settlement_policy()

    assert policy["status"] == "ready_for_testnet_review"
    assert policy["paymentRequirement"]["payToConfigured"] is True
    assert policy["paymentRequirement"]["payTo"].endswith("dEaD")
    assert "pay_to_address_missing" not in policy["blockers"]
    assert policy["safety"]["settlementEnvGateEnabled"] is True
    assert policy["safety"]["x402SettlementEnabled"] is False
    assert policy["safety"]["settlementByZeroGuardEnabled"] is False


def test_x402_settlement_proof_accepts_public_safe_testnet_receipt():
    proof = _valid_x402_proof()

    result = verify_x402_settlement_proof(proof)

    assert result["schema"] == "0guard.x402_base_sepolia_settlement_proof_verification.v1"
    assert result["verified"] is True
    assert result["networkCaip2"] == "eip155:84532"
    assert result["amountAtomic"] == "10000"
    assert result["checks"]["amountAtomicWithinCap"] is True
    assert result["safety"]["settlementByZeroGuardEnabled"] is False
    assert result["safety"]["paymentHeaderStored"] is False


def test_x402_settlement_proof_rejects_over_cap_or_raw_storage_flags():
    proof = _valid_x402_proof()
    proof["amountAtomic"] = "10001"
    proof["paymentHeaderStored"] = True

    result = verify_x402_settlement_proof(proof)

    assert result["verified"] is False
    assert result["checks"]["amountAtomicWithinCap"] is False
    assert result["checks"]["paymentHeaderStored"] is False
    assert result["safety"]["settlementByZeroGuardEnabled"] is False


def test_x402_settlement_policy_surfaces_verified_proof(monkeypatch, tmp_path):
    proof_path = tmp_path / "x402-proof.json"
    proof_path.write_text(json.dumps(_valid_x402_proof()), encoding="utf-8")
    monkeypatch.setenv("ZG_X402_PAY_TO_ADDRESS", _valid_x402_proof()["payTo"])
    monkeypatch.setenv("ZG_X402_ENABLE_SETTLEMENT", "1")

    proof_status = build_x402_settlement_proof_status(proof_path)

    assert proof_status["verified"] is True
    assert proof_status["settlementPerformedExternally"] is True


def _valid_x402_proof() -> dict:
    return {
        "schema": X402_SETTLEMENT_PROOF_SCHEMA,
        "route": "/x402/v1/wallet-preflight",
        "network": "base-sepolia",
        "networkCaip2": "eip155:84532",
        "asset": "USDC",
        "decimals": 6,
        "amountAtomic": "10000",
        "payer": "0x000000000000000000000000000000000000bEEF",
        "payTo": "0x000000000000000000000000000000000000dEaD",
        "transactionHash": "0x" + "a" * 64,
        "facilitatorUrl": "https://x402.org/facilitator",
        "paymentHeaderHash": "b" * 64,
        "responseHash": "c" * 64,
        "termsVersion": "zeroguard-x402-terms-2026-05-19",
        "operatorReviewedCapsAndTerms": True,
        "settlementAttempted": True,
        "facilitatorCalled": True,
        "settled": True,
        "settlementPerformedExternally": True,
        "rawPayloadResaleAllowed": False,
        "paymentHeaderStored": False,
        "paymentHeaderReturned": False,
        "privateKeysReturned": False,
        "transactionSigningByZeroGuard": False,
        "transactionBroadcastingByZeroGuard": False,
        "moneyMovementByZeroGuard": False,
    }
