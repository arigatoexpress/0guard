"""Tests for active read-only external guardrail evaluation."""

import pytest

from guard0.external_guardrails import (
    evaluate_external_guardrail,
    external_guardrail_catalog,
)


def test_external_guardrail_catalog_is_non_mutating():
    catalog = external_guardrail_catalog()

    assert catalog["schema"] == "0guard.external_guardrail_catalog.v1"
    assert catalog["mode"] == "read_only_policy_evaluator"
    assert catalog["safety"]["moneyMovementEnabled"] is False
    assert catalog["safety"]["postingEnabled"] is False
    assert {item["targetId"] for item in catalog["guardrails"]} >= {
        "x402",
        "virtuals_base",
        "lighter_exchange",
        "chainlink_ccip",
        "layerzero_v2",
        "wormhole_ntt",
        "celestia_blobstream",
        "ika_dwallets",
    }


def test_layerzero_single_dvn_is_denied():
    result = evaluate_external_guardrail(
        {
            "target_id": "layerzero_v2",
            "action": "bridge_release",
            "config": {
                "requiredDVNCount": 1,
                "sendReceiveConfigSymmetric": False,
                "nonceReplayProtection": False,
            },
        }
    )

    assert result["decision"] == "deny"
    assert {finding["id"] for finding in result["findings"]} >= {
        "layerzero_single_dvn_denied",
        "layerzero_send_receive_asymmetry",
        "layerzero_replay_protection_missing",
    }
    assert result["safety"]["bridgingEnabled"] is False


def test_lighter_order_and_lit_actions_are_denied():
    order = evaluate_external_guardrail(
        {
            "target_id": "lighter_exchange",
            "action": "place_order",
            "intent_text": "Create an API key and place a perp order.",
        }
    )
    lit = evaluate_external_guardrail(
        {
            "target_id": "lighter_exchange",
            "action": "stake",
            "intent_text": "Buy LIT and fee credits for trading.",
        }
    )

    assert order["decision"] == "deny"
    assert lit["decision"] == "deny"
    assert order["findings"][0]["id"] == "lighter_external_side_effect_denied"
    assert lit["safety"]["exchangeApiKeysEnabled"] is False


def test_x402_live_settlement_requires_controls_and_no_raw_resale():
    result = evaluate_external_guardrail(
        {
            "target_id": "x402",
            "action": "settle",
            "config": {
                "liveSettlement": True,
                "rawPayloadResale": True,
                "networkId": "eip155:8453",
            },
        }
    )

    assert result["decision"] == "deny"
    assert {finding["id"] for finding in result["findings"]} >= {
        "x402_raw_payload_resale_denied",
        "x402_live_settlement_missing_controls",
    }


def test_wormhole_controls_roll_up_to_review_or_allow():
    review = evaluate_external_guardrail({"target_id": "wormhole_ntt", "config": {}})
    allow = evaluate_external_guardrail(
        {
            "target_id": "wormhole_ntt",
            "config": {
                "guardianThreshold": 13,
                "expectedGuardianQuorum": 13,
                "globalAccountantEnabled": True,
                "transceiverRegistryChanged": False,
            },
        }
    )

    assert review["decision"] == "review"
    assert allow["decision"] == "allow"


def test_invalid_config_rejected():
    with pytest.raises(ValueError, match="config must be an object"):
        evaluate_external_guardrail({"target_id": "layerzero_v2", "config": []})


def test_ika_external_guardrail_denies_live_signing():
    result = evaluate_external_guardrail(
        {
            "target_id": "ika_dwallets",
            "action": "sign_transaction",
            "intent_text": "Sign a live dWallet sweep.",
            "config": {"liveSigning": True, "sourceProject": "ikavery"},
        }
    )

    assert result["schema"] == "0guard.external_guardrail_evaluation.v1"
    assert result["decision"] == "deny"
    assert any(finding["id"] == "ika_signing_surface_operator_only" for finding in result["findings"])
    assert any(finding["id"] == "ikavery_pre_alpha_devnet_boundary" for finding in result["findings"])
    assert result["safety"]["transactionSigningEnabled"] is False
