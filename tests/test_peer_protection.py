"""Tests for peer-protection, 0G Private Computer, and Pi mesh manifests."""

from __future__ import annotations

from guard0.peer_protection import (
    build_0g_private_computer_integration,
    build_peer_outreach_preview,
    build_peer_protection_plan,
    build_pi_mesh_plan,
)


def test_private_computer_manifest_is_safe_and_current():
    manifest = build_0g_private_computer_integration()

    assert manifest["schema"] == "0guard.0g_private_computer_integration.v1"
    assert manifest["model"]["id"] == "0GM-1.0-35B-A3B"
    assert manifest["model"]["license"] == "Apache-2.0"
    assert manifest["api"]["openAiCompatible"] is True
    assert manifest["api"]["chatCompletionsUrl"].endswith("/v1/chat/completions")
    assert manifest["api"]["sampleRequest"]["verify_tee"] is True
    assert manifest["safety"]["telegramSendsEnabled"] is False
    assert manifest["safety"]["transactionBroadcastingEnabled"] is False


def test_peer_protection_plan_keeps_outreach_gated():
    plan = build_peer_protection_plan(live=False)

    assert plan["schema"] == "0guard.peer_protection_plan.v1"
    assert "peer-protection layer" in plan["thesis"]
    assert plan["peerContactModel"]["publicPeersExposeContactInfo"] is False
    assert any(item["id"] == "attested_ai_risk_review" for item in plan["protectiveProducts"])
    assert "No unsolicited Telegram, email, or blockchain messages." in plan["automationGates"]
    assert plan["safety"]["externalMessagesEnabled"] is False


def test_peer_outreach_preview_blocks_without_opt_in_and_broadcast():
    preview = build_peer_outreach_preview(
        {
            "peer": {"id": "peer-1", "network": "0g_mainnet"},
            "risk": {"title": "sync lag", "severity": "review", "evidence": ["rpc"]},
            "channel": "onchain_message_hash_draft",
            "contact": {
                "label": "peer operator",
                "evmAddress": "0x000000000000000000000000000000000000dEaD",
                "optInConfirmed": False,
            },
        }
    )

    assert preview["schema"] == "0guard.peer_outreach_preview.v1"
    assert preview["decision"] == "blocked_preview_only"
    assert "peer_opt_in_not_confirmed" in preview["blockedBy"]
    assert preview["telegram_send"] is False
    assert preview["blockchain_broadcast"] is False
    assert preview["onchainEnvelope"]["messageHash"].startswith("0x")
    assert preview["onchainEnvelope"]["calldata"] is None


def test_peer_outreach_preview_with_opt_in_still_requires_operator_review():
    preview = build_peer_outreach_preview(
        {
            "channel": "telegram_opt_in_preview",
            "contact": {"telegramUsername": "peer_ops", "optInConfirmed": True},
        }
    )

    assert preview["decision"] == "ready_for_operator_review"
    assert preview["blockedBy"] == []
    assert preview["delivery"] == "preview_no_send"
    assert preview["onchainEnvelope"]["operatorApprovalRequired"] is True


def test_pi_mesh_plan_uses_pis_for_sentinel_work_not_keys():
    plan = build_pi_mesh_plan()

    assert plan["schema"] == "0guard.pi_mesh_plan.v1"
    assert plan["observedNodes"][0]["id"] == "rvpi-a"
    assert any(role["id"] == "node_sentinel" for role in plan["distributedComputeRoles"])
    assert any("Do not attempt 0GM-35B inference" in task for role in plan["distributedComputeRoles"] for task in role["tasks"])
    assert plan["safety"]["privateKeysReturned"] is False
    assert plan["safety"]["walletSignaturesEnabled"] is False
