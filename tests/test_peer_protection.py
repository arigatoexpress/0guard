"""Tests for peer-protection, 0G Private Computer, and Pi mesh manifests."""

from __future__ import annotations

import json

from guard0.peer_protection import (
    build_0g_hot_wallet_resources,
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
    assert manifest["api"]["recommendedPath"] == "router"
    assert manifest["api"]["apiKeyPrefix"] == "sk-"
    assert manifest["modelCatalog"]["status"] == "not_checked"
    assert manifest["directAdvancedMode"]["minimumLedgerDepositOg"] == 3
    assert manifest["fundingState"]["routerDepositPrepared"] is False
    assert manifest["fundingState"]["paymentLayerContracts"]["mainnet"].startswith("0xA3b15")
    assert manifest["safety"]["telegramSendsEnabled"] is False
    assert manifest["safety"]["transactionBroadcastingEnabled"] is False


def test_hot_wallet_resource_manifest_is_manifest_only():
    manifest = build_0g_hot_wallet_resources()

    assert manifest["schema"] == "0guard.0g_hot_wallet_resources.v1"
    assert manifest["mode"] == "operator_gated_resource_manifest"
    assert manifest["walletRoles"][0]["publicAddress"].startswith("0x885")
    assert manifest["preparedResources"][1]["status"] == "manifest_only_no_transaction"
    assert manifest["preparedResources"][1]["paymentLayerContract"].startswith("0xA3b15")
    assert manifest["preparedResources"][1]["requiresFinalConfirmation"] is True
    assert any("Depositing 0G" in item for item in manifest["notAllowedFromWorkbench"])
    assert manifest["safety"]["moneyMovementEnabled"] is False
    assert manifest["safety"]["privateKeysReturned"] is False


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


def test_pi_mesh_plan_loads_live_snapshot_without_enabling_sends(tmp_path):
    snapshot_path = tmp_path / "rv_pi_mesh.local.json"
    snapshot_path.write_text(
        json.dumps(
            {
                "schema": "0guard.rv_pi_mesh_snapshot.v1",
                "generatedAt": "2026-05-17T13:30:00+00:00",
                "nodes": {
                    "rvpi-a": {
                        "status": "online",
                        "wifiIpv4": "192.168.1.111",
                        "ethernetIpv4": "10.77.4.11",
                        "memoryGiB": 3.7,
                        "eth0": {"carrier": True},
                        "services": {"ari-edge-api": "active"},
                        "safeRole": "sentinel_probe_and_evidence_cache",
                    },
                    "rvpi-b": {
                        "status": "ethernet_ssh_reachable_identity_unverified",
                        "expectedWifiIpv4": "192.168.1.144",
                        "ethernetIpv4": "10.77.4.12",
                        "identityVerified": False,
                        "edgeApiReady": False,
                        "tcpFromRvpiA": {"22": {"ok": True}},
                    },
                },
                "cluster": {
                    "primaryReachable": True,
                    "ethernetCarrierReady": True,
                    "peerEthernetReachable": True,
                    "peerIdentityVerified": False,
                    "edgeApiReady": True,
                    "clusterReady": False,
                    "blockers": ["rvpi_b_identity_unverified", "rvpi_b_edge_api_not_ready"],
                    "recommendedAction": "install_or_authorize_rvpi_b_runtime_over_eth",
                },
                "safety": {
                    "readOnly": True,
                    "privateKeysReturned": False,
                    "telegramSendsEnabled": False,
                },
            }
        ),
        encoding="utf-8",
    )

    plan = build_pi_mesh_plan(status_file=str(snapshot_path))

    assert plan["mode"] == "rv_pi_mesh_snapshot_file"
    assert plan["clusterReady"] is False
    assert "rvpi_b_identity_unverified" in plan["blockers"]
    assert plan["nodes"][1]["ethernetIpv4"] == "10.77.4.12"
    assert plan["snapshot"]["status"] == "loaded"
    assert plan["fileStatus"]["status"] == "loaded"
    assert plan["observedNodes"][0]["eth0"] == "carrier_ready"
    assert plan["observedNodes"][1]["ethernetIpv4"] == "10.77.4.12"
    assert plan["readiness"]["peerEthernetReachable"] is True
    assert plan["readiness"]["peerIdentityVerified"] is False
    assert "rvpi_b_identity_unverified" in plan["readiness"]["blockers"]
    assert plan["readiness"]["telegramSendsEnabled"] is False
