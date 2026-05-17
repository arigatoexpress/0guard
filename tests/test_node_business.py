"""Tests for read-only 0G node business surfaces."""

from __future__ import annotations

from guard0.node_business import (
    build_0g_node_business_plan,
    build_alignment_node_status,
    build_telegram_node_business_preview,
    build_validator_capacity_status,
)


def test_alignment_node_status_defaults_to_safe_snapshot():
    status = build_alignment_node_status(live=False)

    assert status["schema"] == "0guard.0g_alignment_node_status.v1"
    assert status["mode"] == "configured_snapshot"
    assert status["contracts"]["alignmentManager"].startswith("0x7BD")
    assert status["readiness"]["status"] == "operator_action_required"
    assert "alignment_license_not_checked" in status["readiness"]["blockedBy"]
    assert status["readiness"]["requiresWalletPrivateKey"] is True
    assert status["safety"]["privateKeysReturned"] is False
    assert status["safety"]["signingEnabled"] is False
    assert status["safety"]["moneyMovementEnabled"] is False


def test_alignment_node_status_uses_injected_graphql_reader():
    def fake_reader(query: str, variables: dict, timeout_seconds: float) -> dict:
        assert variables["owners"] == ["0x1111111111111111111111111111111111111111"]
        return {
            "data": {
                "nfts": [
                    {
                        "id": "123",
                        "owner": {"id": "0x1111111111111111111111111111111111111111"},
                        "operator": {"id": "0x2222222222222222222222222222222222222222"},
                        "delegatedTime": "100",
                        "approvedTime": "110",
                        "undelegatedTime": None,
                        "totalReward": str(12 * 10**18),
                        "lastUpdatedTime": "120",
                    }
                ]
            }
        }

    status = build_alignment_node_status(
        live=True,
        owner_addresses=["0x1111111111111111111111111111111111111111"],
        graphql_reader=fake_reader,
    )

    assert status["mode"] == "live_subgraph_read_only"
    assert status["query"]["licenseCount"] == 1
    assert status["query"]["activeLicenseCount"] == 1
    assert status["licenses"][0]["tokenId"] == "123"
    assert status["licenses"][0]["totalRewardOg"] == 12
    assert status["licenses"][0]["isRunning"] is True
    assert status["readiness"]["requiresKyc"] is True
    assert "kyc_and_wallet_signature_required" in status["readiness"]["blockedBy"]


def test_validator_capacity_keeps_wsl_ram_as_blocker():
    status = build_validator_capacity_status()

    assert status["schema"] == "0guard.0g_validator_capacity.v1"
    assert status["checks"]["cpuPass"] is True
    assert status["checks"]["mainnetDiskPass"] is True
    assert status["checks"]["wslUsableMemoryPass"] is False
    assert status["readiness"]["status"] == "not_recommended_in_wsl"
    assert any(item["id"] == "ram_upgrade" for item in status["workarounds"])


def test_node_business_plan_is_read_only_and_service_revenue_oriented():
    plan = build_0g_node_business_plan(live=False)

    assert plan["schema"] == "0guard.0g_node_business.v1"
    assert plan["mode"] == "configured_snapshot"
    assert plan["safety"]["moneyMovementEnabled"] is False
    assert any(lane["id"] == "zeroguard_product" for lane in plan["lanes"])
    assert any("Operator subscription" in item for item in plan["monetization"])
    assert plan["currentReadiness"]["storageEconomics"]["perActiveMinerMonthlyOg"] is not None
    assert "No 100 0G" in " ".join(plan["operatorGates"])


def test_telegram_node_business_preview_is_no_send():
    preview = build_telegram_node_business_preview(build_0g_node_business_plan(live=False))

    assert preview["schema"] == "0guard.telegram_node_business_preview.v1"
    assert preview["delivery"] == "preview_no_send"
    assert preview["telegram_send"] is False
    assert preview["safety"]["telegramSendsEnabled"] is False
    assert "Delivery: preview only" in preview["message"]
