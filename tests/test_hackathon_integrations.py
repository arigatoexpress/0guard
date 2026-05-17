"""Tests for next-hackathon integration plans."""

from guard0.hackathon_integrations import (
    arbitrum_integration_plan,
    arbitrum_open_house_buildathon_plan,
    metamask_1shot_cookoff_plan,
    metamask_1shot_permission_preview,
    metamask_integration_plan,
    next_hackathon_plan,
)


def test_next_hackathon_plan_is_source_cited_and_no_side_effects():
    plan = next_hackathon_plan()

    assert plan["schema"] == "0guard.next_hackathon_plan.v1"
    assert plan["opportunities"][0]["id"] == "metamask_smart_accounts_1shot_api_dev_cookoff"
    assert plan["opportunities"][0]["timing"]["rewardAnnouncement"] == "2026-06-22 10:59"
    assert any(
        opportunity["id"] == "arbitrum_open_house_london_online_buildathon"
        for opportunity in plan["opportunities"]
    )
    assert any("MetaMask" in opportunity["name"] for opportunity in plan["opportunities"])
    assert all(opportunity["officialSources"] for opportunity in plan["opportunities"])
    assert plan["safety"]["transactionSigningEnabled"] is False
    assert plan["safety"]["moneyMovementEnabled"] is False


def test_arbitrum_plan_uses_catalog_targets_and_keeps_0g_anchor():
    plan = arbitrum_integration_plan()

    assert plan["schema"] == "0guard.arbitrum_integration_plan.v1"
    ids = {network["id"] for network in plan["networks"]}
    assert {"arbitrum_one", "arbitrum_nova", "arbitrum_sepolia"} <= ids
    assert any("0G proof context" in step for step in plan["demoPath"])
    assert plan["safety"]["bridgingEnabled"] is False


def test_arbitrum_open_house_plan_requires_deployed_arbitrum_proof():
    plan = arbitrum_open_house_buildathon_plan()

    assert plan["schema"] == "0guard.arbitrum_open_house_buildathon_plan.v1"
    assert plan["hackathon"]["targetTracks"][1]["id"] == "best_agentic_project"
    assert plan["qualification"]["mustDeployOnArbitrumChain"] is True
    assert "Arbitrum Sepolia" in plan["qualification"]["eligibleChains"]
    assert plan["contractScope"]["minimumViableContract"] == "PolicyReceiptRegistry"
    assert any("receipt hash" in step for step in plan["demoFlow"])
    assert plan["safety"]["transactionSigningEnabled"] is False


def test_metamask_plan_is_pre_signer_not_wallet_claim():
    plan = metamask_integration_plan()

    assert plan["schema"] == "0guard.metamask_integration_plan.v1"
    assert "not a wallet" in plan["positioning"]
    layer_ids = {layer["id"] for layer in plan["integrationLayers"]}
    assert {"connect_wrapper", "snap_transaction_signature_insights"} <= layer_ids
    assert any("expiry" in control for control in plan["minimumControls"])
    assert plan["safety"]["transactionSigningEnabled"] is False


def test_metamask_1shot_plan_targets_active_cookoff_without_money_movement():
    plan = metamask_1shot_cookoff_plan()

    assert plan["schema"] == "0guard.metamask_1shot_cookoff_plan.v1"
    assert plan["hackathon"]["submissionWindow"].endswith("2026-06-15 10:59")
    assert plan["hackathon"]["targetTracks"][0]["id"] == "best_x402_erc7710"
    assert any("Smart Accounts Kit" in step for step in plan["mainDemoFlow"])
    assert plan["fundingGate"]["send25OgNow"] is False
    assert plan["safety"]["moneyMovementEnabled"] is False


def test_metamask_1shot_permission_preview_builds_bounded_and_unsafe_paths():
    preview = metamask_1shot_permission_preview()

    assert preview["schema"] == "0guard.metamask_1shot_permission_preview.v1"
    assert preview["mode"] == "no_sign_no_settle_preview"
    assert preview["metaMask"]["usesSmartAccountsKit"] is True
    assert "ERC-7710" in preview["metaMask"]["standards"]
    assert preview["oneShot"]["x402Requirement"]["extra"]["assetTransferMethod"] == "erc7710"
    assert preview["oneShot"]["guardrail"]["targetId"] == "x402"
    assert preview["zeroGuard"]["boundedPermissionPreflight"]["decision"] in {"allow", "review"}
    assert preview["zeroGuard"]["delegationExecutionPreflight"]["decision"] in {"review", "deny"}
    assert preview["zeroGuard"]["unsafeVariantPreflight"]["decision"] == "deny"
    assert preview["safety"]["transactionSigningEnabled"] is False
