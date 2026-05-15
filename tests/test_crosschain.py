"""Tests for read-only cross-chain integration fabric."""

import json

from guard0.crosschain import (
    cross_chain_catalog,
    cross_chain_readiness,
    virtuals_facilitator_manifest,
)


def test_cross_chain_catalog_is_source_cited_and_non_mutating():
    catalog = cross_chain_catalog()

    assert catalog["schema"] == "0guard.crosschain_catalog.v1"
    assert catalog["targetCount"] >= 12
    assert catalog["evmTargetCount"] >= 7
    assert catalog["x402"]["mode"] == "prepared_not_live"
    assert catalog["x402"]["rightsEnvelope"]["rawPayloadResaleAllowed"] is False
    assert catalog["safety"]["transactionSigningEnabled"] is False
    assert catalog["safety"]["bridgingEnabled"] is False
    assert catalog["safety"]["moneyMovementEnabled"] is False
    assert catalog["safety"]["tradingEnabled"] is False
    assert catalog["safety"]["exchangeApiKeysEnabled"] is False

    targets = {target["id"]: target for target in catalog["targets"]}
    assert targets["base_mainnet"]["chainId"] == 8453
    assert "virtuals_protocol" in targets["base_mainnet"]["capabilities"]
    assert targets["0g_mainnet"]["chainId"] == 16661
    assert targets["0g_mainnet"]["x402Posture"].startswith("custom_facilitator_required")
    assert targets["celestia_blobstream"]["evmCompatible"] is False
    assert "Blobstream" in targets["celestia_blobstream"]["proofStrategy"]
    assert targets["lighter_exchange"]["nativeAsset"] == "N/A"
    assert targets["lighter_exchange"]["evmCompatible"] is False
    assert targets["lighter_exchange"]["httpStatusUrl"].startswith("https://mainnet.zklighter")
    assert "verifiable_order_matching" in targets["lighter_exchange"]["capabilities"]
    assert targets["chainlink_ccip"]["kind"] == "cross_chain_security_protocol"
    assert "ccip_lane_policy_review" in targets["chainlink_ccip"]["capabilities"]
    assert "dvn_executor_config_review" in targets["layerzero_v2"]["capabilities"]
    assert "global_accountant_supply_invariant" in targets["wormhole_ntt"]["capabilities"]
    assert targets["ika_dwallets"]["kind"] == "zero_trust_signing_fabric"
    assert "native_multichain_signatures" in targets["ika_dwallets"]["capabilities"]
    assert targets["ikavery_recovery"]["status"] == "testnet_devnet_pre_alpha_reference"
    assert targets["encrypt_pre_alpha"]["status"] == "pre_alpha_devnet_plaintext_warning"
    assert all(target["officialSources"] for target in catalog["targets"])


def test_cross_chain_readiness_defaults_to_catalog_only_without_network():
    readiness = cross_chain_readiness(live=False)

    assert readiness["schema"] == "0guard.crosschain_readiness.v1"
    assert readiness["live"] is False
    assert readiness["attemptedRpcProbes"] == 0
    assert readiness["attemptedHttpProbes"] == 0
    assert readiness["rpcReadinessRatio"] is None
    assert readiness["paymentReadiness"]["x402Ready"] is False
    assert readiness["paymentReadiness"]["liveSettlementAllowed"] is False
    assert readiness["agentReadiness"]["virtualsBaseAgentPrepared"] is True
    assert readiness["agentReadiness"]["virtualsLiveAgentLaunched"] is False
    assert readiness["safety"]["rawPayloadsReturned"] is False

    by_id = {probe["id"]: probe for probe in readiness["probes"]}
    assert by_id["base_mainnet"]["status"] == "not_checked"
    assert by_id["lighter_exchange"]["status"] == "not_checked"
    assert by_id["celestia_blobstream"]["status"] == "catalog_only_non_evm"
    assert by_id["chainlink_ccip"]["status"] == "catalog_only_non_evm"
    assert by_id["ika_dwallets"]["status"] == "catalog_only_non_evm"


def test_virtuals_facilitator_manifest_is_deployable_but_not_deployed():
    manifest = virtuals_facilitator_manifest()

    assert manifest["schema"] == "0guard.virtuals_facilitator_manifest.v1"
    assert manifest["agent"]["name"] == "0guard Facilitator"
    assert manifest["agent"]["network"] == "Base"
    assert manifest["agent"]["chainId"] == 8453
    assert manifest["agent"]["launchStatus"] == "prepared_operator_required"
    assert manifest["safety"]["externalAgentLaunchEnabled"] is False
    assert manifest["safety"]["moneyMovementEnabled"] is False
    assert any(capability["route"] == "/api/evaluate" for capability in manifest["capabilities"])
    assert "base_mainnet" in manifest["paymentPolicy"]["recommendedFirstSettlementNetworks"]

    encoded = json.dumps(manifest).lower()
    assert "private_key" not in encoded
    assert "mnemonic" not in encoded
