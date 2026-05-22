"""Tests for the operational readiness profile."""

from guard0 import readiness as readiness_module
from guard0.readiness import production_readiness


def test_production_readiness_is_honest_and_non_mutating(monkeypatch):
    monkeypatch.delenv("ZGG_CHAIN_RPC", raising=False)
    monkeypatch.delenv("ZGG_CHAIN_ID", raising=False)
    monkeypatch.delenv("ZGG_RECEIPT_CONTRACT", raising=False)
    monkeypatch.delenv("TELEGRAM_OPT_IN_STORE_PATH", raising=False)
    monkeypatch.delenv("TELEGRAM_OPT_IN_STORE_URL", raising=False)
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("ZG_TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.setattr(readiness_module, "_production_gate_payloads", _blocked_gate_payloads)

    result = production_readiness()

    assert result["schema"] == "0guard.readyz.v1"
    assert result["mode"] == "operational_readiness_no_side_effects"
    assert result["readiness"] == "production_review"
    assert result["ok"] is False
    checks = {check["id"]: check for check in result["checks"]}
    assert checks["mainnet_verifier_profile"]["status"] == "ok"
    assert checks["mainnet_proof_file"]["status"] == "ok"
    assert checks["detector_coverage"]["status"] == "ok"
    assert checks["reputation_shadow_cache"]["status"] == "ok"
    assert checks["reputation_backfill_artifact"]["status"] == "ok"
    assert checks["reputation_backfill_artifact"]["detail"]["freshWithinTtl"] is True
    assert checks["telegram_state_store"]["status"] == "ok"
    assert checks["storage_node_funded_soak"]["status"] == "review"
    assert checks["wallet_provider_external_proof"]["status"] == "review"
    assert checks["wallet_provider_external_proof"]["detail"]["verified"] is False
    assert "wallet_provider_external_proof_file_missing" in (
        checks["wallet_provider_external_proof"]["detail"]["blockers"]
    )
    assert "real_wallet_extension_proof_missing" in (
        checks["wallet_provider_external_proof"]["detail"]["proofBlockers"]
    )
    assert (
        checks["wallet_provider_external_proof"]["detail"]["suggestedExternalProofUrl"]
        == "https://arigatoexpress.github.io/0guard/wallet-provider-proof/"
    )
    assert (
        checks["wallet_provider_external_proof"]["detail"]["requiresRealWalletExtension"]
        is True
    )
    assert checks["wallet_provider_external_proof"]["detail"]["requiresWindowEthereum"] is True
    assert (
        checks["wallet_provider_external_proof"]["detail"]["requiresThrowawayEmptyWallet"]
        is True
    )
    assert "repeated-character placeholder hashes are rejected" in (
        checks["wallet_provider_external_proof"]["detail"]["receiptHashPolicy"]
    )
    assert (
        checks["wallet_provider_external_proof"]["detail"]["placeholderReceiptHashesRejected"]
        is True
    )
    assert checks["wallet_provider_external_proof"]["detail"]["realWalletExtension"] is True
    assert checks["wallet_provider_external_proof"]["detail"]["mockProvider"] is False
    assert checks["telegram_live_identity"]["status"] == "review"
    assert checks["storage_upload_readback"]["status"] == "review"
    assert "live_proof_file_missing" in checks["storage_upload_readback"]["detail"]["blockers"]
    assert "live_proof_file_missing" in (
        checks["storage_upload_readback"]["detail"]["proofBlockers"]
    )
    assert "storage_sdk_runtime_not_present" in (
        checks["storage_upload_readback"]["detail"]["preflightBlockers"]
    )
    assert "live_proof_file_missing" in (
        checks["storage_upload_readback"]["detail"]["liveProofBlockers"]
    )
    assert checks["private_compute_paid_smoke"]["status"] == "review"
    assert "paid_smoke_proof_file_missing" in (
        checks["private_compute_paid_smoke"]["detail"]["blockers"]
    )
    assert "paid_smoke_proof_file_missing" in (
        checks["private_compute_paid_smoke"]["detail"]["paidSmokeProofBlockers"]
    )
    assert "router_api_key_missing" in (
        checks["private_compute_paid_smoke"]["detail"]["paidSmokePreflightBlockers"]
    )
    assert (
        checks["private_compute_paid_smoke"]["detail"]["routerContractSchema"]
        == "0guard.0g_private_compute_router_contract.v1"
    )
    assert (
        checks["private_compute_paid_smoke"]["detail"]["paidInferenceGateEnv"]
        == "ZG_ALLOW_PAID_INFERENCE"
    )
    assert (
        checks["private_compute_paid_smoke"]["detail"]["inferenceBudgetEnv"]
        == "ZG_0G_INFERENCE_BUDGET_USD"
    )
    assert (
        checks["private_compute_paid_smoke"]["detail"]["routerTraceField"]
        == "x_0g_trace.billing.total_cost"
    )
    assert checks["x402_settlement_path"]["status"] == "review"
    assert checks["x402_settlement_path"]["detail"]["spendCapsConfigured"] is True
    assert checks["x402_settlement_path"]["detail"]["termsConfigured"] is True
    assert checks["x402_settlement_path"]["detail"]["payToConfigured"] is False
    assert checks["x402_settlement_path"]["detail"]["perRequestMax"] == "0.01 USDC"
    assert checks["x402_settlement_path"]["detail"]["baseSepoliaSettlementProofVerified"] is False
    assert checks["x402_settlement_path"]["detail"]["settlementByZeroGuardEnabled"] is False
    assert "storage_node_funded_soak" in result["hardGates"]
    assert checks["telegram_state_store"]["detail"]["storeMode"] == "local_json_default"
    assert checks["telegram_state_store"]["detail"]["defaultLocalStore"] is True
    assert result["safety"]["networkCalls"] is False
    assert result["safety"]["transactionSigningEnabled"] is False
    assert result["operatorPromotions"][0]["env"]["ZGG_CHAIN_ID"] == "16661"


def test_production_readiness_detects_mainnet_runtime_env(monkeypatch):
    monkeypatch.setattr(readiness_module, "_production_gate_payloads", _blocked_gate_payloads)
    monkeypatch.setenv("ZGG_CHAIN_RPC", "https://evmrpc.0g.ai")
    monkeypatch.setenv("ZGG_CHAIN_ID", "16661")
    monkeypatch.setenv("ZGG_RECEIPT_CONTRACT", "0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc")

    result = production_readiness()
    checks = {check["id"]: check for check in result["checks"]}

    assert checks["mainnet_verifier_profile"]["status"] == "ok"
    assert checks["mainnet_verifier_profile"]["detail"]["receiptContractConfigured"] is True
    assert result["readiness"] == "production_review"


def test_production_readiness_marks_stale_or_unsupervised_backfill_review(monkeypatch):
    payloads = _green_gate_payloads()
    payloads["reputation_backfill"]["latestAgeSeconds"] = 21601

    monkeypatch.setattr(readiness_module, "_production_gate_payloads", lambda: payloads)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "configured-in-env")
    monkeypatch.setenv("TELEGRAM_WEBHOOK_SECRET_TOKEN", "configured-in-env")
    monkeypatch.setenv("ZGG_CHAIN_RPC", "https://evmrpc.0g.ai")
    monkeypatch.setenv("ZGG_CHAIN_ID", "16661")
    monkeypatch.setenv("ZGG_RECEIPT_CONTRACT", "0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc")

    result = production_readiness()
    checks = {check["id"]: check for check in result["checks"]}

    assert result["readiness"] == "production_review"
    assert checks["reputation_backfill_artifact"]["status"] == "review"
    assert checks["reputation_backfill_artifact"]["detail"]["freshWithinTtl"] is False
    assert "reputation_backfill_artifact" in result["hardGates"]

    payloads["reputation_backfill"]["latestAgeSeconds"] = 30
    payloads["reputation_backfill"]["scheduleManifest"]["supervisorInstalled"] = False

    result = production_readiness()
    checks = {check["id"]: check for check in result["checks"]}

    assert checks["reputation_backfill_artifact"]["status"] == "review"
    assert checks["reputation_backfill_artifact"]["detail"]["freshWithinTtl"] is True
    assert checks["reputation_backfill_artifact"]["detail"]["supervisorInstalled"] is False


def test_production_readiness_prefers_packaged_node_pi_proof(monkeypatch):
    payloads = _blocked_gate_payloads()
    payloads["pi_mesh"]["readiness"] = {
        "clusterReady": False,
        "blockers": ["run_rv_pi_mesh_snapshot"],
    }
    payloads["node_pi_proof"] = {
        "status": "blocked",
        "verified": False,
        "proofPresent": True,
        "recordedAt": "2026-05-20T06:32:58+00:00",
        "blockers": ["connected_peers_below_target_8"],
        "checks": {
            "storageSnapshotPresent": True,
            "storageRpcOk": True,
            "storageProcessRunning": True,
            "storageRelayTcpOpen": True,
            "storagePeerDepthReady": False,
            "storageSyncReady": True,
            "onlyPriorTestFundingObserved": True,
            "hundredOgTransferSent": True,
        },
        "storageNode": {
            "snapshotPresent": True,
            "zgsRunning": True,
            "rpcOk": True,
            "relayTcpOpen": True,
            "connectedPeers": 0,
            "targetPeers": 8,
            "syncGapBlocks": 1,
            "activeMinerBalanceOg": 0.25,
            "onlyPriorTestFundingObserved": True,
            "hundredOgTransferSent": False,
        },
        "peerDiagnostics": {
            "connectedPeers": 0,
            "targetPeers": 8,
            "peerDepthReady": False,
            "hypothesisIds": ["shallow_peer_discovery"],
        },
        "piMesh": {
            "snapshotPresent": True,
            "clusterReady": True,
            "blockers": [],
            "primaryReachable": True,
            "peerEthernetReachable": True,
            "edgeApiReady": True,
        },
        "safety": {"telegramSendsEnabled": False},
    }
    monkeypatch.setattr(readiness_module, "_production_gate_payloads", lambda: payloads)

    result = production_readiness()
    checks = {check["id"]: check for check in result["checks"]}

    assert checks["pi_mesh_cluster"]["status"] == "ok"
    assert checks["pi_mesh_cluster"]["detail"]["mode"] == "node_pi_readiness_proof"
    assert checks["storage_node_funded_soak"]["status"] == "review"
    assert checks["storage_node_funded_soak"]["detail"]["mode"] == "node_pi_readiness_proof"
    assert checks["storage_node_funded_soak"]["detail"]["connectedPeers"] == 0
    assert checks["storage_node_funded_soak"]["detail"]["targetPeers"] == 8
    assert "connected_peers_below_target_8" in checks["storage_node_funded_soak"]["detail"]["blockedBy"]
    assert "pi_mesh_cluster" not in result["hardGates"]
    assert "storage_node_funded_soak" in result["hardGates"]
    assert result["nodePiProofStatus"] == "blocked"


def test_production_readiness_detects_file_backed_telegram_store(monkeypatch, tmp_path):
    monkeypatch.setattr(readiness_module, "_production_gate_payloads", _blocked_gate_payloads)
    monkeypatch.setenv("TELEGRAM_OPT_IN_STORE_PATH", str(tmp_path / "telegram-opt-ins.json"))

    result = production_readiness()
    checks = {check["id"]: check for check in result["checks"]}

    assert checks["telegram_state_store"]["status"] == "ok"
    assert checks["telegram_state_store"]["detail"]["storeMode"] == "local_json"
    assert checks["telegram_state_store"]["detail"]["persistentStoreConfigured"] is True


def test_production_readiness_can_report_green_when_all_hard_gates_are_clear(monkeypatch):
    monkeypatch.setattr(readiness_module, "_production_gate_payloads", _green_gate_payloads)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "configured-in-env")
    monkeypatch.setenv("TELEGRAM_WEBHOOK_SECRET_TOKEN", "configured-in-env")
    monkeypatch.setenv("ZGG_CHAIN_RPC", "https://evmrpc.0g.ai")
    monkeypatch.setenv("ZGG_CHAIN_ID", "16661")
    monkeypatch.setenv("ZGG_RECEIPT_CONTRACT", "0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc")

    result = production_readiness()

    assert result["readiness"] == "production_ready"
    assert result["productionHealthy"] is True
    assert result["hardGates"] == []


def _blocked_gate_payloads() -> dict:
    payloads = _green_gate_payloads()
    payloads["storage"]["readiness"]["largeFundingExpansionReady"] = False
    payloads["storage"]["readiness"]["blockedBy"] = ["connected_peers_below_target_8"]
    payloads["storage"]["sync"]["connectedPeers"] = 2
    payloads["storage"]["sync"]["syncGapBlocks"] = 1
    payloads["storage_upload"]["safety"]["liveStorageUpload"] = False
    payloads["storage_upload"]["safety"]["liveStorageGatewayReadback"] = False
    payloads["storage_upload"]["blockers"] = [
        "live_proof_file_missing",
        "storage_sdk_runtime_not_present",
    ]
    payloads["storage_upload"]["proofBlockers"] = ["live_proof_file_missing"]
    payloads["storage_upload"]["preflightBlockers"] = ["storage_sdk_runtime_not_present"]
    payloads["storage_upload"]["liveProof"] = {
        "status": "missing",
        "verified": False,
        "blockers": ["live_proof_file_missing"],
    }
    payloads["private_compute_smoke"]["status"] = "blocked_before_paid_inference"
    payloads["private_compute_smoke"]["blockers"] = [
        "paid_smoke_proof_file_missing",
        "router_api_key_missing",
    ]
    payloads["private_compute_smoke"]["paidSmokeProof"] = {
        "status": "missing",
        "verified": False,
        "blockers": ["paid_smoke_proof_file_missing"],
        "proofBlockers": ["paid_smoke_proof_file_missing"],
        "preflightBlockers": ["router_api_key_missing"],
        "paidInferencePerformedExternally": False,
        "costUsd": None,
    }
    payloads["private_compute_smoke"]["safety"]["inferenceExecuted"] = False
    payloads["private_compute_smoke"]["safety"]["paidInferenceEnabled"] = False
    payloads["x402_preflight"]["status"] = "payment_required_dry_run"
    payloads["x402_preflight"]["safety"]["x402SettlementEnabled"] = False
    payloads["x402_preflight"]["paymentReadback"]["settlementAttempted"] = False
    payloads["x402_preflight"]["paymentReadback"]["facilitatorCalled"] = False
    payloads["x402_policy"]["paymentRequirement"]["payToConfigured"] = False
    payloads["x402_policy"]["settlementProof"]["verified"] = False
    payloads["x402_policy"]["settlementProof"]["settlementAttempted"] = False
    payloads["x402_policy"]["settlementProof"]["facilitatorCalled"] = False
    payloads["x402_policy"]["settlementProof"]["settlementPerformedExternally"] = False
    payloads["wallet_provider_proof"]["verified"] = False
    payloads["wallet_provider_proof"]["proofPresent"] = True
    payloads["wallet_provider_proof"]["blockers"] = [
        "wallet_provider_external_proof_file_missing",
        "real_wallet_extension_proof_missing",
    ]
    payloads["wallet_provider_proof"]["proofBlockers"] = [
        "wallet_provider_external_proof_file_missing",
        "real_wallet_extension_proof_missing",
    ]
    return payloads


def _green_gate_payloads() -> dict:
    return {
        "storage": {
            "mode": "rv_soak_snapshot_file",
            "readiness": {
                "status": "funded_soak_expansion_ready",
                "processStatus": "running",
                "blockedBy": [],
                "largeFundingExpansionReady": True,
            },
            "sync": {
                "connectedPeers": 8,
                "logSyncHeight": 33532334,
                "latestMainnetBlock": 33532335,
                "syncGapBlocks": 1,
                "nextTxSeq": 105577,
                "dbSizeHuman": "14G",
            },
            "fundedSoak": {
                "onlyPriorTestFundingObserved": True,
                "hundredOgTransferSent": False,
            },
            "fundingSummary": {
                "activeMinerAddress": "0xf5c1c3eb88c262adb451c1ce3b1c391f7d968ecd",
                "activeMinerBalanceOg": 0.25,
                "onlyPriorTestFundingObserved": True,
                "hundredOgTransferSent": False,
                "largeTransferDetected": False,
                "mainnetFundingRecommended": False,
            },
        },
        "pi_mesh": {
            "mode": "rv_pi_mesh_snapshot_file",
            "observedNodes": [{"id": "rvpi-a"}, {"id": "rvpi-b"}],
            "readiness": {"clusterReady": True, "blockers": []},
            "safety": {"telegramSendsEnabled": False},
        },
        "reputation_backfill": {
            "status": "ready",
            "latestRunExists": True,
            "latestAgeSeconds": 30,
            "ttlSeconds": 21600,
            "derivedEvidenceCount": 5,
            "parsedDomainCount": 81444,
            "rawPayloadsReturned": False,
            "scheduleManifest": {"supervisorInstalled": True},
        },
        "storage_upload": {
            "schema": "0guard.0g_storage_upload_manifest.v1",
            "blockers": [],
            "proofBlockers": [],
            "preflightBlockers": [],
            "bundle": {"fileCount": 3},
            "readbackVerifier": {"allMatched": True},
            "liveProof": {"status": "verified", "verified": True, "blockers": []},
            "uploadPlan": {"operatorRequired": True},
            "safety": {
                "liveStorageUpload": True,
                "liveStorageGatewayReadback": True,
            },
        },
        "private_compute_smoke": {
            "status": "paid_smoke_complete",
            "blockers": [],
            "paidSmokeProof": {
                "status": "verified",
                "verified": True,
                "blockers": [],
                "proofBlockers": [],
                "preflightBlockers": [],
                "paidInferencePerformedExternally": True,
                "costUsd": 0.01,
                "safety": {
                    "paidInferenceByZeroGuard": False,
                    "rawPromptReturned": False,
                    "rawResponseReturned": False,
                },
            },
            "router": {
                "apiKeyConfigured": True,
                "paidInferenceAllowedByEnv": True,
                "budgetUsd": 1.0,
            },
            "routerContract": {
                "schema": "0guard.0g_private_compute_router_contract.v1",
                "chatCompletionsUrl": "https://router-api.0g.ai/v1/chat/completions",
                "budgetGate": {
                    "paidInferenceGateEnv": "ZG_ALLOW_PAID_INFERENCE",
                    "budgetEnv": "ZG_0G_INFERENCE_BUDGET_USD",
                },
                "billing": {"routerTraceField": "x_0g_trace.billing.total_cost"},
            },
            "safety": {
                "inferenceExecuted": True,
                "paidInferenceEnabled": True,
                "promptSafeForInference": True,
            },
        },
        "x402_preflight": {
            "status": "payment_fixture_accepted_no_settlement",
            "httpStatus": 200,
            "safety": {"x402SettlementEnabled": False},
            "paymentReadback": {
                "settlementAttempted": False,
                "facilitatorCalled": False,
            },
            "rightsPolicy": {"rawPayloadResaleAllowed": False},
        },
        "x402_policy": {
            "schema": "0guard.x402_settlement_policy.v1",
            "status": "testnet_settlement_proof_recorded",
            "spendCaps": {"perRequestMaxDisplay": "0.01 USDC"},
            "terms": {"rawPayloadResaleAllowed": False},
            "paymentRequirement": {"payToConfigured": True},
            "settlementProof": {
                "status": "verified",
                "verified": True,
                "settlementAttempted": True,
                "facilitatorCalled": True,
                "settlementPerformedExternally": True,
            },
            "safety": {
                "x402SettlementEnabled": False,
                "settlementByZeroGuardEnabled": False,
            },
        },
        "wallet_provider_proof": {
            "schema": "0guard.wallet_provider_external_proof_verification.v1",
            "status": "verified",
            "verified": True,
            "proofPresent": True,
            "suggestedExternalProofUrl": "https://arigatoexpress.github.io/0guard/wallet-provider-proof/",
            "requiresRealWalletExtension": True,
            "requiresWindowEthereum": True,
            "requiresThrowawayEmptyWallet": True,
            "receiptHashPolicy": (
                "Each receipt hash must be a real 64-hex SHA-256 verdict hash from the "
                "hosted capture flow; repeated-character placeholder hashes are rejected."
            ),
            "placeholderReceiptHashesRejected": True,
            "blockers": [],
            "proofBlockers": [],
            "proofMode": "real_wallet_extension_window_ethereum",
            "externalDappOrigin": "http://127.0.0.1:8142",
            "windowEthereumPresent": True,
            "realWalletExtension": True,
            "mockProvider": False,
            "throwawayWallet": True,
            "walletWasEmpty": True,
            "readOnlyRequest": {"forwardedToProvider": True},
            "reviewRequest": {"forwardedToProvider": False},
            "denyRequest": {"forwardedToProvider": False},
            "safety": {
                "rawParamsReturned": False,
                "privateKeysReturned": False,
            },
        },
    }
