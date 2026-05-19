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
    assert checks["telegram_state_store"]["status"] == "ok"
    assert checks["storage_node_funded_soak"]["status"] == "review"
    assert checks["telegram_live_identity"]["status"] == "review"
    assert checks["private_compute_paid_smoke"]["status"] == "review"
    assert checks["x402_settlement_path"]["status"] == "review"
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
    payloads["private_compute_smoke"]["status"] = "blocked_before_paid_inference"
    payloads["private_compute_smoke"]["blockers"] = ["router_api_key_missing"]
    payloads["private_compute_smoke"]["safety"]["inferenceExecuted"] = False
    payloads["private_compute_smoke"]["safety"]["paidInferenceEnabled"] = False
    payloads["x402_preflight"]["status"] = "payment_required_dry_run"
    payloads["x402_preflight"]["safety"]["x402SettlementEnabled"] = False
    payloads["x402_preflight"]["paymentReadback"]["settlementAttempted"] = False
    payloads["x402_preflight"]["paymentReadback"]["facilitatorCalled"] = False
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
            "bundle": {"fileCount": 3},
            "readbackVerifier": {"allMatched": True},
            "uploadPlan": {"operatorRequired": True},
            "safety": {
                "liveStorageUpload": True,
                "liveStorageGatewayReadback": True,
            },
        },
        "private_compute_smoke": {
            "status": "paid_smoke_complete",
            "blockers": [],
            "router": {
                "apiKeyConfigured": True,
                "paidInferenceAllowedByEnv": True,
                "budgetUsd": 1.0,
            },
            "safety": {
                "inferenceExecuted": True,
                "paidInferenceEnabled": True,
                "promptSafeForInference": True,
            },
        },
        "x402_preflight": {
            "status": "settled",
            "httpStatus": 200,
            "safety": {"x402SettlementEnabled": True},
            "paymentReadback": {
                "settlementAttempted": True,
                "facilitatorCalled": True,
            },
            "rightsPolicy": {"rawPayloadResaleAllowed": False},
        },
    }
