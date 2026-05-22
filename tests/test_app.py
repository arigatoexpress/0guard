"""Smoke tests for Flask app."""

import hashlib
import hmac
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlencode

import pytest

import guard0.app as app_module
from guard0.app import app
from guard0.telegram_bot import validate_webapp_init_data as real_validate_webapp_init_data

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app_module._PENDING_TELEGRAM_CHALLENGES.clear()
    app_module._CONSUMED_TELEGRAM_TOKEN_IDS.clear()
    app_module._TELEGRAM_OPT_IN_RECORDS.clear()
    app_module._TELEGRAM_STORE_LOADED_PATH = None
    with app.test_client() as c:
        yield c


def signed_telegram_init_data(fields: dict[str, str], bot_token: str) -> str:
    data_check_string = "\n".join(f"{key}={fields[key]}" for key in sorted(fields))
    secret_key = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    signature = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    return urlencode({**fields, "hash": signature})


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    data = r.get_json()
    assert data["service"] == "zg-hack-guard"
    assert data["read_only"] is True
    assert data["telegram_sends_enabled"] is False
    assert data["money_movement_enabled"] is False
    assert data["safety_flags"]["external_sends_blocked_from_workbench"] is True
    assert data["safety_flags"]["money_movement_enabled"] is False
    assert data["telegram_mira"]["safety"]["telegramSendsEnabled"] is False
    assert data["0g_da_node"]["schema"] == "0guard.0g_da_node_status.v1"
    assert data["0g_da_node"]["readiness"]["status"] == "blocked"
    assert data["0g_da_node"]["readiness"]["blockedBy"] == ["signer_balance_not_checked"]
    assert data["0g_da_node"]["readiness"]["fundingReady"] is False
    assert data["0g_da_node"]["safety"]["telegramSendsEnabled"] is False
    assert data["0g_storage_node_status"]["schema"] == "0guard.0g_storage_node_status.v1"
    assert data["0g_storage_node_status"]["readiness"]["status"] == "blocked"
    assert data["0g_storage_node_status"]["readiness"]["mainnetFundingReady"] is False
    assert data["0g_storage_node_status"]["safety"]["moneyMovementEnabled"] is False
    assert data["0g_node_business"]["schema"] == "0guard.0g_node_business.v1"
    assert data["0g_node_business"]["safety"]["moneyMovementEnabled"] is False
    assert data["0g_private_computer"]["schema"] == "0guard.0g_private_computer_integration.v1"
    assert data["0g_private_computer"]["safety"]["transactionBroadcastingEnabled"] is False
    assert data["local_inference_mesh"]["schema"] == "0guard.local_inference_mesh.v1"
    assert data["local_inference_mesh"]["safety"]["promptExecutionEnabled"] is False
    assert data["x402_data_products"]["schema"] == "0guard.x402_data_products.v1"
    assert data["x402_data_products"]["safety"]["x402SettlementEnabled"] is False
    assert data["x402_settlement_policy"]["schema"] == "0guard.x402_settlement_policy.v1"
    assert data["x402_settlement_policy"]["safety"]["x402SettlementEnabled"] is False
    assert data["historical_backfill_plan"]["schema"] == "0guard.historical_backfill_plan.v1"
    assert data["historical_feature_store"]["schema"] == "0guard.historical_feature_store.v1"
    assert data["historical_feature_store"]["safety"]["rawPayloadsReturned"] is False
    assert data["production_gaps"]["schema"] == "0guard.production_gap_matrix.v1"
    assert data["production_gaps"]["productionReady"] is False
    assert data["production_gaps"]["safety"]["moneyMovementEnabled"] is False
    assert data["model_training_roadmap"]["schema"] == "0guard.model_training_roadmap.v1"
    assert data["model_training_roadmap"]["safety"]["trainingRunStarted"] is False
    assert data["incident_eval_set"]["schema"] == "0guard.incident_detector_eval_set.v1"
    assert data["incident_eval_set"]["caseCount"] == 3
    assert data["0g_hot_wallet_resources"]["schema"] == "0guard.0g_hot_wallet_resources.v1"
    assert data["0g_hot_wallet_resources"]["safety"]["moneyMovementEnabled"] is False
    assert data["peer_protection"]["schema"] == "0guard.peer_protection_plan.v1"
    assert data["peer_protection"]["safety"]["externalMessagesEnabled"] is False
    assert data["pi_mesh"]["schema"] == "0guard.pi_mesh_plan.v1"
    assert data["0g_chain_id"] == 16661
    assert data["0g_chain_rpc"] == "https://evmrpc.0g.ai"
    assert data["0g_receipt_contract"] == "0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc"


def test_healthz_aliases(client):
    for path in ("/healthz", "/healthz/", "/api/healthz"):
        r = client.get(path)
        assert r.status_code == 200
        data = r.get_json()
        assert data["schema"] == "0guard.healthz.v1"
        assert data["ok"] is True
        assert data["service"] == "zg-hack-guard"
        assert data["read_only"] is True
        assert data["telegram_sends_enabled"] is False
        assert data["money_movement_enabled"] is False
        assert data["safety_flags"]["telegram_sends_enabled"] is False
        assert data["safety_flags"]["money_movement_enabled"] is False


def test_deployment_readiness_route_is_read_only(client):
    r = client.get("/api/deployment/readiness")
    assert r.status_code == 200
    data = r.get_json()
    assert data["schema"] == "0guard.deployment_readiness.v1"
    assert data["safety"]["readOnly"] is True
    assert data["safety"]["networkCalls"] is False
    assert data["safety"]["transactionSigningEnabled"] is False
    assert data["safety"]["moneyMovementEnabled"] is False
    assert any(gate["id"] == "clean_revision_for_app_deploy" for gate in data["promotionGates"])


def test_module_entrypoint_honors_container_host_env(monkeypatch):
    run_args = {}

    def fake_run(**kwargs):
        run_args.update(kwargs)

    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("PORT", "8110")
    monkeypatch.setattr(app_module.app, "run", fake_run)

    app_module.main()

    assert run_args == {"host": "0.0.0.0", "port": 8110, "debug": False}


def test_frontend_contract_is_browser_smoke_ready_and_non_mutating(client):
    r = client.get("/api/frontend-contract")
    assert r.status_code == 200
    data = r.get_json()
    assert data["schema"] == "0guard.frontend_contract.v1"
    assert data["route"] == "/"
    assert data["mode"] == "read_only_pre_wallet"
    assert data["safety"]["workbenchCanTriggerLiveActions"] is False
    assert data["safety"]["livePostingEnabled"] is False
    assert data["safety"]["telegramSendsEnabled"] is False
    assert data["safety"]["transactionSigningEnabled"] is False
    assert data["safety"]["moneyMovementEnabled"] is False
    assert "/api/external-action-contracts" in data["apiRoutes"]
    assert "/api/0g/status" in data["apiRoutes"]
    assert "/api/0g/da-node/status" in data["apiRoutes"]
    assert "/api/0g/storage-node/status" in data["apiRoutes"]
    assert "/api/0g/storage-node/peer-diagnostics" in data["apiRoutes"]
    assert "/api/0g/node-pi-readiness-proof" in data["apiRoutes"]
    assert "/api/0g/storage-upload/manifest" in data["apiRoutes"]
    assert "/api/0g/alignment-node/status" in data["apiRoutes"]
    assert "/api/0g/validator-capacity" in data["apiRoutes"]
    assert "/api/0g/node-business" in data["apiRoutes"]
    assert "/api/0g/private-computer" in data["apiRoutes"]
    assert "/api/0g/private-computer/smoke-preview" in data["apiRoutes"]
    assert "/api/0g/private-computer/smoke-proof" in data["apiRoutes"]
    assert "/api/local-inference/status" in data["apiRoutes"]
    assert "/api/telegram/local-inference-preview" in data["apiRoutes"]
    assert "/api/0g/hot-wallet-resources" in data["apiRoutes"]
    assert "/api/0g/peer-protection" in data["apiRoutes"]
    assert "/api/0g/pi-mesh" in data["apiRoutes"]
    assert "/api/peer/outreach-preview" in data["apiRoutes"]
    assert "/api/0g/receipt" in data["apiRoutes"]
    assert "/api/0g/proof-ladder" in data["apiRoutes"]
    assert "/api/data/summary" in data["apiRoutes"]
    assert "/api/data/incidents" in data["apiRoutes"]
    assert "/api/data/provenance" in data["apiRoutes"]
    assert "/api/data/detection-coverage" in data["apiRoutes"]
    assert "/api/data/signature-map" in data["apiRoutes"]
    assert "/api/data/backfill-plan" in data["apiRoutes"]
    assert "/api/data/historical-feature-store" in data["apiRoutes"]
    assert "/api/osint/sources" in data["apiRoutes"]
    assert "/api/osint/readiness" in data["apiRoutes"]
    assert "/api/osint/signals" in data["apiRoutes"]
    assert "/api/intelligence/evolving" in data["apiRoutes"]
    assert "/api/intelligence/cyber-threats" in data["apiRoutes"]
    assert "/api/intelligence/data-streams" in data["apiRoutes"]
    assert "/api/x402/data-products" in data["apiRoutes"]
    assert "/api/x402/dry-run/wallet-preflight" in data["apiRoutes"]
    assert "/api/x402/settlement-policy" in data["apiRoutes"]
    assert "/x402/v1/wallet-preflight" in data["apiRoutes"]
    assert "/api/intelligence/detector-candidates" in data["apiRoutes"]
    assert "/api/product/brief" in data["apiRoutes"]
    assert "/api/product/strategy-review" in data["apiRoutes"]
    assert "/api/deployment/readiness" in data["apiRoutes"]
    assert "/api/production/gaps" in data["apiRoutes"]
    assert "/api/production-gaps" in data["apiRoutes"]
    assert "/api/model/training-roadmap" in data["apiRoutes"]
    assert "/api/model/incident-eval-set" in data["apiRoutes"]
    assert "/api/readyz" in data["apiRoutes"]
    assert "/api/healthz" in data["apiRoutes"]
    assert "/api/roadmap" in data["apiRoutes"]
    assert "/api/experiments/frontier" in data["apiRoutes"]
    assert "/api/experiments/run" in data["apiRoutes"]
    assert "/api/threat-case-file" in data["apiRoutes"]
    assert "/api/wallet/alert-preview" in data["apiRoutes"]
    assert "/api/wallet/provider-guard" in data["apiRoutes"]
    assert "/api/wallet/provider-proof" in data["apiRoutes"]
    assert "/api/ton/status" in data["apiRoutes"]
    assert "/api/ton/risk-rules" in data["apiRoutes"]
    assert "/api/ton/wallet-risk-preview" in data["apiRoutes"]
    assert "/tonconnect-manifest.json" in data["apiRoutes"]
    assert "/api/integrations/cross-chain" in data["apiRoutes"]
    assert "/api/integrations/cross-chain/readiness" in data["apiRoutes"]
    assert "/api/integrations/virtuals-facilitator" in data["apiRoutes"]
    assert "/api/integrations/ika" in data["apiRoutes"]
    assert "/api/integrations/ika/evaluate" in data["apiRoutes"]
    assert "/api/reputation/probe" in data["apiRoutes"]
    assert "/api/reputation/connectors" in data["apiRoutes"]
    assert "/api/reputation/connectors/live" in data["apiRoutes"]
    assert "/api/reputation/backfill/status" in data["apiRoutes"]
    assert "/api/reputation/adapters" in data["apiRoutes"]
    assert "/api/reputation/adapters/normalize" in data["apiRoutes"]
    assert "/api/reputation/shadow-cache" in data["apiRoutes"]
    assert "/api/native-preflight" in data["apiRoutes"]
    assert "/api/hackathon/strategy" in data["apiRoutes"]
    assert "/api/developer-kit" in data["apiRoutes"]
    assert "/api/integrations/external-guardrails" in data["apiRoutes"]
    assert "/api/integrations/external-guardrails/evaluate" in data["apiRoutes"]
    assert "/api/hackathon/submission-brief" in data["apiRoutes"]
    assert "/api/hackathon/submission-packet" in data["apiRoutes"]
    assert "/api/hackathon/readiness" in data["apiRoutes"]
    assert "/api/hackathon/threat-passport" in data["apiRoutes"]
    assert "/api/telegram/status" in data["apiRoutes"]
    assert "/api/telegram/webapp/verify" in data["apiRoutes"]
    assert "/api/telegram/miniapp/contract" in data["apiRoutes"]
    assert "/api/telegram/miniapp/session" in data["apiRoutes"]
    assert "/api/telegram/miniapp/preview" in data["apiRoutes"]
    assert "/api/telegram/miniapp/ton-preview" in data["apiRoutes"]
    assert "/api/telegram/mira-preview" in data["apiRoutes"]
    assert "/api/telegram/wallet-alert-preview" in data["apiRoutes"]
    assert "/api/telegram/da-node-preview" in data["apiRoutes"]
    assert "/api/telegram/storage-node-preview" in data["apiRoutes"]
    assert "/api/telegram/node-business-preview" in data["apiRoutes"]
    assert "/api/mira/claim-preview" in data["apiRoutes"]
    assert "#run-evaluate" in data["requiredSelectors"]
    assert "#run-threat-case-file" in data["requiredSelectors"]
    assert "#play-story" in data["requiredSelectors"]
    assert "#flow-canvas" in data["requiredSelectors"]
    assert "#plain-explanation" in data["requiredSelectors"]
    assert "#technical-output" in data["requiredSelectors"]
    assert "#risk-list" in data["requiredSelectors"]
    assert "#load-phishdestroy-worker" in data["requiredSelectors"]
    assert "#load-detector-candidates" in data["requiredSelectors"]
    assert "#contract-output" in data["requiredSelectors"]
    assert "#case-file-output" in data["requiredSelectors"]
    assert "#zg-status-output" in data["requiredSelectors"]
    assert "#verify-receipt-hash" in data["requiredSelectors"]
    assert "#verify-receipt" in data["requiredSelectors"]
    assert "#data-flow-output" in data["requiredSelectors"]
    assert "#provenance-summary" in data["requiredSelectors"]
    assert "#load-provenance-matrix" in data["requiredSelectors"]
    assert "#load-live-provenance" in data["requiredSelectors"]
    assert "#osint-output" in data["requiredSelectors"]
    assert "#load-evolving-intel" in data["requiredSelectors"]
    assert "#load-cyber-threat-repository" in data["requiredSelectors"]
    assert "#load-intelligence-stream-plan" in data["requiredSelectors"]
    assert "#load-product-brief" in data["requiredSelectors"]
    assert "#load-production-readiness" in data["requiredSelectors"]
    assert "#load-deployment-readiness" in data["requiredSelectors"]
    assert "#load-production-gaps" in data["requiredSelectors"]
    assert "#load-model-training-roadmap" in data["requiredSelectors"]
    assert "#load-incident-eval-set" in data["requiredSelectors"]
    assert "#load-ecosystem-roadmap" in data["requiredSelectors"]
    assert "#load-frontier-experiments" in data["requiredSelectors"]
    assert "#load-submission-packet" in data["requiredSelectors"]
    assert "#load-submission-readiness" in data["requiredSelectors"]
    assert "#load-threat-passport" in data["requiredSelectors"]
    assert "#load-cross-chain-catalog" in data["requiredSelectors"]
    assert "#load-cross-chain-readiness" in data["requiredSelectors"]
    assert "#load-virtuals-facilitator" in data["requiredSelectors"]
    assert "#load-ika-integration" in data["requiredSelectors"]
    assert "#run-reputation-probe" in data["requiredSelectors"]
    assert "#load-reputation-backfill-status" in data["requiredSelectors"]
    assert "#load-reputation-adapters" in data["requiredSelectors"]
    assert "#load-reputation-shadow-cache" in data["requiredSelectors"]
    assert "#run-native-preflight" in data["requiredSelectors"]
    assert "#load-hackathon-strategy" in data["requiredSelectors"]
    assert "#load-developer-kit" in data["requiredSelectors"]
    assert "#load-external-guardrails" in data["requiredSelectors"]
    assert "#run-external-guardrail-check" in data["requiredSelectors"]
    assert "#cross-chain-output" in data["requiredSelectors"]
    assert "#load-da-node-status" in data["requiredSelectors"]
    assert "#load-storage-node-status" in data["requiredSelectors"]
    assert "#load-storage-upload-manifest" in data["requiredSelectors"]
    assert "#run-telegram-da-node-preview" in data["requiredSelectors"]
    assert "#load-node-business" in data["requiredSelectors"]
    assert "#load-alignment-node-status" in data["requiredSelectors"]
    assert "#load-validator-capacity" in data["requiredSelectors"]
    assert "#load-private-computer" in data["requiredSelectors"]
    assert "#load-private-compute-smoke-preview" in data["requiredSelectors"]
    assert "#load-local-inference" in data["requiredSelectors"]
    assert "#run-telegram-local-inference-preview" in data["requiredSelectors"]
    assert "#load-hot-wallet-resources" in data["requiredSelectors"]
    assert "#load-peer-protection" in data["requiredSelectors"]
    assert "#run-peer-outreach-preview" in data["requiredSelectors"]
    assert "#load-pi-mesh" in data["requiredSelectors"]
    assert "#run-telegram-node-business-preview" in data["requiredSelectors"]
    assert "#load-historical-backfill-plan" in data["requiredSelectors"]
    assert "#load-historical-feature-store" in data["requiredSelectors"]
    assert "#load-x402-data-products" in data["requiredSelectors"]
    assert "#load-x402-dry-run" in data["requiredSelectors"]
    assert "#load-x402-settlement-policy" in data["requiredSelectors"]
    assert "#da-node-output" in data["requiredSelectors"]
    assert "#telegram-register-output" in data["requiredSelectors"]
    assert "#mira-output" in data["requiredSelectors"]
    assert "#wallet-address-input" in data["requiredSelectors"]
    assert "#run-wallet-alert-preview" in data["requiredSelectors"]
    assert "#run-telegram-wallet-alert-preview" in data["requiredSelectors"]
    assert "#run-wallet-provider-guard" in data["requiredSelectors"]
    assert "#wallet-alert-output" in data["requiredSelectors"]
    assert "#open-telegram-miniapp" in data["requiredSelectors"]


def test_frontend_contract_selectors_match_static_shell(client):
    contract = client.get("/api/frontend-contract").get_json()
    html = client.get("/").get_data(as_text=True)
    for selector in contract["requiredSelectors"]:
        assert f'id="{selector.removeprefix("#")}"' in html
    for expected_text in contract["requiredText"]:
        assert expected_text in html
    assert 'href="/static/styles.css"' in html
    assert 'src="/static/app.js"' in html


def test_frontend_uses_packaged_template_and_static_assets():
    package_root = REPO_ROOT / "src" / "guard0"
    source = (package_root / "app.py").read_text()
    assert "render_template_string" not in source
    assert "HTML_DASHBOARD" not in source
    assert (package_root / "templates" / "index.html").read_text().startswith("<!doctype html>")
    assert (package_root / "templates" / "telegram_mini_app.html").read_text().startswith(
        "<!doctype html>"
    )
    assert (package_root / "templates" / "wallet_provider_demo.html").read_text().startswith(
        "<!doctype html>"
    )
    assert "run-evaluate" in (package_root / "static" / "app.js").read_text()
    assert "loadProductBrief" in (package_root / "static" / "app.js").read_text()
    assert "runThreatCaseFile" in (package_root / "static" / "app.js").read_text()
    assert "runWalletProviderGuard" in (package_root / "static" / "app.js").read_text()
    assert "loadFrontierExperiments" in (package_root / "static" / "app.js").read_text()
    assert "loadReputationAdapters" in (package_root / "static" / "app.js").read_text()
    assert "loadPeerProtection" in (package_root / "static" / "app.js").read_text()
    assert "loadHotWalletResources" in (package_root / "static" / "app.js").read_text()
    assert "loadLocalInference" in (package_root / "static" / "app.js").read_text()
    assert "loadX402DataProducts" in (package_root / "static" / "app.js").read_text()
    assert "loadDeploymentReadiness" in (package_root / "static" / "app.js").read_text()
    assert "loadProductionGaps" in (package_root / "static" / "app.js").read_text()
    assert "loadModelTrainingRoadmap" in (package_root / "static" / "app.js").read_text()
    assert "loadIncidentEvalSet" in (package_root / "static" / "app.js").read_text()
    assert "runPeerOutreachPreview" in (package_root / "static" / "app.js").read_text()
    assert "miniappRunPreview" in (package_root / "static" / "telegram-miniapp.js").read_text()
    assert "create0guardProvider" in (
        package_root / "static" / "wallet-provider-guard-client.js"
    ).read_text()
    assert "providerCalls.push" in (
        package_root / "static" / "wallet-provider-demo.js"
    ).read_text()
    assert "miniapp-evidence-panel" in (
        package_root / "templates" / "telegram_mini_app.html"
    ).read_text()
    assert ".shell" in (package_root / "static" / "styles.css").read_text()


def test_wallet_provider_demo_shell_is_packaged_and_non_custodial(client):
    response = client.get("/demo/wallet-provider-guard")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Wallet Provider Guard" in html
    assert 'id="demo-read-chain"' in html
    assert 'id="demo-switch-chain"' in html
    assert 'id="demo-unlimited-approval"' in html
    assert 'id="provider-demo-call-count"' in html
    assert 'src="/static/wallet-provider-demo.js"' in html
    assert 'href="/"' in html


def test_telegram_miniapp_shell_contract_and_static_assets(client):
    contract_response = client.get("/api/telegram/miniapp/contract")
    assert contract_response.status_code == 200
    contract = contract_response.get_json()
    assert contract["schema"] == "0guard.telegram_miniapp_contract.v1"
    assert contract["route"] == "/telegram"
    assert contract["telegramApi"]["usesTelegramWebAppJs"] is True
    assert contract["telegramApi"]["serverSideValidationRequired"] is True
    assert contract["telegramApi"]["sendDataUsed"] is False
    assert contract["safety"]["telegramSendsEnabled"] is False
    assert "/api/telegram/miniapp/session" in contract["apiRoutes"]
    assert "/api/telegram/miniapp/preview" in contract["apiRoutes"]
    assert "/api/telegram/miniapp/ton-preview" in contract["apiRoutes"]
    assert "/api/ton/wallet-risk-preview" in contract["apiRoutes"]
    assert "#miniapp-evidence-panel" in contract["requiredSelectors"]
    assert "#miniapp-evidence-receipt" in contract["requiredSelectors"]

    html = client.get("/telegram").get_data(as_text=True)
    for selector in contract["requiredSelectors"]:
        assert f'id="{selector.removeprefix("#")}"' in html
    for expected_text in contract["requiredText"]:
        assert expected_text in html
    assert "https://telegram.org/js/telegram-web-app.js" in html
    assert 'src="/static/telegram-miniapp.js"' in html


def test_external_action_contracts_keep_live_paths_out_of_workbench(client):
    r = client.get("/api/external-action-contracts")
    assert r.status_code == 200
    data = r.get_json()
    assert data["defaultMode"] == "dry_run"
    assert data["workbenchCanTriggerLiveActions"] is False
    by_id = {item["id"]: item for item in data["actions"]}
    assert by_id["x-post"]["liveConfirmationFlag"] == "--live-post-confirm POST_TO_X_FROM_0GUARD"
    assert (
        by_id["telegram-post"]["liveConfirmationFlag"]
        == "--live-send-confirm SEND_TO_TELEGRAM_FROM_0GUARD"
    )
    assert by_id["0g-contract-deploy"]["reachableFromWorkbench"] is False
    assert by_id["0g-peer-chain-message"]["reachableFromWorkbench"] is False
    assert by_id["0g-peer-chain-message"]["default"] == "draft_only"


def test_peer_protection_routes_are_no_send_and_no_broadcast(client):
    storage_manifest = client.get("/api/0g/storage-upload/manifest")
    assert storage_manifest.status_code == 200
    storage_manifest_body = storage_manifest.get_json()
    assert storage_manifest_body["schema"] == "0guard.0g_storage_upload_manifest.v1"
    assert storage_manifest_body["status"] == "pending_live_upload_readback"
    assert storage_manifest_body["verified"] is False
    assert storage_manifest_body["proofPresent"] is False
    assert storage_manifest_body["bundleFileCount"] == storage_manifest_body["bundle"]["fileCount"]
    assert storage_manifest_body["bundleRoot"] == storage_manifest_body["bundle"]["bundleRoot"]
    assert storage_manifest_body["uploadPlan"]["liveUploadPerformed"] is False
    assert storage_manifest_body["readbackVerifier"]["liveStorageGatewayReadback"] is False
    assert storage_manifest_body["safety"]["moneyMovementEnabled"] is False

    private_computer = client.get("/api/0g/private-computer")
    assert private_computer.status_code == 200
    private_body = private_computer.get_json()
    assert private_body["schema"] == "0guard.0g_private_computer_integration.v1"
    assert private_body["api"]["openAiCompatible"] is True
    assert private_body["safety"]["transactionBroadcastingEnabled"] is False

    private_smoke = client.post(
        "/api/0g/private-computer/smoke-preview",
        json={"prompt": "Summarize this deterministic ZeroGuard review packet."},
    )
    assert private_smoke.status_code == 200
    private_smoke_body = private_smoke.get_json()
    assert private_smoke_body["schema"] == "0guard.0g_private_compute_smoke_preview.v1"
    assert private_smoke_body["sampleRequest"]["inferenceExecuted"] is False
    assert private_smoke_body["router"]["apiKeyReturned"] is False
    assert private_smoke_body["routerContract"]["openAiCompatible"] is True
    assert private_smoke_body["routerContract"]["auth"]["apiKeyReturned"] is False
    assert private_smoke_body["routerContract"]["auth"]["serverSideOnly"] is True
    assert private_smoke_body["routerContract"]["budgetGate"]["budgetEnv"] == (
        "ZG_0G_INFERENCE_BUDGET_USD"
    )
    assert private_smoke_body["paidSmokeProof"]["status"] == "missing"
    assert private_smoke_body["operatorProofPacket"]["status"] == (
        "ready_for_external_paid_smoke_proof"
    )
    assert private_smoke_body["operatorProofPacket"]["apiKeyStoredInProof"] is False
    assert private_smoke_body["safety"]["networkCalls"] is False
    assert private_smoke_body["safety"]["transactionSigningEnabled"] is False

    private_smoke_proof = client.get("/api/0g/private-computer/smoke-proof")
    assert private_smoke_proof.status_code == 200
    private_smoke_proof_body = private_smoke_proof.get_json()
    assert (
        private_smoke_proof_body["schema"]
        == "0guard.0g_private_compute_paid_smoke_proof_verification.v1"
    )
    assert private_smoke_proof_body["status"] == "missing"
    assert private_smoke_proof_body["verified"] is False
    assert (
        "record_0g_private_compute_paid_smoke.py"
        in private_smoke_proof_body["recordProofCommandTemplate"]
    )
    assert private_smoke_proof_body["routerContract"]["auth"]["browserUseAllowed"] is False
    assert (
        private_smoke_proof_body["routerContract"]["proofRequirements"]["recordResponseHash"]
        is True
    )
    assert private_smoke_proof_body["operatorProofPacket"]["rawPromptRequired"] is False
    assert private_smoke_proof_body["safety"]["proofVerificationOnly"] is True
    assert private_smoke_proof_body["safety"]["paidInferenceByZeroGuard"] is False
    assert private_smoke_proof_body["safety"]["apiKeyReturned"] is False

    hot_wallets = client.get("/api/0g/hot-wallet-resources")
    assert hot_wallets.status_code == 200
    hot_wallet_body = hot_wallets.get_json()
    assert hot_wallet_body["schema"] == "0guard.0g_hot_wallet_resources.v1"
    assert hot_wallet_body["preparedResources"][1]["requiresFinalConfirmation"] is True
    assert hot_wallet_body["safety"]["moneyMovementEnabled"] is False

    peer_plan = client.get("/api/0g/peer-protection")
    assert peer_plan.status_code == 200
    peer_body = peer_plan.get_json()
    assert peer_body["schema"] == "0guard.peer_protection_plan.v1"
    assert peer_body["peerContactModel"]["publicPeersExposeContactInfo"] is False

    pi_mesh = client.get("/api/0g/pi-mesh")
    assert pi_mesh.status_code == 200
    assert pi_mesh.get_json()["schema"] == "0guard.pi_mesh_plan.v1"

    preview = client.post(
        "/api/peer/outreach-preview",
        json={
            "channel": "onchain_message_hash_draft",
            "contact": {
                "evmAddress": "0x000000000000000000000000000000000000dEaD",
                "optInConfirmed": False,
            },
        },
    )
    assert preview.status_code == 200
    preview_body = preview.get_json()
    assert preview_body["decision"] == "blocked_preview_only"
    assert preview_body["telegram_send"] is False
    assert preview_body["blockchain_broadcast"] is False
    assert preview_body["onchainEnvelope"]["calldata"] is None


def test_local_inference_x402_and_backfill_routes_are_no_side_effect(client):
    local = client.get("/api/local-inference/status")
    assert local.status_code == 200
    local_body = local.get_json()
    assert local_body["schema"] == "0guard.local_inference_mesh.v1"
    assert local_body["safety"]["promptExecutionEnabled"] is False
    assert local_body["safety"]["telegramSendsEnabled"] is False

    telegram_preview = client.get("/api/telegram/local-inference-preview")
    assert telegram_preview.status_code == 200
    preview_body = telegram_preview.get_json()
    assert preview_body["schema"] == "0guard.telegram_local_inference_preview.v1"
    assert preview_body["telegram_send"] is False
    assert preview_body["safety"]["promptExecutionEnabled"] is False

    x402 = client.get("/api/x402/data-products")
    assert x402.status_code == 200
    x402_body = x402.get_json()
    assert x402_body["schema"] == "0guard.x402_data_products.v1"
    assert x402_body["safety"]["x402SettlementEnabled"] is False
    assert all(item["rawPayloadResaleAllowed"] is False for item in x402_body["products"])

    x402_dry_run = client.get("/api/x402/dry-run/wallet-preflight")
    assert x402_dry_run.status_code == 402
    x402_dry_run_body = x402_dry_run.get_json()
    assert x402_dry_run_body["schema"] == "0guard.x402_wallet_preflight_dry_run.v1"
    assert x402_dry_run_body["paymentReadback"]["facilitatorCalled"] is False
    assert x402_dry_run_body["safety"]["x402SettlementEnabled"] is False
    assert x402_dry_run_body["rightsPolicy"]["rawPayloadResaleAllowed"] is False

    x402_fixture = client.post(
        "/api/x402/dry-run/wallet-preflight",
        headers={"X-PAYMENT": "fixture-paid-zeroguard-wallet-preflight-v1"},
        json={"target": "0x02228b0afcdbEdf8180D96Fc181Da3AF5DD1d1ab"},
    )
    assert x402_fixture.status_code == 200
    x402_fixture_body = x402_fixture.get_json()
    assert x402_fixture_body["status"] == "payment_fixture_accepted_no_settlement"
    assert x402_fixture_body["paymentReadback"]["settlementAttempted"] is False
    assert x402_fixture_body["productResponse"]["rawPayloadResaleAllowed"] is False

    x402_live_disabled = client.get("/x402/v1/wallet-preflight")
    assert x402_live_disabled.status_code == 503
    live_disabled_body = x402_live_disabled.get_json()
    assert live_disabled_body["schema"] == "0guard.x402_live_wallet_preflight_disabled.v1"
    assert live_disabled_body["status"] == "settlement_disabled"
    assert live_disabled_body["safety"]["x402SettlementEnabled"] is False
    assert live_disabled_body["safety"]["paymentHeaderStored"] is False

    x402_policy = client.get("/api/x402/settlement-policy")
    assert x402_policy.status_code == 200
    x402_policy_body = x402_policy.get_json()
    assert x402_policy_body["schema"] == "0guard.x402_settlement_policy.v1"
    assert x402_policy_body["spendCaps"]["perRequestMaxDisplay"] == "0.01 USDC"
    assert x402_policy_body["terms"]["rawPayloadResaleAllowed"] is False
    assert x402_policy_body["settlementProofStatus"] == "verified"
    assert x402_policy_body["settlementProofVerified"] is True
    assert x402_policy_body["operatorProofPacket"]["paymentHeaderHashRequired"] is True
    assert x402_policy_body["operatorProofPacket"]["rawPaymentHeaderStored"] is False
    assert (
        "record_x402_base_sepolia_settlement_proof.py"
        in x402_policy_body["operatorProofPacket"]["recordProofCommandTemplate"]
    )
    assert x402_policy_body["safety"]["x402SettlementEnabled"] is False

    backfill = client.get("/api/data/backfill-plan")
    assert backfill.status_code == 200
    backfill_body = backfill.get_json()
    assert backfill_body["schema"] == "0guard.historical_backfill_plan.v1"
    assert backfill_body["safety"]["rawPayloadsReturned"] is False

    feature_store = client.get("/api/data/historical-feature-store?limit=2")
    assert feature_store.status_code == 200
    feature_store_body = feature_store.get_json()
    assert feature_store_body["schema"] == "0guard.historical_feature_store.v1"
    assert feature_store_body["featureCountsByType"]["incident_detector_trace"] == 2
    assert feature_store_body["featureStoreReceipt"]["liveUploadPerformed"] is False
    assert feature_store_body["rightsPolicy"]["rawPayloadResaleAllowed"] is False
    assert feature_store_body["safety"]["rawPayloadsReturned"] is False

    bad_feature_store_limit = client.get("/api/data/historical-feature-store?limit=0")
    assert bad_feature_store_limit.status_code == 400

    gaps = client.get("/api/production/gaps")
    assert gaps.status_code == 200
    gaps_body = gaps.get_json()
    assert gaps_body["schema"] == "0guard.production_gap_matrix.v1"
    assert gaps_body["productionReady"] is False
    assert gaps_body["rawPayloadsReturned"] is False
    assert gaps_body["classificationSummary"]["counts"]["mock_fixture_only"] >= 1
    assert any(item["id"] == "model.0g_private_computer" for item in gaps_body["gaps"])
    assert gaps_body["safety"]["x402SettlementEnabled"] is False
    assert gaps_body["safety"]["paidInferenceEnabled"] is False

    gaps_alias = client.get("/api/production-gaps")
    assert gaps_alias.status_code == 200
    assert gaps_alias.get_json()["schema"] == "0guard.production_gap_matrix.v1"

    strategy = client.get("/api/product/strategy-review")
    assert strategy.status_code == 200
    strategy_body = strategy.get_json()
    assert strategy_body["schema"] == "0guard.strategy_review.v1"
    assert strategy_body["safety"]["transactionSigningEnabled"] is False
    assert strategy_body["nextBuildSequence"][0]["id"] == "production_contract_freeze"

    model = client.get("/api/model/training-roadmap")
    assert model.status_code == 200
    model_body = model.get_json()
    assert model_body["schema"] == "0guard.model_training_roadmap.v1"
    assert model_body["authorityBoundary"].startswith("Models may summarize")
    assert any(item["id"] == "incident_detector_eval_set" for item in model_body["datasets"])
    assert model_body["safety"]["trainingRunStarted"] is False

    eval_set = client.get("/api/model/incident-eval-set?limit=2")
    assert eval_set.status_code == 200
    eval_body = eval_set.get_json()
    assert eval_body["schema"] == "0guard.incident_detector_eval_set.v1"
    assert eval_body["caseCount"] == 2
    assert eval_body["rows"][0]["rights"]["rawPayloadResaleAllowed"] is False
    assert eval_body["safety"]["trainingRunStarted"] is False

    bad_limit = client.get("/api/model/incident-eval-set?limit=0")
    assert bad_limit.status_code == 400


def test_telegram_routes_do_not_import_live_send_helpers():
    source = (REPO_ROOT / "src" / "guard0" / "app.py").read_text()
    assert "send_message" not in source
    assert "send_thread" not in source
    assert "get_me" not in source
    assert "setWebhook" not in source


def test_data_summary_and_detection_coverage_are_read_only(client):
    summary = client.get("/api/data/summary")
    assert summary.status_code == 200
    summary_body = summary.get_json()
    assert summary_body["schema"] == "0guard.incident_summary.v1"
    assert summary_body["validation"]["ok"] is True
    assert summary_body["stats"]["incidentCount"] == 28

    incidents = client.get("/api/data/incidents?chain=Ethereum&min_loss_usd=100000&limit=2")
    assert incidents.status_code == 200
    incident_body = incidents.get_json()
    assert incident_body["schema"] == "0guard.incidents.v1"
    assert len(incident_body["incidents"]) == 2
    assert all(item["chain"] == "Ethereum" for item in incident_body["incidents"])

    coverage = client.get("/api/data/detection-coverage")
    assert coverage.status_code == 200
    coverage_body = coverage.get_json()
    assert coverage_body["schema"] == "0guard.detection_coverage.v1"
    assert coverage_body["coveredCount"] == 28

    provenance = client.get("/api/data/provenance")
    assert provenance.status_code == 200
    provenance_body = provenance.get_json()
    assert provenance_body["schema"] == "0guard.incident_provenance_matrix.v1"
    assert provenance_body["coverage"]["incidentCount"] == 28
    assert provenance_body["coverage"]["withMatchedEvidence"] == 28
    assert provenance_body["sourceStatus"]["status"] == "canonical_dataset"
    assert provenance_body["sourceStatus"]["evidenceMode"] == "canonical_dataset_evidence"
    assert provenance_body["live"] is False
    assert provenance_body["safety"]["rawPayloadsReturned"] is False

    signature_map = client.get("/api/data/signature-map")
    assert signature_map.status_code == 200
    signature_body = signature_map.get_json()
    assert signature_body["schema"] == "0guard.signature_map.v1"
    assert signature_body["incidentCount"] == 28
    assert signature_body["matchedCount"] == 28
    assert signature_body["topGaps"] == {}


def test_osint_and_hackathon_routes_are_read_only(client):
    sources = client.get("/api/osint/sources")
    assert sources.status_code == 200
    source_body = sources.get_json()
    assert source_body["schema"] == "0guard.osint_source_registry.v1"
    assert source_body["rightsPolicy"]["rawPayloadResaleAllowed"] is False
    assert source_body["sourceCount"] >= 8

    readiness = client.get("/api/osint/readiness")
    assert readiness.status_code == 200
    readiness_body = readiness.get_json()
    assert readiness_body["schema"] == "0guard.osint_readiness.v1"
    assert readiness_body["live"] is False
    assert readiness_body["safety"]["readOnly"] is True
    assert readiness_body["safety"]["rawPayloadsReturned"] is False

    signals = client.get("/api/osint/signals?limit=3")
    assert signals.status_code == 200
    signal_body = signals.get_json()
    assert signal_body["schema"] == "0guard.osint_signals.v1"
    assert signal_body["live"] is False
    assert signal_body["safety"]["rawPayloadsReturned"] is False

    evolving = client.get("/api/intelligence/evolving")
    assert evolving.status_code == 200
    evolving_body = evolving.get_json()
    assert evolving_body["schema"] == "0guard.evolving_threat_intelligence.v1"
    assert evolving_body["zeroGSuite"]["storage"]["currentRootHash"]
    assert evolving_body["qualityBar"]["walletTrackingDefault"] == "preview_no_send_read_only"
    assert evolving_body["safety"]["rawPayloadsReturned"] is False

    cyber = client.get("/api/intelligence/cyber-threats?cves=CVE-2024-3094")
    assert cyber.status_code == 200
    cyber_body = cyber.get_json()
    assert cyber_body["schema"] == "0guard.cyber_threat_repository.v1"
    assert cyber_body["live"] is False
    assert cyber_body["rightsPolicy"]["rawPayloadsReturned"] is False
    assert cyber_body["safety"]["notLegalAdvice"] is True
    assert cyber_body["safety"]["notAttribution"] is True
    assert "mitre_attack_lazarus_g0032" in {
        item["id"] for item in cyber_body["mitreTtpContext"]
    }

    streams = client.get("/api/intelligence/data-streams")
    assert streams.status_code == 200
    stream_body = streams.get_json()
    assert stream_body["schema"] == "0guard.intelligence_stream_plan.v1"
    assert stream_body["rightsPolicy"]["rawPayloadResaleAllowed"] is False
    assert stream_body["streams"][0]["id"] == "unified_reputation_adapter"

    events = client.get("/api/intelligence/events")
    assert events.status_code == 200
    event_body = events.get_json()
    assert event_body["schema"] == "0guard.intelligence_events_snapshot.v1"
    assert event_body["live"] is False
    assert event_body["safety"]["rawPayloadsReturned"] is False

    candidates = client.get("/api/intelligence/detector-candidates")
    assert candidates.status_code == 200
    candidate_body = candidates.get_json()
    assert candidate_body["schema"] == "0guard.detector_candidates.v1"
    assert candidate_body["live"] is False
    assert candidate_body["safety"]["rawPayloadsReturned"] is False
    assert candidate_body["safety"]["candidatePromotionAutomatic"] is False

    roadmap = client.get("/api/roadmap")
    assert roadmap.status_code == 200
    roadmap_body = roadmap.get_json()
    assert roadmap_body["schema"] == "0guard.ecosystem_roadmap.v1"
    assert roadmap_body["positioning"]["category"] == "pre-wallet safety layer for autonomous agents"
    assert roadmap_body["safety"]["bridgingEnabled"] is False

    frontier = client.get("/api/experiments/frontier")
    assert frontier.status_code == 200
    frontier_body = frontier.get_json()
    assert frontier_body["schema"] == "0guard.frontier_experiments.v1"
    assert frontier_body["safety"]["networkCalls"] is False

    frontier_run = client.post(
        "/api/experiments/run",
        json={"experimentId": "zero_g_storage_receipt_readback"},
    )
    assert frontier_run.status_code == 200
    frontier_run_body = frontier_run.get_json()
    assert frontier_run_body["schema"] == "0guard.frontier_experiment_preview.v1"
    assert frontier_run_body["preview"]["storageReceipt"]["stored"] is False
    assert frontier_run_body["safety"]["liveStorageUpload"] is False

    brief = client.get("/api/hackathon/submission-brief")
    assert brief.status_code == 200
    brief_body = brief.get_json()
    assert brief_body["schema"] == "0guard.hackathon_submission_brief.v1"
    assert brief_body["project"]["name"] == "0guard"
    assert brief_body["dataProduct"]["incidentCount"] == 28
    assert brief_body["submissionRequirements"]["publicXPost"]["mandatory"] is True
    assert brief_body["repoProfessionalization"]["license"] == "Apache-2.0"
    assert brief_body["repoProfessionalization"]["ready"] is True

    packet = client.get("/api/hackathon/submission-packet")
    assert packet.status_code == 200
    packet_body = packet.get_json()
    assert packet_body["schema"] == "0guard.hackquest_submission_packet.v1"
    assert packet_body["formFields"]["demoVideoUrl"].endswith("0guard-hackquest-demo-final.mp4")
    assert packet_body["formFields"]["mediaArchive"].endswith("assets/README.md")
    assert packet_body["repoProfessionalization"]["assetRegistryUrl"].endswith(
        "assets/README.md"
    )
    assert packet_body["xPost"]["mediaPath"].endswith("0guard-workbench-provenance.png")
    assert packet_body["safety"]["rawPayloadsReturned"] is False

    readiness = client.get("/api/hackathon/readiness")
    assert readiness.status_code == 200
    readiness_body = readiness.get_json()
    assert readiness_body["schema"] == "0guard.hackquest_readiness_audit.v1"
    assert readiness_body["mainnetRequirement"]["chainId"] == 16661
    assert readiness_body["submittableNow"] is True
    assert readiness_body["repoProfessionalization"]["ready"] is True
    assert readiness_body["safety"]["rawPayloadsReturned"] is False

    passport = client.get("/api/hackathon/threat-passport")
    assert passport.status_code == 200
    passport_body = passport.get_json()
    assert passport_body["schema"] == "0guard.threat_receipt_passport.v1"
    assert passport_body["receipt"]["decision"] == "deny"
    assert passport_body["receipt"]["zeroG"]["chain_anchor"]["status"] == "preflight"
    assert passport_body["provenance"]["coverage"]["withMatchedEvidence"] == 28
    assert passport_body["signatureCoverage"]["incidentCount"] == 28
    assert passport_body["signatureCoverage"]["gapCount"] == 0
    assert passport_body["safety"]["rawPayloadsReturned"] is False


def test_cross_chain_integration_routes_are_read_only(client):
    catalog = client.get("/api/integrations/cross-chain")
    assert catalog.status_code == 200
    catalog_body = catalog.get_json()
    assert catalog_body["schema"] == "0guard.crosschain_catalog.v1"
    assert catalog_body["targetCount"] >= 8
    assert catalog_body["x402"]["mode"] == "prepared_not_live"
    assert catalog_body["safety"]["bridgingEnabled"] is False
    assert catalog_body["safety"]["moneyMovementEnabled"] is False

    readiness = client.get("/api/integrations/cross-chain/readiness")
    assert readiness.status_code == 200
    readiness_body = readiness.get_json()
    assert readiness_body["schema"] == "0guard.crosschain_readiness.v1"
    assert readiness_body["live"] is False
    assert readiness_body["attemptedRpcProbes"] == 0
    assert readiness_body["paymentReadiness"]["x402Ready"] is False
    assert readiness_body["agentReadiness"]["virtualsLiveAgentLaunched"] is False
    assert readiness_body["safety"]["transactionSigningEnabled"] is False

    manifest = client.get("/api/integrations/virtuals-facilitator")
    assert manifest.status_code == 200
    manifest_body = manifest.get_json()
    assert manifest_body["schema"] == "0guard.virtuals_facilitator_manifest.v1"
    assert manifest_body["agent"]["name"] == "0guard Facilitator"
    assert manifest_body["agent"]["launchStatus"] == "prepared_operator_required"
    assert manifest_body["safety"]["externalAgentLaunchEnabled"] is False

    ika = client.get("/api/integrations/ika")
    assert ika.status_code == 200
    ika_body = ika.get_json()
    assert ika_body["schema"] == "0guard.ika_integration_manifest.v1"
    assert ika_body["safety"]["privateKeyImportEnabled"] is False

    ika_preflight = client.post(
        "/api/integrations/ika/evaluate",
        json={
            "sourceProject": "ikavery",
            "operation": "sweep",
            "chain": "solana:devnet",
            "liveSigning": True,
        },
    )
    assert ika_preflight.status_code == 200
    ika_preflight_body = ika_preflight.get_json()
    assert ika_preflight_body["schema"] == "0guard.ika_signing_preflight.v1"
    assert ika_preflight_body["decision"] == "deny"
    assert ika_preflight_body["transactionSigningEnabled"] is False
    assert ika_preflight_body["safety"]["transactionSigningEnabled"] is False

    reputation = client.post(
        "/api/reputation/probe",
        json={
            "url": "https://docs.0g.ai.evil.example/claim",
            "address": "0x02228b0afcdbEdf8180D96Fc181Da3AF5DD1d1ab",
            "sourceEvidence": [
                {"sourceId": "operator_report", "verdict": "phishing", "confidence": 0.91}
            ],
        },
    )
    assert reputation.status_code == 200
    reputation_body = reputation.get_json()
    assert reputation_body["schema"] == "0guard.reputation_probe.v1"
    assert reputation_body["decision"]["decision"] == "deny"
    assert reputation_body["rawPayloadsReturned"] is False
    assert reputation_body["rightsPolicy"]["rawPayloadsReturned"] is False

    connectors = client.post(
        "/api/reputation/connectors",
        json={
            "url": "https://docs.0g.ai.evil.example/claim",
            "address": "0x02228b0afcdbEdf8180D96Fc181Da3AF5DD1d1ab",
            "chain": "eip155:1",
        },
    )
    assert connectors.status_code == 200
    connectors_body = connectors.get_json()
    assert connectors_body["schema"] == "0guard.reputation_connectors.v1"
    assert connectors_body["safety"]["networkCalls"] is False
    assert connectors_body["rightsPolicy"]["rawPayloadsReturned"] is False
    assert {"goplus_security", "chainabuse"} <= {
        connector["id"] for connector in connectors_body["connectors"]
    }

    live_connector = client.get("/api/reputation/connectors/live")
    assert live_connector.status_code == 200
    live_connector_body = live_connector.get_json()
    assert live_connector_body["schema"] == "0guard.reputation_connector_snapshot.v1"
    assert live_connector_body["mode"] == "live_fetch_disabled"
    assert live_connector_body["safety"]["networkCalls"] is False
    assert live_connector_body["rightsPolicy"]["rawPayloadsReturned"] is False

    cisa_connector = client.get(
        "/api/reputation/connectors/live?sourceId=cisa_kev&cves=CVE-2024-3094"
    )
    assert cisa_connector.status_code == 200
    cisa_body = cisa_connector.get_json()
    assert cisa_body["sourceId"] == "cisa_kev"
    assert cisa_body["mode"] == "live_fetch_disabled"
    assert cisa_body["subject"]["cveIds"] == ["CVE-2024-3094"]

    backfill_status = client.get("/api/reputation/backfill/status")
    assert backfill_status.status_code == 200
    backfill_body = backfill_status.get_json()
    assert backfill_body["schema"] == "0guard.reputation_backfill_status.v1"
    assert backfill_body["safety"]["networkCalls"] is False
    assert backfill_body["rightsPolicy"]["rawPayloadsReturned"] is False
    assert backfill_body["rawPayloadsReturned"] is False
    assert "supervisorInstalled" in backfill_body
    assert "freshWithinTtl" in backfill_body
    assert "supervisedFreshnessReady" in backfill_body

    adapters = client.get("/api/reputation/adapters")
    assert adapters.status_code == 200
    adapters_body = adapters.get_json()
    assert adapters_body["schema"] == "0guard.reputation_adapter_catalog.v1"
    assert adapters_body["safety"]["networkCalls"] is False
    assert adapters_body["rightsPolicy"]["rawPayloadsReturned"] is False
    assert {adapter["id"] for adapter in adapters_body["adapters"]} >= {
        "phishdestroy_destroylist",
        "cryptoscamdb",
        "forta_labelled_datasets",
        "goplus_security",
        "chainabuse",
        "forta_graphql_api",
    }

    adapter_preview = client.post(
        "/api/reputation/adapters/normalize",
        json={
            "sourceId": "goplus_security",
            "subject": {
                "url": "https://docs.0g.ai.evil.example/claim",
                "address": "0x02228b0afcdbEdf8180D96Fc181Da3AF5DD1d1ab",
                "chain": "eip155:1",
            },
            "payload": {
                "result": {
                    "0x02228b0afcdbeDf8180d96fc181da3af5dd1d1ab": {
                        "blacklist_doubt": "1",
                        "phishing_activities": "1",
                    }
                }
            },
        },
    )
    assert adapter_preview.status_code == 200
    adapter_preview_body = adapter_preview.get_json()
    assert adapter_preview_body["schema"] == "0guard.reputation_adapter_preview.v1"
    assert adapter_preview_body["rawPayloadReturned"] is False
    assert adapter_preview_body["reputationPreview"]["decision"]["decision"] == "deny"
    assert adapter_preview_body["safety"]["networkCalls"] is False

    shadow_cache = client.get("/api/reputation/shadow-cache")
    assert shadow_cache.status_code == 200
    shadow_cache_body = shadow_cache.get_json()
    assert shadow_cache_body["schema"] == "0guard.reputation_shadow_cache.v1"
    assert shadow_cache_body["sourceCount"] == 3
    assert shadow_cache_body["probePreview"]["decision"]["decision"] == "deny"
    assert shadow_cache_body["sourceRights"]["rawPayloadsReturned"] is False
    assert shadow_cache_body["safety"]["networkCalls"] is False
    assert "docs.0g.ai.evil.example/claim" not in str(shadow_cache_body)

    ready = client.get("/api/readyz")
    assert ready.status_code == 200
    ready_body = ready.get_json()
    assert ready_body["schema"] == "0guard.readyz.v1"
    assert ready_body["mode"] == "operational_readiness_no_side_effects"
    assert ready_body["safety"]["transactionSigningEnabled"] is False
    assert ready_body["safety"]["networkCalls"] is False

    proof_ladder = client.post(
        "/api/0g/proof-ladder",
        json={
            "surface": "evm",
            "operation": "approve",
            "chain": "eip155:16661",
            "intent": {
                "action": "approve",
                "mode": "live_transaction",
                "requires_signature": True,
                "prompt_text": (
                    "Approve this agent to spend funds; also here is "
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
            },
        },
    )
    assert proof_ladder.status_code == 200
    proof_ladder_body = proof_ladder.get_json()
    assert proof_ladder_body["schema"] == "0guard.0g_proof_ladder.v1"
    assert proof_ladder_body["decision"]["decision"] == "deny"
    assert [stage["id"] for stage in proof_ladder_body["stages"]] == [
        "chainReceipt",
        "storagePacket",
        "daAvailability",
        "computePreview",
        "alignmentVerifier",
    ]
    assert proof_ladder_body["stages"][0]["chainId"] == 16661
    assert proof_ladder_body["stages"][0]["network"] == "0G Mainnet"
    assert proof_ladder_body["safety"]["liveStorageUpload"] is False
    assert proof_ladder_body["safety"]["liveComputeInference"] is False
    assert proof_ladder_body["safety"]["moneyMovementEnabled"] is False
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in str(
        proof_ladder_body
    )

    native_preflight = client.post(
        "/api/native-preflight",
        json={
            "surface": "ika_dwallets",
            "sourceProject": "ikavery",
            "operation": "sweep",
            "chain": "solana:devnet",
            "liveSigning": True,
        },
    )
    assert native_preflight.status_code == 200
    native_body = native_preflight.get_json()
    assert native_body["schema"] == "0guard.native_preflight.v1"
    assert native_body["decision"] == "deny"
    assert native_body["transactionSigningEnabled"] is False
    assert native_body["zeroGStorageReady"] is True
    assert native_body["safety"]["transactionSigningEnabled"] is False

    native_with_reputation = client.post(
        "/api/native-preflight",
        json={
            "surface": "evm",
            "operation": "approve",
            "chain": "eip155:1",
            "target": "0x02228b0afcdbEdf8180D96Fc181Da3AF5DD1d1ab",
        },
    )
    assert native_with_reputation.status_code == 200
    reputation_component_ids = {
        item["id"] for item in native_with_reputation.get_json()["components"]
    }
    assert "reputation_probe" in reputation_component_ids

    case_file = client.post(
        "/api/threat-case-file",
        json={
            "intent": {
                "action": "approve",
                "mode": "live_transaction",
                "requires_signature": True,
                "target_contract": "0x02228b0afcdbEdf8180D96Fc181Da3AF5DD1d1ab",
            }
        },
    )
    assert case_file.status_code == 200
    case_body = case_file.get_json()
    assert case_body["schema"] == "0guard.threat_case_file.v1"
    assert case_body["safety"]["telegramSendsEnabled"] is False
    assert case_body["safety"]["transactionSigningEnabled"] is False
    assert case_body["sourceRights"]["rawPayloadsReturned"] is False

    strategy = client.get("/api/hackathon/strategy")
    assert strategy.status_code == 200
    strategy_body = strategy.get_json()
    assert strategy_body["schema"] == "0guard.hackathon_strategy.v1"
    assert strategy_body["opportunities"][0]["id"] == "0g_apac_final_review"

    next_hackathons = client.get("/api/hackathons/next")
    assert next_hackathons.status_code == 200
    next_body = next_hackathons.get_json()
    assert next_body["schema"] == "0guard.next_hackathon_plan.v1"
    assert next_body["opportunities"][0]["id"] == "metamask_smart_accounts_1shot_api_dev_cookoff"

    developer_kit = client.get("/api/developer-kit")
    assert developer_kit.status_code == 200
    developer_kit_body = developer_kit.get_json()
    assert developer_kit_body["schema"] == "0guard.developer_kit.v1"
    assert developer_kit_body["transactionSigningEnabled"] is False
    assert developer_kit_body["safety"]["transactionSigningEnabled"] is False
    assert "/api/readyz" in {route["path"] for route in developer_kit_body["routes"]}
    assert {recipe["id"] for recipe in developer_kit_body["adapterRecipes"]} >= {
        "agentkit_turnkey_safe_evm",
        "ika_mpckit_odws",
    }
    assert "/api/reputation/connectors" in {
        route["path"] for route in developer_kit_body["routes"]
    }
    assert "/api/reputation/adapters" in {
        route["path"] for route in developer_kit_body["routes"]
    }
    assert "/api/reputation/adapters/normalize" in {
        route["path"] for route in developer_kit_body["routes"]
    }
    assert "/api/reputation/shadow-cache" in {
        route["path"] for route in developer_kit_body["routes"]
    }

    guardrails = client.get("/api/integrations/external-guardrails")
    assert guardrails.status_code == 200
    guardrail_body = guardrails.get_json()
    assert guardrail_body["schema"] == "0guard.external_guardrail_catalog.v1"
    assert guardrail_body["safety"]["moneyMovementEnabled"] is False
    assert {item["targetId"] for item in guardrail_body["guardrails"]} >= {
        "arbitrum_l2",
        "metamask_wallet",
        "lighter_exchange",
        "chainlink_ccip",
        "layerzero_v2",
        "wormhole_ntt",
    }

    arbitrum = client.get("/api/integrations/arbitrum")
    assert arbitrum.status_code == 200
    assert arbitrum.get_json()["schema"] == "0guard.arbitrum_integration_plan.v1"

    arbitrum_buildathon = client.get("/api/hackathons/arbitrum-open-house")
    assert arbitrum_buildathon.status_code == 200
    arbitrum_buildathon_body = arbitrum_buildathon.get_json()
    assert (
        arbitrum_buildathon_body["schema"]
        == "0guard.arbitrum_open_house_buildathon_plan.v1"
    )
    assert arbitrum_buildathon_body["qualification"]["mustDeployOnArbitrumChain"] is True
    assert arbitrum_buildathon_body["safety"]["moneyMovementEnabled"] is False

    metamask = client.get("/api/integrations/metamask")
    assert metamask.status_code == 200
    assert metamask.get_json()["schema"] == "0guard.metamask_integration_plan.v1"

    metamask_1shot = client.get("/api/hackathons/metamask-1shot")
    assert metamask_1shot.status_code == 200
    metamask_1shot_body = metamask_1shot.get_json()
    assert metamask_1shot_body["schema"] == "0guard.metamask_1shot_cookoff_plan.v1"
    assert metamask_1shot_body["fundingGate"]["send25OgNow"] is False

    metamask_preview = client.post(
        "/api/hackathons/metamask-1shot/permission-preview",
        json={"network": "eip155:84532", "maxAmount": "10000"},
    )
    assert metamask_preview.status_code == 200
    metamask_preview_body = metamask_preview.get_json()
    assert metamask_preview_body["schema"] == "0guard.metamask_1shot_permission_preview.v1"
    assert metamask_preview_body["oneShot"]["x402Requirement"]["extra"]["assetTransferMethod"] == "erc7710"
    assert metamask_preview_body["zeroGuard"]["unsafeVariantPreflight"]["decision"] == "deny"
    assert metamask_preview_body["safety"]["transactionSigningEnabled"] is False

    evaluation = client.post(
        "/api/integrations/external-guardrails/evaluate",
        json={
            "target_id": "layerzero_v2",
            "action": "bridge_release",
            "config": {
                "requiredDVNCount": 1,
                "sendReceiveConfigSymmetric": False,
                "nonceReplayProtection": False,
            },
        },
    )
    assert evaluation.status_code == 200
    evaluation_body = evaluation.get_json()
    assert evaluation_body["schema"] == "0guard.external_guardrail_evaluation.v1"
    assert evaluation_body["decision"] == "deny"
    assert evaluation_body["safety"]["transactionSigningEnabled"] is False
    assert {finding["id"] for finding in evaluation_body["findings"]} >= {
        "layerzero_single_dvn_denied",
        "layerzero_send_receive_asymmetry",
        "layerzero_replay_protection_missing",
    }


def test_osint_signal_route_rejects_bad_limit(client):
    assert client.get("/api/osint/signals?limit=bad").status_code == 400
    assert client.get("/api/osint/signals?limit=0").status_code == 400
    assert client.get("/api/osint/signals?limit=101").status_code == 400
    assert client.get("/api/intelligence/evolving?limit=bad").status_code == 400
    assert client.get("/api/intelligence/evolving?limit=0").status_code == 400
    assert client.get("/api/intelligence/evolving?limit=51").status_code == 400
    assert client.get("/api/intelligence/events?limit=bad").status_code == 400
    assert client.get("/api/intelligence/events?limit=0").status_code == 400
    assert client.get("/api/intelligence/events?limit=51").status_code == 400
    assert client.get("/api/intelligence/detector-candidates?limit=bad").status_code == 400
    assert client.get("/api/intelligence/detector-candidates?limit=0").status_code == 400
    assert client.get("/api/intelligence/detector-candidates?limit=51").status_code == 400
    assert client.get("/api/intelligence/cyber-threats?limit=bad").status_code == 400
    assert client.get("/api/intelligence/cyber-threats?limit=0").status_code == 400
    assert client.get("/api/intelligence/cyber-threats?limit=26").status_code == 400
    assert client.get("/api/reputation/connectors/live?limit=bad").status_code == 400
    assert client.get("/api/reputation/connectors/live?limit=0").status_code == 400
    assert client.get("/api/reputation/connectors/live?limit=51").status_code == 400


def test_data_incident_filters_reject_bad_inputs(client):
    assert client.get("/api/data/incidents?min_loss_usd=bad").status_code == 400
    assert client.get("/api/data/incidents?min_loss_usd=-1").status_code == 400
    assert client.get("/api/data/incidents?limit=0").status_code == 400
    assert client.get("/api/data/incidents?limit=201").status_code == 400


def test_0g_status_is_read_only_and_reports_runtime_config(monkeypatch, client):
    monkeypatch.setattr(
        app_module,
        "build_0g_status",
        lambda: {
            "schema": "0guard.0g_status.v1",
            "readMode": "live_rpc_read_only",
            "rpc": {"expectedChainId": 16602, "status": "ok"},
            "receiptAnchor": {"configured": False},
            "safety": {
                "privateKeyRequired": False,
                "signingEnabled": False,
                "broadcastingEnabled": False,
            },
        },
    )

    r = client.get("/api/0g/status")
    assert r.status_code == 200
    data = r.get_json()
    assert data["schema"] == "0guard.0g_status.v1"
    assert data["readMode"] == "live_rpc_read_only"
    assert data["rpc"]["expectedChainId"] == 16602
    assert data["receiptAnchor"]["configured"] is False
    assert data["safety"]["privateKeyRequired"] is False
    assert data["safety"]["signingEnabled"] is False
    assert data["safety"]["broadcastingEnabled"] is False


def test_0g_da_node_status_and_telegram_preview_are_no_send(monkeypatch, client):
    monkeypatch.setattr(
        app_module,
        "build_da_node_status",
        lambda live=False: {
            "schema": "0guard.0g_da_node_status.v1",
            "mode": "live_rpc_read_only" if live else "configured_snapshot",
            "node": {"publicSocket": "35.254.123.37:34000"},
            "balances": {
                "signer": {"balanceOg": 0.0, "balanceWei": "0", "status": "ok"},
                "miner": {"balanceOg": 0.0, "balanceWei": "0", "status": "ok"},
            },
            "readiness": {"status": "blocked", "blockedBy": ["signer_zero_balance"]},
            "yield": {"status": "not_claimed_without_reward_source"},
            "safety": {
                "networkCalls": live,
                "telegramSendsEnabled": False,
                "moneyMovementEnabled": False,
            },
        },
    )

    status_response = client.get("/api/0g/da-node/status?live=1")
    assert status_response.status_code == 200
    status = status_response.get_json()
    assert status["schema"] == "0guard.0g_da_node_status.v1"
    assert status["mode"] == "live_rpc_read_only"
    assert status["safety"]["telegramSendsEnabled"] is False

    preview_response = client.get("/api/telegram/da-node-preview?live=1")
    assert preview_response.status_code == 200
    preview = preview_response.get_json()
    assert preview["schema"] == "0guard.telegram_da_node_preview.v1"
    assert preview["delivery"] == "preview_no_send"
    assert preview["telegram_send"] is False
    assert preview["digestPolicy"]["shouldSendNow"] is False
    assert preview["safety"]["moneyMovementEnabled"] is False


def test_0g_storage_node_status_and_telegram_preview_are_no_send(monkeypatch, client):
    monkeypatch.setattr(
        app_module,
        "build_storage_node_status",
        lambda live=False: {
            "schema": "0guard.0g_storage_node_status.v1",
            "mode": "live_storage_rpc_read_only" if live else "configured_snapshot",
            "node": {"publicSocket": "35.254.123.37:1234"},
            "storageRpc": {
                "connectedPeers": 4,
                "logSyncHeight": 3041488,
                "networkIdentity": {"chainId": 16661},
            },
            "readiness": {"status": "ready_for_no_key_soak", "blockedBy": []},
            "funding": {"status": "not_ready_for_mainnet_funds"},
            "yield": {"status": "not_inferred_without_official_reward_source"},
            "safety": {
                "networkCalls": live,
                "telegramSendsEnabled": False,
                "moneyMovementEnabled": False,
            },
        },
    )

    status_response = client.get("/api/0g/storage-node/status?live=1")
    assert status_response.status_code == 200
    status = status_response.get_json()
    assert status["schema"] == "0guard.0g_storage_node_status.v1"
    assert status["mode"] == "live_storage_rpc_read_only"
    assert status["safety"]["telegramSendsEnabled"] is False

    preview_response = client.get("/api/telegram/storage-node-preview?live=1")
    assert preview_response.status_code == 200
    preview = preview_response.get_json()
    assert preview["schema"] == "0guard.telegram_storage_node_preview.v1"
    assert preview["delivery"] == "preview_no_send"
    assert preview["telegram_send"] is False
    assert preview["summary"]["connectedPeers"] == 4
    assert preview["safety"]["moneyMovementEnabled"] is False


def test_0g_storage_peer_diagnostics_route_is_read_only(monkeypatch, client):
    monkeypatch.setattr(
        app_module,
        "build_storage_peer_diagnostics",
        lambda status_file=None: {
            "schema": "0guard.rv_0g_peer_diagnostics.v1",
            "status": "loaded",
            "summary": {
                "connectedPeers": 2,
                "peerDepthReady": False,
                "blockedBy": ["connected_peers_below_target_8"],
            },
            "safety": {
                "readOnly": True,
                "privateKeysRead": False,
                "privateKeysReturned": False,
                "moneyMovementEnabled": False,
            },
        },
    )

    response = client.get("/api/0g/storage-node/peer-diagnostics?snapshot=1")

    assert response.status_code == 200
    data = response.get_json()
    assert data["schema"] == "0guard.rv_0g_peer_diagnostics.v1"
    assert data["summary"]["connectedPeers"] == 2
    assert data["summary"]["peerDepthReady"] is False
    assert data["safety"]["privateKeysRead"] is False
    assert data["safety"]["moneyMovementEnabled"] is False


def test_0g_node_pi_readiness_proof_route_is_read_only(client):
    response = client.get("/api/0g/node-pi-readiness-proof")

    assert response.status_code == 200
    data = response.get_json()
    assert data["schema"] == "0guard.node_pi_readiness_proof_status.v1"
    assert data["status"] in {"missing", "blocked", "ready"}
    assert data["safety"]["proofVerificationOnly"] is True
    assert data["safety"]["privateKeysReturned"] is False
    assert data["safety"]["transactionSigningEnabled"] is False
    assert data["safety"]["transactionBroadcastingEnabled"] is False
    assert data["safety"]["moneyMovementEnabled"] is False


def test_0g_node_business_routes_are_read_only(monkeypatch, client):
    monkeypatch.setattr(
        app_module,
        "build_alignment_node_status",
        lambda live=False: {
            "schema": "0guard.0g_alignment_node_status.v1",
            "readiness": {"status": "operator_action_required", "blockedBy": []},
            "economics": {"part2ApproxDailyOg": 0.52},
            "safety": {"networkCalls": live, "moneyMovementEnabled": False},
        },
    )
    monkeypatch.setattr(
        app_module,
        "build_validator_capacity_status",
        lambda: {
            "schema": "0guard.0g_validator_capacity.v1",
            "readiness": {"status": "not_recommended_in_wsl", "validatorReady": False},
            "safety": {"moneyMovementEnabled": False},
        },
    )
    monkeypatch.setattr(
        app_module,
        "build_0g_node_business_plan",
        lambda live=False: {
            "schema": "0guard.0g_node_business.v1",
            "currentReadiness": {
                "storage": {"status": "ready_for_no_key_soak"},
                "alignment": {"status": "operator_action_required"},
                "validator": {"status": "not_recommended_in_wsl"},
                "storageEconomics": {"perActiveMinerMonthlyOg": 0.150483},
            },
            "operatorGates": ["No 100 0G funding until proven."],
            "safety": {"networkCalls": live, "moneyMovementEnabled": False},
        },
    )

    alignment = client.get("/api/0g/alignment-node/status?live=1")
    assert alignment.status_code == 200
    assert alignment.get_json()["schema"] == "0guard.0g_alignment_node_status.v1"

    validator = client.get("/api/0g/validator-capacity")
    assert validator.status_code == 200
    assert validator.get_json()["schema"] == "0guard.0g_validator_capacity.v1"

    business = client.get("/api/0g/node-business?live=1")
    assert business.status_code == 200
    body = business.get_json()
    assert body["schema"] == "0guard.0g_node_business.v1"
    assert body["safety"]["moneyMovementEnabled"] is False

    preview = client.get("/api/telegram/node-business-preview?live=1")
    assert preview.status_code == 200
    preview_body = preview.get_json()
    assert preview_body["schema"] == "0guard.telegram_node_business_preview.v1"
    assert preview_body["delivery"] == "preview_no_send"
    assert preview_body["telegram_send"] is False
    assert preview_body["safety"]["moneyMovementEnabled"] is False


def test_0g_receipt_verifier_is_read_only_without_contract(monkeypatch, client):
    monkeypatch.setenv("ZGG_RECEIPT_CONTRACT", "0x0000000000000000000000000000000000000000")
    receipt_hash = "0x" + "a" * 64
    r = client.get(f"/api/0g/receipt?receipt_hash={receipt_hash}")
    assert r.status_code == 200
    data = r.get_json()
    assert data["schema"] == "0guard.0g_receipt_verifier.v1"
    assert data["verified"] is False
    assert data["status"] == "contract_not_configured"
    assert data["safety"]["privateKeyRequired"] is False
    assert data["safety"]["signingEnabled"] is False
    assert data["safety"]["broadcastingEnabled"] is False

    legacy_alias = client.get(f"/api/0g/receipt?receipt={receipt_hash}")
    assert legacy_alias.status_code == 200
    assert legacy_alias.get_json()["schema"] == "0guard.0g_receipt_verifier.v1"

    bad = client.get("/api/0g/receipt?receipt_hash=not-a-hash")
    assert bad.status_code == 200
    assert bad.get_json()["status"] == "invalid_receipt_hash"


def test_telegram_mira_status_is_preview_only(client):
    r = client.get("/api/telegram/status")
    assert r.status_code == 200
    data = r.get_json()
    assert data["schema"] == "0guard.telegram_mira_status.v1"
    assert data["mode"] == "opt_in_preview_no_sends"
    assert data["mira"]["externalLlmCalls"] is False
    assert data["miniAppAuth"]["serverSideValidationRequired"] is True
    assert data["safety"]["telegramSendsEnabled"] is False
    assert data["safety"]["networkCalls"] is False
    assert "/api/telegram/opt-ins" in data["apiRoutes"]
    assert "/api/telegram/miniapp/session" in data["apiRoutes"]
    assert "/api/telegram/miniapp/preview" in data["apiRoutes"]
    assert "/api/telegram/miniapp/ton-preview" in data["apiRoutes"]
    assert "/api/telegram/wallet-alert-preview" in data["apiRoutes"]
    assert "/api/telegram/da-node-preview" in data["apiRoutes"]
    assert "/api/telegram/storage-node-preview" in data["apiRoutes"]
    assert "/api/telegram/node-business-preview" in data["apiRoutes"]
    assert "/api/ton/status" in data["apiRoutes"]
    assert "da_node.digest" in data["registration"]["nodeScopes"]
    assert "storage_node.digest" in data["registration"]["nodeScopes"]
    assert "node_business.digest" in data["registration"]["nodeScopes"]
    assert data["registration"]["walletAlertPolicy"]["telegramSendEnabled"] is False
    # Compatibility keys for steward readbacks (flat shape)
    assert isinstance(data["botTokenConfigured"], bool)
    assert isinstance(data["telegramBotUsernameConfigured"], bool)
    assert data["secretSource"] in ("env", "ephemeral_demo")
    assert isinstance(data["secretConfiguredForProduction"], bool)
    assert data["telegramSendsEnabled"] is False


def test_telegram_status_live_can_report_bot_identity_without_sends(monkeypatch, client):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "123:fake")

    monkeypatch.setattr(app_module, "_telegram_webhook_info", lambda: {"url_set": False})
    monkeypatch.setattr(
        app_module,
        "_telegram_bot_identity",
        lambda: {
            "status": "ok",
            "username": "zeroguard_bot",
            "canJoinGroups": True,
        },
    )

    r = client.get("/api/telegram/status?live=1")
    data = r.get_json()

    assert r.status_code == 200
    assert data["liveReadback"] is True
    assert data["botApiIdentity"]["status"] == "ok"
    assert data["botApiIdentity"]["username"] == "zeroguard_bot"
    assert data["telegramSendsEnabled"] is False
    assert data["safety"]["telegramSendsEnabled"] is False


def test_telegram_miniapp_session_allows_browser_preview_without_sends(client):
    r = client.post("/api/telegram/miniapp/session", json={})
    assert r.status_code == 200
    data = r.get_json()
    assert data["schema"] == "0guard.telegram_miniapp_session.v1"
    assert data["mode"] == "local_browser_preview"
    assert data["auth"]["initDataPresent"] is False
    assert data["auth"]["validated"] is False
    assert data["launch"]["serverSideInitDataValidation"] is True
    assert data["launch"]["sendDataUsed"] is False
    assert data["qualityPolicy"]["telegramSendEnabled"] is False
    assert data["safety"]["telegramSendsEnabled"] is False

    get_r = client.get("/api/telegram/miniapp/session")
    assert get_r.status_code == 200
    get_data = get_r.get_json()
    assert get_data["schema"] == "0guard.telegram_miniapp_session.v1"
    assert get_data["mode"] == "local_browser_preview"
    assert get_data["local_browser_preview"] is True


def test_telegram_miniapp_session_validates_signed_init_data(monkeypatch, client):
    bot_token = "123456:ABCDEF"
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", bot_token)
    init_data = signed_telegram_init_data(
        {
            "auth_date": "1710000000",
            "user": json.dumps({"id": 123456, "username": "ari"}, separators=(",", ":")),
        },
        bot_token,
    )
    monkeypatch.setattr(
        app_module,
        "validate_webapp_init_data",
        lambda data, token: real_validate_webapp_init_data(data, token, now=1710000100),
    )

    r = client.post("/api/telegram/miniapp/session", json={"initData": init_data})

    assert r.status_code == 200
    data = r.get_json()
    assert data["schema"] == "0guard.telegram_miniapp_session.v1"
    assert data["mode"] == "telegram_webapp"
    assert data["auth"]["validated"] is True
    assert data["auth"]["initDataPresent"] is True
    assert data["auth"]["optInStatus"] == "not_attached"
    assert data["safety"]["telegramSendsEnabled"] is False
    public_json = json.dumps(data)
    assert "123456" not in public_json
    assert "ari" not in public_json


def test_telegram_miniapp_requires_configured_bot_token_for_init_data(monkeypatch, client):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    r = client.post("/api/telegram/miniapp/session", json={"initData": "auth_date=1"})
    assert r.status_code == 503
    data = r.get_json()
    assert data["schema"] == "0guard.telegram_miniapp_error.v1"
    assert "TELEGRAM_BOT_TOKEN" in data["error"]
    assert data["safety"]["telegramSendsEnabled"] is False


def test_telegram_miniapp_preview_combines_wallet_alert_and_mira(client):
    address = "0x885b0892D241Cb5033C9995e09cA521d54f936b5"
    r = client.post(
        "/api/telegram/miniapp/preview",
        json={
            "address": address,
            "url": "https://docs.0g.ai.evil.example/claim",
            "sourceEvidence": [
                {"sourceId": "operator_report", "verdict": "phishing", "confidence": 0.91}
            ],
            "reputationAdapter": {
                "sourceId": "goplus_security",
                "subject": {
                    "url": "https://docs.0g.ai.evil.example/claim",
                    "address": "0x02228b0afcdbEdf8180D96Fc181Da3AF5DD1d1ab",
                    "chain": "eip155:1",
                },
                "payload": {"result": {"is_blacklisted": "1", "phishing_activities": "1"}},
            },
            "intent": {
                "action": "approve",
                "mode": "live_transaction",
                "requires_signature": True,
                "calldata": (
                    "0x095ea7b3ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff"
                ),
            },
        },
    )
    assert r.status_code == 200
    data = r.get_json()
    assert data["schema"] == "0guard.telegram_miniapp_preview.v1"
    assert data["delivery"] == "preview_no_send"
    assert data["telegram_send"] is False
    assert data["network_calls"] is False
    assert data["walletAlert"]["schema"] == "0guard.wallet_alert_preview.v1"
    assert data["walletAlert"]["decision"]["decision"] == "deny"
    assert data["walletAlert"]["reputation"]["schema"] == "0guard.reputation_probe.v1"
    assert data["walletAlert"]["reputation"]["adapterEvidence"] == {
        "sourceIds": ["goplus_security"],
        "derivedEvidenceCount": 1,
        "rawPayloadsReturned": False,
    }
    assert data["walletAlert"]["reputation"]["safety"]["networkCalls"] is False
    assert data["mira"]["schema"] == "0guard.mira_preview.v1"
    assert data["mira"]["telegram_send"] is False
    assert data["qualityPolicy"]["telegramSendEnabled"] is False
    assert data["safety"]["telegramSendsEnabled"] is False
    assert data["uiSummary"]["verdict"] == "deny"

    get_r = client.get("/api/telegram/miniapp/preview?approval_intent=deny")
    assert get_r.status_code == 200
    get_data = get_r.get_json()
    assert get_data["schema"] == "0guard.telegram_miniapp_preview.v1"
    assert get_data["delivery"] == "preview_no_send"
    assert get_data["telegram_send"] is False
    assert get_data["walletAlert"]["decision"]["decision"] == "deny"
    assert get_data["mira"]["schema"] == "0guard.mira_preview.v1"


def test_ton_and_mira_claim_preview_routes_are_read_only(client):
    manifest = client.get("/tonconnect-manifest.json")
    assert manifest.status_code == 200
    manifest_body = manifest.get_json()
    assert manifest_body["name"] == "0guard"
    assert manifest_body["safety"]["sendTransactionEnabled"] is False

    status = client.get("/api/ton/status")
    assert status.status_code == 200
    status_body = status.get_json()
    assert status_body["schema"] == "0guard.ton_status.v1"
    assert status_body["tonConnect"]["sendTransactionEnabled"] is False
    assert status_body["tonConnect"]["tonProofRequested"] is False

    rules = client.get("/api/ton/risk-rules")
    assert rules.status_code == 200
    assert rules.get_json()["schema"] == "0guard.ton_risk_rules.v1"

    preview = client.post(
        "/api/ton/wallet-risk-preview",
        json={
            "address": "EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c",
            "intent": {"comment": "urgent claim airdrop"},
        },
    )
    assert preview.status_code == 200
    preview_body = preview.get_json()
    assert preview_body["schema"] == "0guard.ton_wallet_risk_preview.v1"
    assert preview_body["decision"]["decision"] == "deny"
    assert preview_body["safety"]["sendTransactionEnabled"] is False
    assert preview_body["receipt"]["liveUploadPerformed"] is False

    miniapp = client.post(
        "/api/telegram/miniapp/ton-preview",
        json={
            "address": "EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c",
            "intent": {"comment": "check before wallet prompt"},
        },
    )
    assert miniapp.status_code == 200
    miniapp_body = miniapp.get_json()
    assert miniapp_body["schema"] == "0guard.telegram_miniapp_ton_preview.v1"
    assert miniapp_body["telegram_send"] is False
    assert miniapp_body["ton"]["safety"]["tonProofRequested"] is False
    assert miniapp_body["miraClaimPreview"]["schema"] == "0guard.mira_claim_preview.v1"
    assert miniapp_body["miraClaimPreview"]["externalMiraCalls"] is False

    claim = client.post(
        "/api/mira/claim-preview",
        json={
            "subject": {"type": "demo"},
            "claims": [{"id": "demo", "claim": "0guard did not request a signature."}],
            "evidence": [{"sourceId": "0guard_runtime", "kind": "test"}],
        },
    )
    assert claim.status_code == 200
    claim_body = claim.get_json()
    assert claim_body["schema"] == "0guard.mira_claim_preview.v1"
    assert claim_body["miraVerifyReady"] is True
    assert claim_body["network_calls"] is False

    bad = client.post("/api/ton/wallet-risk-preview", json={"address": "not-ton"})
    assert bad.status_code == 400


def test_wallet_alert_preview_routes_are_quality_gated_and_no_send(client):
    address = "0x885b0892D241Cb5033C9995e09cA521d54f936b5"
    preview_response = client.post(
        "/api/wallet/alert-preview",
        json={
            "address": address,
            "intent": {
                "action": "approve",
                "mode": "live_transaction",
                "requires_signature": True,
                "calldata": (
                    "0x095ea7b3ffffffffffffffffffffffffffffffff"
                    "ffffffffffffffffffffffffffffffff"
                ),
            },
        },
    )
    assert preview_response.status_code == 200
    preview = preview_response.get_json()
    assert preview["schema"] == "0guard.wallet_alert_preview.v1"
    assert preview["mode"] == "preview_no_send"
    assert preview["decision"]["decision"] == "deny"
    assert preview["alertCount"] == 1
    assert preview["alerts"][0]["sendPolicy"]["wouldSendFromWorkbench"] is False
    assert preview["safety"]["telegramSendEnabled"] is False
    assert preview["safety"]["networkCalls"] is False

    telegram_preview = client.post(
        "/api/telegram/wallet-alert-preview",
        json={
            "address": address,
            "live": "false",
            "url": "https://docs.0g.ai.evil.example/claim",
            "sourceEvidence": [
                {"sourceId": "operator_report", "verdict": "phishing", "confidence": 0.91}
            ],
            "intent": {"action": "read_balance", "mode": "simulation"},
        },
    )
    assert telegram_preview.status_code == 200
    telegram_body = telegram_preview.get_json()
    assert telegram_body["schema"] == "0guard.telegram_wallet_alert_preview.v1"
    assert telegram_body["delivery"] == "preview_no_send"
    assert telegram_body["telegram_send"] is False
    assert telegram_body["network_calls"] is False
    assert telegram_body["walletAlert"]["decision"]["decision"] == "deny"
    assert telegram_body["walletAlert"]["reputation"]["schema"] == "0guard.reputation_probe.v1"
    assert telegram_body["walletAlert"]["reputation"]["safety"]["networkCalls"] is False
    assert telegram_body["walletAlert"]["safety"]["workbenchCanSend"] is False

    no_address = client.get("/api/wallet/alert-preview?type=transfer&amount=0")
    assert no_address.status_code == 200
    data = no_address.get_json()
    assert data["schema"] == "0guard.wallet_alert_preview.v1"
    assert data["decision"]["decision"] == "deny"

    telegram_no_address = client.get("/api/telegram/wallet-alert-preview?type=transfer&amount=0")
    assert telegram_no_address.status_code == 200
    data = telegram_no_address.get_json()
    assert data["schema"] == "0guard.telegram_wallet_alert_preview.v1"
    assert data["delivery"] == "preview_no_send"
    assert data["telegram_send"] is False
    assert data["walletAlert"]["decision"]["decision"] == "deny"

    bad = client.post("/api/wallet/alert-preview", json={"address": "not-an-address"})
    assert bad.status_code == 400

    max_zero = client.post("/api/wallet/alert-preview", json={"address": address, "max_alerts": 0})
    assert max_zero.status_code == 400


def test_wallet_alert_preview_denies_negative_amount_intents(client):
    address = "0x885b0892D241Cb5033C9995e09cA521d54f936b5"
    preview_response = client.post(
        "/api/wallet/alert-preview",
        json={
            "address": address,
            "intent": {
                "type": "transfer",
                "asset": "ETH",
                "amount": -1,
                "to": "0x000000000000000000000000000000000000dEaD",
                "chain": "0g_mainnet",
            },
        },
    )
    assert preview_response.status_code == 200
    preview = preview_response.get_json()
    assert preview["schema"] == "0guard.wallet_alert_preview.v1"
    assert preview["decision"]["decision"] == "deny"
    assert any("amount invariant" in blocker.lower() for blocker in preview["decision"]["blockers"])
    assert preview["safety"]["telegramSendEnabled"] is False
    assert preview["safety"]["transactionBroadcastingEnabled"] is False

    get_preview = client.get(
        "/api/wallet/alert-preview",
        query_string={
            "address": address,
            "intent": "transfer",
            "asset": "ETH",
            "amount": "-1",
            "to": "0x000000000000000000000000000000000000dEaD",
            "chain": "0g_mainnet",
        },
    )
    assert get_preview.status_code == 200
    preview = get_preview.get_json()
    assert preview["schema"] == "0guard.wallet_alert_preview.v1"
    assert preview["decision"]["decision"] == "deny"

    telegram_get = client.get(
        "/api/telegram/wallet-alert-preview",
        query_string={
            "address": address,
            "intent": "transfer",
            "amount": "-1",
            "to": "0x000000000000000000000000000000000000dEaD",
            "chain": "0g_mainnet",
        },
    )
    assert telegram_get.status_code == 200
    telegram_body = telegram_get.get_json()
    assert telegram_body["schema"] == "0guard.telegram_wallet_alert_preview.v1"
    assert telegram_body["delivery"] == "preview_no_send"
    assert telegram_body["telegram_send"] is False


def test_wallet_provider_guard_route_blocks_sensitive_provider_requests(client):
    preflight = client.open(
        "/api/wallet/provider-guard",
        method="OPTIONS",
        headers={
            "Origin": "http://127.0.0.1:8142",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert preflight.status_code == 204
    assert preflight.headers["Access-Control-Allow-Origin"] == "http://127.0.0.1:8142"
    assert preflight.headers["Access-Control-Allow-Methods"] == "POST, OPTIONS"

    response = client.post(
        "/api/wallet/provider-guard",
        headers={"Origin": "https://arigatoexpress.github.io"},
        json={
            "origin": "https://arigatoexpress.github.io",
            "method": "eth_sendTransaction",
            "params": [
                {
                    "chainId": "0x1",
                    "to": "0x000000000000000000000000000000000000dEaD",
                    "data": (
                        "0x095ea7b3"
                        "ffffffffffffffffffffffffffffffff"
                        "ffffffffffffffffffffffffffffffff"
                    ),
                    "value": "0x0",
                }
            ],
        },
    )

    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "https://arigatoexpress.github.io"
    payload = response.get_json()
    assert payload["schema"] == "0guard.wallet_provider_guard.v1"
    assert payload["decision"] == "deny"
    assert payload["enforcement"]["walletPromptBlocked"] is True
    assert payload["enforcement"]["providerCallAllowed"] is False
    assert payload["preflight"]["schema"] == "0guard.native_preflight.v1"
    assert payload["safety"]["providerForwardingPerformedBy0guard"] is False

    mismatch = client.post(
        "/api/wallet/provider-guard",
        headers={"Origin": "https://arigatoexpress.github.io"},
        json={
            "origin": "https://claim-drop.evil.example",
            "method": "eth_chainId",
            "params": [],
        },
    )
    assert mismatch.status_code == 400
    assert "origin mismatch" in mismatch.get_json()["error"]

    blocked_origin = client.post(
        "/api/wallet/provider-guard",
        headers={"Origin": "https://evil.example"},
        json={"origin": "https://evil.example", "method": "eth_chainId", "params": []},
    )
    assert blocked_origin.status_code == 400
    assert "not allowlisted" in blocked_origin.get_json()["error"]

    read_only = client.post(
        "/api/wallet/provider-guard",
        json={"origin": "https://safe.example", "method": "eth_chainId", "params": []},
    )
    assert read_only.status_code == 200
    assert read_only.get_json()["decision"] == "allow"

    bad = client.post("/api/wallet/provider-guard", json={"params": []})
    assert bad.status_code == 400

    disallowed = client.open(
        "/api/wallet/provider-guard",
        method="OPTIONS",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert disallowed.status_code == 204
    assert "Access-Control-Allow-Origin" not in disallowed.headers


def test_wallet_provider_external_proof_route_is_read_only_and_missing_by_default(client):
    response = client.get("/api/wallet/provider-proof")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["schema"] == "0guard.wallet_provider_external_proof_verification.v1"
    assert payload["status"] == "missing"
    assert payload["verified"] is False
    assert payload["proofBlockers"] == [
        "wallet_provider_external_proof_file_missing",
        "real_wallet_extension_proof_missing",
        "window_ethereum_proof_missing",
        "throwaway_empty_wallet_proof_missing",
        "operator_review_proof_missing",
    ]
    assert payload["blockers"] == payload["proofBlockers"]
    assert "record_wallet_provider_external_proof.py" in payload["recordProofCommandTemplate"]
    assert "--draft-file /tmp/0guard-wallet-provider-proof-draft.json" in (
        payload["draftFileRecorderCommandTemplate"]
    )
    assert payload["operatorProofPath"] == "docs/hackathon-0g/wallet-provider-external-proof.json"
    assert "--out docs/hackathon-0g/wallet-provider-external-proof.json" in (
        payload["recordProofCommandTemplate"]
    )
    assert "/app/docs/hackathon-0g/wallet-provider-external-proof.json" not in (
        payload["recordProofCommandTemplate"]
    )
    assert "/app/docs/hackathon-0g/wallet-provider-external-proof.json" not in (
        payload["draftFileRecorderCommandTemplate"]
    )
    assert (
        payload["suggestedExternalProofUrl"]
        == "https://arigatoexpress.github.io/0guard/wallet-provider-proof/"
    )
    assert payload["requiresRealWalletExtension"] is True
    assert payload["requiresWindowEthereum"] is True
    assert payload["privateKeysReturned"] is False
    assert payload["transactionSigningEnabled"] is False
    assert payload["transactionBroadcastingEnabled"] is False
    assert payload["proofDraftAssistant"]["status"] == "ready_for_external_window_ethereum_proof"
    assert payload["proofDraftAssistant"]["rawWalletAddressRequired"] is False
    assert payload["safety"]["proofVerificationOnly"] is True
    assert payload["safety"]["transactionSigningEnabled"] is False
    assert payload["safety"]["moneyMovementEnabled"] is False


def test_telegram_registration_and_mira_preview_are_local_and_redacted(monkeypatch, client):
    monkeypatch.setenv("TELEGRAM_REGISTRATION_SECRET", "test-secret-for-telegram-registration")
    monkeypatch.setenv("TELEGRAM_WEBHOOK_SECRET_TOKEN", "test-webhook-secret")

    challenge_response = client.post(
        "/api/telegram/registrations",
        json={"user_label": "ari@example.com", "scopes": ["mira_alerts", "security.digest"]},
    )
    assert challenge_response.status_code == 200
    challenge = challenge_response.get_json()["challenge"]
    assert challenge["telegram_send"] is False
    assert challenge["secret_source"] == "env"
    assert challenge["start_payload"] == challenge["token_id"]
    assert challenge["token_redacted"] is True
    assert "token" not in challenge

    opt_in_response = client.post(
        "/api/telegram/opt-ins",
        json={
            "token_id": challenge["start_payload"],
            "telegram_user": {
                "id": 123456,
                "username": "ari",
                "language_code": "en",
                "is_bot": False,
            },
        },
    )
    assert opt_in_response.status_code == 200
    opt_in = opt_in_response.get_json()
    public_json = json.dumps(opt_in)
    assert opt_in["record"]["status"] == "opted_in"
    assert "ari@example.com" not in public_json
    assert "123456" not in public_json
    assert opt_in["safety"]["telegramSendsEnabled"] is False

    replay_response = client.post(
        "/api/telegram/opt-ins",
        json={"token_id": challenge["start_payload"], "telegram_user": {"id": 999}},
    )
    assert replay_response.status_code == 400

    preview_response = client.post(
        "/api/telegram/mira-preview",
        json={
            "record_id": opt_in["record"]["record_id"],
            "intent": {
                "action": "approve",
                "mode": "live_transaction",
                "requires_signature": True,
                "calldata": "0x095ea7b3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            },
        },
    )
    assert preview_response.status_code == 200
    preview = preview_response.get_json()
    assert preview["schema"] == "0guard.mira_preview.v1"
    assert preview["delivery"] == "preview_no_send"
    assert preview["telegram_send"] is False
    assert preview["network_calls"] is False
    assert preview["decision"]["decision"] == "deny"

    da_webhook_response = client.post(
        "/api/telegram/webhook",
        json={
            "message": {
                "text": "/da",
                "from": {"id": 123456, "username": "ari"},
                "chat": {"id": 123456},
            }
        },
        headers={"X-Telegram-Bot-Api-Secret-Token": "test-webhook-secret"},
    )
    assert da_webhook_response.status_code == 200
    da_webhook = da_webhook_response.get_json()
    assert da_webhook["schema"] == "0guard.telegram_da_node_preview.v1"
    assert da_webhook["action"] == "da_node_preview"
    assert da_webhook["telegram_send"] is False
    assert da_webhook["digestPolicy"]["enabled"] is False


def test_telegram_opt_in_store_persists_records_without_sends(monkeypatch, tmp_path, client):
    monkeypatch.setenv("TELEGRAM_REGISTRATION_SECRET", "test-secret-for-telegram-registration")
    monkeypatch.setenv("TELEGRAM_OPT_IN_STORE_PATH", str(tmp_path / "telegram-opt-ins.json"))

    challenge = client.post(
        "/api/telegram/registrations",
        json={"user_label": "persistent-preview", "scopes": ["mira_alerts"]},
    ).get_json()["challenge"]
    opt_in = client.post(
        "/api/telegram/opt-ins",
        json={"token_id": challenge["start_payload"], "telegram_user": {"id": 123456}},
    ).get_json()
    record_id = opt_in["record"]["record_id"]

    store_payload = json.loads((tmp_path / "telegram-opt-ins.json").read_text())
    assert store_payload["schema"] == "0guard.telegram_opt_in_store.v1"
    assert store_payload["telegram_send"] is False
    assert store_payload["network_calls"] is False
    assert record_id in store_payload["records"]

    app_module._TELEGRAM_OPT_IN_RECORDS.clear()
    app_module._CONSUMED_TELEGRAM_TOKEN_IDS.clear()
    app_module._TELEGRAM_STORE_LOADED_PATH = None

    status = client.get("/api/telegram/status").get_json()
    assert status["registration"]["store"]["mode"] == "local_json"
    assert status["registration"]["store"]["persistent"] is True
    assert status["registration"]["activeOptIns"] == 1

    replay = client.post(
        "/api/telegram/opt-ins",
        json={"token_id": challenge["start_payload"], "telegram_user": {"id": 999}},
    )
    assert replay.status_code == 400

    preview = client.post(
        "/api/telegram/mira-preview",
        json={"record_id": record_id, "intent": {"action": "approve", "mode": "preview"}},
    )
    assert preview.status_code == 200
    assert preview.get_json()["telegram_send"] is False


def test_telegram_webapp_verify_requires_bot_token(monkeypatch, client):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    r = client.post("/api/telegram/webapp/verify", json={"init_data": "auth_date=1"})
    assert r.status_code == 503
    assert "TELEGRAM_BOT_TOKEN" in r.get_json()["error"]


def test_telegram_webapp_verify_validates_signed_init_data(monkeypatch, client):
    bot_token = "123456:ABCDEF"
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", bot_token)
    init_data = signed_telegram_init_data(
        {
            "auth_date": "1710000000",
            "user": json.dumps({"id": 123456, "username": "ari"}, separators=(",", ":")),
        },
        bot_token,
    )
    monkeypatch.setattr(
        app_module,
        "validate_webapp_init_data",
        lambda data, token: real_validate_webapp_init_data(data, token, now=1710000100),
    )

    r = client.post("/api/telegram/webapp/verify", json={"init_data": init_data})

    assert r.status_code == 200
    data = r.get_json()
    assert data["valid"] is True
    assert data["safety"]["telegramSendsEnabled"] is False
    public_json = json.dumps(data)
    assert "123456" not in public_json
    assert "ari" not in public_json


def test_telegram_webhook_requires_secret(monkeypatch, client):
    monkeypatch.delenv("TELEGRAM_WEBHOOK_SECRET_TOKEN", raising=False)
    r = client.post("/api/telegram/webhook", json={"message": {"text": "/start token"}})
    assert r.status_code == 503

    monkeypatch.setenv("TELEGRAM_WEBHOOK_SECRET_TOKEN", "webhook-secret")
    r = client.post(
        "/api/telegram/webhook",
        json={"message": {"text": "/start token"}},
        headers={"X-Telegram-Bot-Api-Secret-Token": "wrong"},
    )
    assert r.status_code == 401


def test_telegram_webhook_start_preview_and_stop(monkeypatch, client):
    monkeypatch.setenv("TELEGRAM_REGISTRATION_SECRET", "test-secret-for-telegram-registration")
    monkeypatch.setenv("TELEGRAM_WEBHOOK_SECRET_TOKEN", "webhook-secret")

    challenge = client.post(
        "/api/telegram/registrations",
        json={"user_label": "telegram-webhook-demo"},
    ).get_json()["challenge"]

    headers = {"X-Telegram-Bot-Api-Secret-Token": "webhook-secret"}
    message_base = {
        "chat": {"id": -100123456},
        "from": {"id": 123456, "username": "ari", "language_code": "en", "is_bot": False},
    }
    opt_in = client.post(
        "/api/telegram/webhook",
        json={"message": {**message_base, "text": f"/start {challenge['start_payload']}"}},
        headers=headers,
    )
    assert opt_in.status_code == 200
    opt_in_body = opt_in.get_json()
    assert opt_in_body["action"] == "opted_in"
    assert opt_in_body["telegram_send"] is False
    assert opt_in_body["network_calls"] is False

    preview = client.post(
        "/api/telegram/webhook",
        json={"message": {**message_base, "text": "Should I approve this spender?"}},
        headers=headers,
    )
    assert preview.status_code == 200
    preview_body = preview.get_json()
    assert preview_body["action"] == "preview"
    assert preview_body["delivery"] == "preview_no_send"
    assert preview_body["telegram_send"] is False

    stop = client.post(
        "/api/telegram/webhook",
        json={"message": {**message_base, "text": "/stop"}},
        headers=headers,
    )
    assert stop.status_code == 200
    assert stop.get_json()["action"] == "opted_out"

    ignored = client.post(
        "/api/telegram/webhook",
        json={"message": {**message_base, "text": "Any more alerts?"}},
        headers=headers,
    )
    assert ignored.status_code == 200
    assert ignored.get_json()["action"] == "ignored_not_opted_in"


def test_evaluate_deny_live_tx(client):
    r = client.post(
        "/api/evaluate",
        json={"intent": {"action": "swap", "mode": "live_transaction", "requires_signature": True}},
    )
    assert r.status_code == 200
    data = r.get_json()
    assert data["decision"] == "deny"


def test_hack_check_endpoint(client):
    r = client.post(
        "/api/hack-check",
        json={
            "action": "approve",
            "calldata": "0x095ea7b3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        },
    )
    assert r.status_code == 200
    data = r.get_json()
    assert any("Unlimited" in b for b in data["blockers"])


def test_domain_check(client):
    r = client.get("/api/domain?url=https://docs.0g.ai")
    assert r.status_code == 200
    data = r.get_json()
    assert data["decision"] == "allow"

    spoof = client.get("/api/domain?url=https://docs.0g.ai.evil.example")
    assert spoof.status_code == 200
    spoof_data = spoof.get_json()
    assert spoof_data["decision"] == "review"


def test_x_post_cli_requires_live_confirmation_before_credentials():
    result = subprocess.run(
        [sys.executable, "scripts/x_post.py", "--text", "hello"],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": "src"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "--live-post-confirm POST_TO_X_FROM_0GUARD" in result.stderr
    assert "Missing environment variables" not in result.stderr


def test_x_post_cli_dry_run_does_not_require_credentials():
    result = subprocess.run(
        [sys.executable, "scripts/x_post.py", "--text", "hello", "--dry-run"],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": "src"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "Dry-run complete" in result.stderr


def test_x_media_cleanup_template_does_not_require_credentials(tmp_path):
    manifest = tmp_path / "x-cleanup-template.json"
    result = subprocess.run(
        [
            sys.executable,
            "scripts/x_media_cleanup.py",
            "--template",
            "--manifest-out",
            str(manifest),
        ],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": "src"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert payload["schema"] == "0guard.x_media_cleanup_manifest.v1"
    assert payload["keepTweetIds"] == ["2054779961425461542", "2055041461218140204"]
    assert "hackquest" in payload["keepKeywords"]
    assert payload["deleteCandidateCount"] == 0


def test_x_media_cleanup_keyword_classifier_ignores_short_url_fragments():
    spec = importlib.util.spec_from_file_location(
        "x_media_cleanup_test_module",
        REPO_ROOT / "scripts" / "x_media_cleanup.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    keywords = set(module.DEFAULT_HACKATHON_KEYWORDS)

    assert not module._is_hackathon_related(
        "RT @lookdotfun: LOOK has signed a term sheet https://t.co/0gaNEXTyyy",
        keywords,
    )
    assert module._is_hackathon_related(
        "0guard is built on 0G with @0G_labs #0GHackathon #BuildOn0G",
        keywords,
    )


def test_x_media_cleanup_delete_requires_confirmation_before_credentials(tmp_path):
    manifest = tmp_path / "x-cleanup.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "0guard.x_media_cleanup_manifest.v1",
                "items": [
                    {
                        "tweetId": "111",
                        "keep": False,
                        "deleteRecommended": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            "scripts/x_media_cleanup.py",
            "--delete-from-manifest",
            str(manifest),
        ],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": "src"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "--live-delete-confirm DELETE_X_MEDIA_FROM_0GUARD" in result.stderr
    assert "Missing environment variables" not in result.stderr


def test_x_media_cleanup_delete_dry_run_does_not_require_credentials(tmp_path):
    manifest = tmp_path / "x-cleanup.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "0guard.x_media_cleanup_manifest.v1",
                "items": [
                    {
                        "tweetId": "111",
                        "keep": False,
                        "deleteRecommended": True,
                    },
                    {
                        "tweetId": "2054779961425461542",
                        "keep": True,
                        "deleteRecommended": False,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable,
            "scripts/x_media_cleanup.py",
            "--delete-from-manifest",
            str(manifest),
            "--dry-run",
        ],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": "src"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "Prepared 1 X post deletion candidate(s)" in result.stdout
    assert "Dry-run complete. No X posts deleted." in result.stdout


def test_cli_evaluate_runs_without_budget_argument_regression():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "guard0.cli",
            "evaluate",
            "--intent-json",
            '{"action":"simulate","mode":"simulation","requires_signature":false}',
        ],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": "src"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert '"decision": "allow"' in result.stdout
    assert "AttributeError" not in result.stderr


def test_cli_native_preflight_allows_read_only_payload():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "guard0.cli",
            "native-preflight",
            "--payload-json",
            '{"surface":"evm","operation":"read_status","chain":"eip155:8453"}',
        ],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": "src"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert '"schema": "0guard.native_preflight.v1"' in result.stdout
    assert '"decision": "allow"' in result.stdout
    assert '"transactionSigningEnabled": false' in result.stdout


def test_cli_proof_ladder_returns_no_side_effect_packet():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "guard0.cli",
            "proof-ladder",
            "--payload-json",
            json.dumps(
                {
                    "intent": {
                        "action": "approve",
                        "mode": "live_transaction",
                        "requires_signature": True,
                        "prompt_text": (
                            "keep secret "
                            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        ),
                    }
                }
            ),
        ],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": "src"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert '"schema": "0guard.0g_proof_ladder.v1"' in result.stdout
    assert '"id": "alignmentVerifier"' in result.stdout
    assert '"moneyMovementEnabled": false' in result.stdout
    assert "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" not in result.stdout


def test_cli_reputation_adapter_normalizer_returns_derived_evidence_without_fetching():
    payload = {
        "sourceId": "chainabuse",
        "subject": {
            "url": "https://docs.0g.ai.evil.example/claim",
            "address": "0x02228b0afcdbEdf8180D96Fc181Da3AF5DD1d1ab",
            "chain": "eip155:1",
        },
        "payload": {
            "reports": [
                {
                    "checked": True,
                    "confidence_score": 91,
                    "category": "phishing",
                    "reportUrl": "https://chainabuse.example/private/report",
                }
            ]
        },
    }
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "guard0.cli",
            "normalize-reputation-adapter",
            "--payload-json",
            json.dumps(payload),
        ],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": "src"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert '"schema": "0guard.reputation_adapter_preview.v1"' in result.stdout
    assert '"rawPayloadReturned": false' in result.stdout
    assert '"networkCalls": false' in result.stdout
    assert "chainabuse.example" not in result.stdout


def test_cli_reputation_shadow_cache_returns_no_fetch_cache_without_raw_urls():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "guard0.cli",
            "reputation-shadow-cache",
        ],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": "src"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert '"schema": "0guard.reputation_shadow_cache.v1"' in result.stdout
    assert '"networkCalls": false' in result.stdout
    assert '"rawPayloadsReturned": false' in result.stdout
    assert "docs.0g.ai.evil.example/claim" not in result.stdout


def test_telegram_post_cli_requires_live_confirmation_before_credentials():
    result = subprocess.run(
        [sys.executable, "scripts/telegram_post.py", "--text", "hello"],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": "src"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "--live-send-confirm SEND_TO_TELEGRAM_FROM_0GUARD" in result.stderr
    assert "TELEGRAM_BOT_TOKEN" not in result.stderr


def test_telegram_post_cli_text_dry_run_does_not_require_credentials():
    result = subprocess.run(
        [sys.executable, "scripts/telegram_post.py", "--text", "hello", "--dry-run"],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": "src"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "[DRY RUN] Would post 1 message to Telegram" in result.stdout


def test_pi_mesh_route_can_ingest_snapshot(monkeypatch, tmp_path, client):
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
                        "eth0": {"carrier": True},
                    },
                    "rvpi-b": {
                        "status": "ethernet_ssh_reachable_identity_unverified",
                        "ethernetIpv4": "10.77.4.12",
                        "identityVerified": False,
                    },
                },
                "cluster": {
                    "primaryReachable": True,
                    "ethernetCarrierReady": True,
                    "peerEthernetReachable": True,
                    "peerIdentityVerified": False,
                    "edgeApiReady": True,
                    "clusterReady": False,
                    "blockers": ["rvpi_b_identity_unverified"],
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
    monkeypatch.setattr(app_module, "DEFAULT_PI_MESH_STATUS_PATH", str(snapshot_path))

    r = client.get("/api/0g/pi-mesh?snapshot=1")
    data = r.get_json()

    assert r.status_code == 200
    assert data["mode"] == "rv_pi_mesh_snapshot_file"
    assert data["readiness"]["peerEthernetReachable"] is True
    assert data["readiness"]["peerIdentityVerified"] is False
    assert data["safety"]["telegramSendsEnabled"] is False


def test_x_auto_post_workflow_is_manual_and_dry_run_by_default():
    workflow = (REPO_ROOT / ".github/workflows/x-auto-post.yml").read_text()
    assert "workflow_dispatch:" in workflow
    assert "push:" not in workflow
    assert "live_post_confirm" in workflow
    assert "--live-post-confirm POST_TO_X_FROM_0GUARD" in workflow
    assert "--dry-run" in workflow
