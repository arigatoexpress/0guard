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
    assert data["safety_flags"]["external_sends_blocked_from_workbench"] is True
    assert data["safety_flags"]["money_movement_enabled"] is False
    assert data["telegram_mira"]["safety"]["telegramSendsEnabled"] is False
    assert data["0g_chain_id"] == 16602
    assert data["0g_chain_rpc"] == "https://evmrpc-testnet.0g.ai"
    assert data["0g_receipt_contract"] == "0x0000000000000000000000000000000000000000"


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
    assert "/api/0g/receipt" in data["apiRoutes"]
    assert "/api/data/summary" in data["apiRoutes"]
    assert "/api/data/incidents" in data["apiRoutes"]
    assert "/api/data/provenance" in data["apiRoutes"]
    assert "/api/data/detection-coverage" in data["apiRoutes"]
    assert "/api/data/signature-map" in data["apiRoutes"]
    assert "/api/osint/sources" in data["apiRoutes"]
    assert "/api/osint/readiness" in data["apiRoutes"]
    assert "/api/osint/signals" in data["apiRoutes"]
    assert "/api/intelligence/evolving" in data["apiRoutes"]
    assert "/api/intelligence/data-streams" in data["apiRoutes"]
    assert "/api/roadmap" in data["apiRoutes"]
    assert "/api/wallet/alert-preview" in data["apiRoutes"]
    assert "/api/ton/status" in data["apiRoutes"]
    assert "/api/ton/risk-rules" in data["apiRoutes"]
    assert "/api/ton/wallet-risk-preview" in data["apiRoutes"]
    assert "/tonconnect-manifest.json" in data["apiRoutes"]
    assert "/api/integrations/cross-chain" in data["apiRoutes"]
    assert "/api/integrations/cross-chain/readiness" in data["apiRoutes"]
    assert "/api/integrations/virtuals-facilitator" in data["apiRoutes"]
    assert "/api/integrations/ika" in data["apiRoutes"]
    assert "/api/integrations/ika/evaluate" in data["apiRoutes"]
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
    assert "/api/mira/claim-preview" in data["apiRoutes"]
    assert "#run-evaluate" in data["requiredSelectors"]
    assert "#play-story" in data["requiredSelectors"]
    assert "#flow-canvas" in data["requiredSelectors"]
    assert "#plain-explanation" in data["requiredSelectors"]
    assert "#technical-output" in data["requiredSelectors"]
    assert "#risk-list" in data["requiredSelectors"]
    assert "#contract-output" in data["requiredSelectors"]
    assert "#zg-status-output" in data["requiredSelectors"]
    assert "#verify-receipt-hash" in data["requiredSelectors"]
    assert "#verify-receipt" in data["requiredSelectors"]
    assert "#data-flow-output" in data["requiredSelectors"]
    assert "#provenance-summary" in data["requiredSelectors"]
    assert "#load-provenance-matrix" in data["requiredSelectors"]
    assert "#load-live-provenance" in data["requiredSelectors"]
    assert "#osint-output" in data["requiredSelectors"]
    assert "#load-evolving-intel" in data["requiredSelectors"]
    assert "#load-intelligence-stream-plan" in data["requiredSelectors"]
    assert "#load-ecosystem-roadmap" in data["requiredSelectors"]
    assert "#load-submission-packet" in data["requiredSelectors"]
    assert "#load-submission-readiness" in data["requiredSelectors"]
    assert "#load-threat-passport" in data["requiredSelectors"]
    assert "#load-cross-chain-catalog" in data["requiredSelectors"]
    assert "#load-cross-chain-readiness" in data["requiredSelectors"]
    assert "#load-virtuals-facilitator" in data["requiredSelectors"]
    assert "#load-ika-integration" in data["requiredSelectors"]
    assert "#load-external-guardrails" in data["requiredSelectors"]
    assert "#run-external-guardrail-check" in data["requiredSelectors"]
    assert "#cross-chain-output" in data["requiredSelectors"]
    assert "#telegram-register-output" in data["requiredSelectors"]
    assert "#mira-output" in data["requiredSelectors"]
    assert "#wallet-address-input" in data["requiredSelectors"]
    assert "#run-wallet-alert-preview" in data["requiredSelectors"]
    assert "#run-telegram-wallet-alert-preview" in data["requiredSelectors"]
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
    assert "run-evaluate" in (package_root / "static" / "app.js").read_text()
    assert "miniappRunPreview" in (package_root / "static" / "telegram-miniapp.js").read_text()
    assert ".shell" in (package_root / "static" / "styles.css").read_text()


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

    streams = client.get("/api/intelligence/data-streams")
    assert streams.status_code == 200
    stream_body = streams.get_json()
    assert stream_body["schema"] == "0guard.intelligence_stream_plan.v1"
    assert stream_body["rightsPolicy"]["rawPayloadResaleAllowed"] is False
    assert stream_body["streams"][0]["id"] == "unified_reputation_adapter"

    roadmap = client.get("/api/roadmap")
    assert roadmap.status_code == 200
    roadmap_body = roadmap.get_json()
    assert roadmap_body["schema"] == "0guard.ecosystem_roadmap.v1"
    assert roadmap_body["positioning"]["category"] == "pre-wallet safety layer for autonomous agents"
    assert roadmap_body["safety"]["bridgingEnabled"] is False

    brief = client.get("/api/hackathon/submission-brief")
    assert brief.status_code == 200
    brief_body = brief.get_json()
    assert brief_body["schema"] == "0guard.hackathon_submission_brief.v1"
    assert brief_body["project"]["name"] == "0guard"
    assert brief_body["dataProduct"]["incidentCount"] == 28
    assert brief_body["submissionRequirements"]["publicXPost"]["mandatory"] is True

    packet = client.get("/api/hackathon/submission-packet")
    assert packet.status_code == 200
    packet_body = packet.get_json()
    assert packet_body["schema"] == "0guard.hackquest_submission_packet.v1"
    assert packet_body["formFields"]["demoVideoUrl"].endswith("0guard-hackquest-demo-final.mp4")
    assert packet_body["xPost"]["mediaPath"].endswith("0guard-workbench-provenance.png")
    assert packet_body["safety"]["rawPayloadsReturned"] is False

    readiness = client.get("/api/hackathon/readiness")
    assert readiness.status_code == 200
    readiness_body = readiness.get_json()
    assert readiness_body["schema"] == "0guard.hackquest_readiness_audit.v1"
    assert readiness_body["mainnetRequirement"]["chainId"] == 16661
    assert readiness_body["submittableNow"] is True
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
    assert ika_preflight_body["safety"]["transactionSigningEnabled"] is False

    guardrails = client.get("/api/integrations/external-guardrails")
    assert guardrails.status_code == 200
    guardrail_body = guardrails.get_json()
    assert guardrail_body["schema"] == "0guard.external_guardrail_catalog.v1"
    assert guardrail_body["safety"]["moneyMovementEnabled"] is False
    assert {item["targetId"] for item in guardrail_body["guardrails"]} >= {
        "lighter_exchange",
        "chainlink_ccip",
        "layerzero_v2",
        "wormhole_ntt",
    }

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


def test_0g_receipt_verifier_is_read_only_without_contract(client):
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
    assert "/api/ton/status" in data["apiRoutes"]
    assert data["registration"]["walletAlertPolicy"]["telegramSendEnabled"] is False
    # Compatibility keys for steward readbacks (flat shape)
    assert isinstance(data["botTokenConfigured"], bool)
    assert isinstance(data["telegramBotUsernameConfigured"], bool)
    assert data["secretSource"] in ("env", "ephemeral_demo")
    assert isinstance(data["secretConfiguredForProduction"], bool)
    assert data["telegramSendsEnabled"] is False


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
            "intent": {"action": "read_balance", "mode": "simulation"},
        },
    )
    assert telegram_preview.status_code == 200
    telegram_body = telegram_preview.get_json()
    assert telegram_body["schema"] == "0guard.telegram_wallet_alert_preview.v1"
    assert telegram_body["delivery"] == "preview_no_send"
    assert telegram_body["telegram_send"] is False
    assert telegram_body["network_calls"] is False
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


def test_telegram_registration_and_mira_preview_are_local_and_redacted(monkeypatch, client):
    monkeypatch.setenv("TELEGRAM_REGISTRATION_SECRET", "test-secret-for-telegram-registration")

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


def test_x_auto_post_workflow_is_manual_and_dry_run_by_default():
    workflow = (REPO_ROOT / ".github/workflows/x-auto-post.yml").read_text()
    assert "workflow_dispatch:" in workflow
    assert "push:" not in workflow
    assert "live_post_confirm" in workflow
    assert "--live-post-confirm POST_TO_X_FROM_0GUARD" in workflow
    assert "--dry-run" in workflow
