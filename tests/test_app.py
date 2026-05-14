"""Smoke tests for Flask app."""

import hashlib
import hmac
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
    assert "/api/integrations/cross-chain" in data["apiRoutes"]
    assert "/api/integrations/cross-chain/readiness" in data["apiRoutes"]
    assert "/api/integrations/virtuals-facilitator" in data["apiRoutes"]
    assert "/api/hackathon/submission-brief" in data["apiRoutes"]
    assert "/api/hackathon/submission-packet" in data["apiRoutes"]
    assert "/api/hackathon/readiness" in data["apiRoutes"]
    assert "/api/hackathon/threat-passport" in data["apiRoutes"]
    assert "/api/telegram/status" in data["apiRoutes"]
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
    assert "#load-submission-packet" in data["requiredSelectors"]
    assert "#load-submission-readiness" in data["requiredSelectors"]
    assert "#load-threat-passport" in data["requiredSelectors"]
    assert "#load-cross-chain-catalog" in data["requiredSelectors"]
    assert "#load-cross-chain-readiness" in data["requiredSelectors"]
    assert "#load-virtuals-facilitator" in data["requiredSelectors"]
    assert "#cross-chain-output" in data["requiredSelectors"]
    assert "#telegram-register-output" in data["requiredSelectors"]
    assert "#mira-output" in data["requiredSelectors"]


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
    assert "run-evaluate" in (package_root / "static" / "app.js").read_text()
    assert ".shell" in (package_root / "static" / "styles.css").read_text()


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
    assert coverage_body["coveredCount"] >= 12

    provenance = client.get("/api/data/provenance")
    assert provenance.status_code == 200
    provenance_body = provenance.get_json()
    assert provenance_body["schema"] == "0guard.incident_provenance_matrix.v1"
    assert provenance_body["coverage"]["incidentCount"] == 28
    assert provenance_body["coverage"]["withMatchedEvidence"] >= 20
    assert provenance_body["sourceStatus"]["status"] == "canonical_dataset"
    assert provenance_body["sourceStatus"]["evidenceMode"] == "canonical_dataset_evidence"
    assert provenance_body["live"] is False
    assert provenance_body["safety"]["rawPayloadsReturned"] is False

    signature_map = client.get("/api/data/signature-map")
    assert signature_map.status_code == 200
    signature_body = signature_map.get_json()
    assert signature_body["schema"] == "0guard.signature_map.v1"
    assert signature_body["incidentCount"] == 28
    assert signature_body["gapCount"] >= 1


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
    assert passport_body["provenance"]["coverage"]["withMatchedEvidence"] == 26
    assert passport_body["signatureCoverage"]["incidentCount"] == 28
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


def test_osint_signal_route_rejects_bad_limit(client):
    assert client.get("/api/osint/signals?limit=bad").status_code == 400
    assert client.get("/api/osint/signals?limit=0").status_code == 400
    assert client.get("/api/osint/signals?limit=101").status_code == 400


def test_data_incident_filters_reject_bad_inputs(client):
    assert client.get("/api/data/incidents?min_loss_usd=bad").status_code == 400
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
