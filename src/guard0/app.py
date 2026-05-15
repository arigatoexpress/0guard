"""
Flask API & Dashboard for 0G Hack Guard
========================================
Endpoints:
  GET  /api/health
  GET  /api/frontend-contract
  GET  /api/external-action-contracts
  POST /api/evaluate
  POST /api/hack-check
  GET  /api/domain
"""

from __future__ import annotations

import os
import secrets
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, render_template, request

from guard0.crosschain import (
    cross_chain_catalog,
    cross_chain_readiness,
    virtuals_facilitator_manifest,
)
from guard0.external_guardrails import (
    evaluate_external_guardrail,
    external_guardrail_catalog,
)
from guard0.incident_data import detection_coverage, filter_incidents, incident_summary
from guard0.ika import evaluate_ika_signing_request, ika_integration_manifest
from guard0.mira import build_mira_claim_preview, build_mira_security_preview
from guard0.osint import (
    evolving_threat_intelligence,
    hackathon_submission_brief,
    hackquest_readiness_audit,
    hackquest_submission_packet,
    incident_provenance_matrix,
    osint_readiness,
    osint_signals,
    signature_map,
    source_registry_public,
    threat_receipt_passport,
)
from guard0.policy import evaluate_intent
from guard0.roadmap import ecosystem_roadmap, intelligence_stream_plan
from guard0.ton import (
    build_ton_wallet_risk_preview,
    ton_risk_rules,
    ton_status,
    tonconnect_manifest,
)
from guard0.crypto_hack_guard import check_crypto_hack_signatures
from guard0.chain import build_0g_status, get_0g_config, verify_anchor
from guard0.telegram_bot import TelegramWebAppAuthError, validate_webapp_init_data
from guard0.telegram_subscriptions import (
    DEFAULT_SCOPE,
    TokenVerificationError,
    build_opt_in_record,
    build_telegram_registration_challenge,
    ensure_registration_token_not_replayed,
    public_opt_in_status,
    verify_telegram_registration_token,
)
from guard0.wallet_alerts import build_wallet_alert_preview, wallet_alert_quality_policy

app = Flask(__name__)

DEMO_EVM_ADDRESS = "0x000000000000000000000000000000000000dead"

_EPHEMERAL_TELEGRAM_REGISTRATION_SECRET = secrets.token_urlsafe(32)
_PENDING_TELEGRAM_CHALLENGES: dict[str, dict] = {}
_CONSUMED_TELEGRAM_TOKEN_IDS: set[str] = set()
_TELEGRAM_OPT_IN_RECORDS: dict[str, dict] = {}

FRONTEND_REQUIRED_SELECTORS = (
    "#nav-intent",
    "#nav-signatures",
    "#nav-domain",
    "#mode-pill",
    "#send-pill",
    "#chain-pill",
    "#decision-pill",
    "#play-story",
    "#run-drift-scenario",
    "#run-bridge-scenario",
    "#run-upgrade-scenario",
    "#run-safe-scenario",
    "#flow-canvas",
    "#flow-packet",
    "#plain-explanation",
    "#technical-output",
    "#risk-list",
    "#intent-input",
    "#run-evaluate",
    "#load-deny-sample",
    "#load-allow-sample",
    "#hack-input",
    "#run-hack-check",
    "#domain-input",
    "#run-domain-check",
    "#result-output",
    "#contract-output",
    "#zg-status-output",
    "#data-flow-output",
    "#provenance-summary",
    "#load-data-summary",
    "#load-provenance-matrix",
    "#load-live-provenance",
    "#load-detection-coverage",
    "#load-signature-map",
    "#load-osint-sources",
    "#load-osint-readiness",
    "#load-osint-signals",
    "#load-evolving-intel",
    "#load-submission-brief",
    "#load-submission-packet",
    "#load-submission-readiness",
    "#load-threat-passport",
    "#load-cross-chain-catalog",
    "#load-cross-chain-readiness",
    "#load-virtuals-facilitator",
    "#load-ika-integration",
    "#load-external-guardrails",
    "#run-external-guardrail-check",
    "#cross-chain-output",
    "#osint-output",
    "#verify-receipt-hash",
    "#verify-receipt",
    "#telegram-register-output",
    "#mira-output",
    "#wallet-address-input",
    "#run-wallet-alert-preview",
    "#run-telegram-wallet-alert-preview",
    "#wallet-alert-output",
    "#telegram-user-label",
    "#create-telegram-registration",
    "#complete-telegram-opt-in",
    "#run-mira-preview",
    "#wallet-status",
    "#telegram-status",
    "#deploy-status",
    "#open-telegram-miniapp",
    "#load-intelligence-stream-plan",
    "#load-ecosystem-roadmap",
)

MINIAPP_REQUIRED_SELECTORS = (
    "#miniapp-root",
    "#miniapp-mode",
    "#miniapp-auth-status",
    "#miniapp-session-output",
    "#miniapp-wallet-address",
    "#miniapp-intent-kind",
    "#miniapp-chain",
    "#miniapp-asset",
    "#miniapp-amount",
    "#miniapp-to",
    "#miniapp-preview-alert",
    "#miniapp-run-mira",
    "#miniapp-ton-address",
    "#miniapp-preview-ton",
    "#miniapp-alert-message",
    "#miniapp-ton-output",
    "#miniapp-output",
    "#miniapp-mira-output",
    "#miniapp-quality-output",
)

DOMAIN_ALLOWLIST = (
    "0g.ai",
    "docs.0g.ai",
    "hackquest.io",
    "github.com",
)


def external_action_contracts_payload() -> dict:
    """Return the non-mutating external action posture for the workbench."""
    return {
        "schema": "0guard.external_action_contracts.v1",
        "defaultMode": "dry_run",
        "workbenchCanTriggerLiveActions": False,
        "livePostingEnabled": False,
        "telegramSendsEnabled": False,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "moneyMovementEnabled": False,
        "secretDisplayEnabled": False,
        "actions": [
            {
                "id": "x-post",
                "script": "scripts/x_post.py",
                "default": "dry_run",
                "liveConfirmationFlag": "--live-post-confirm POST_TO_X_FROM_0GUARD",
                "reachableFromWorkbench": False,
            },
            {
                "id": "telegram-post",
                "script": "scripts/telegram_post.py",
                "default": "dry_run",
                "liveConfirmationFlag": "--live-send-confirm SEND_TO_TELEGRAM_FROM_0GUARD",
                "reachableFromWorkbench": False,
            },
            {
                "id": "0g-contract-deploy",
                "script": "scripts/deploy_0g.py",
                "default": "blocked_from_workbench",
                "liveConfirmationFlag": "local CLI only with PRIVATE_KEY and explicit operator review",
                "reachableFromWorkbench": False,
            },
        ],
        "blockedCapabilities": [
            "wallet signature requests",
            "raw transaction broadcasting",
            "X/Telegram posting from the browser",
            "secret display or echo",
            "fund movement",
            "production deploys",
        ],
    }


def _telegram_registration_secret() -> tuple[str, str]:
    configured = os.getenv("TELEGRAM_REGISTRATION_SECRET")
    if configured:
        return configured, "env"
    return _EPHEMERAL_TELEGRAM_REGISTRATION_SECRET, "ephemeral_demo"


def _telegram_mira_status_payload() -> dict:
    _, secret_source = _telegram_registration_secret()
    bot_username = os.getenv("TELEGRAM_BOT_USERNAME", "")
    return {
        "schema": "0guard.telegram_mira_status.v1",
        "mode": "opt_in_preview_no_sends",
        "mira": {
            "enabled": True,
            "responseMode": "deterministic_policy_preview",
            "externalLlmCalls": False,
        },
        "registration": {
            "secretSource": secret_source,
            "secretConfiguredForProduction": secret_source == "env",
            "pendingChallenges": len(_PENDING_TELEGRAM_CHALLENGES),
            "activeOptIns": sum(
                1 for record in _TELEGRAM_OPT_IN_RECORDS.values() if record.get("status") == "opted_in"
            ),
            "defaultScopes": [DEFAULT_SCOPE],
            "walletAlertPolicy": wallet_alert_quality_policy(),
            "telegramBotUsernameConfigured": bool(bot_username),
        },
        "miniAppAuth": {
            "telegramInitDataSupported": True,
            "botTokenConfigured": bool(os.getenv("TELEGRAM_BOT_TOKEN")),
            "serverSideValidationRequired": True,
        },
        "apiRoutes": [
            "/api/telegram/status",
            "/api/telegram/registrations",
            "/api/telegram/opt-ins",
            "/api/telegram/webapp/verify",
            "/api/telegram/miniapp/contract",
            "/api/telegram/miniapp/session",
            "/api/telegram/miniapp/preview",
            "/api/telegram/miniapp/ton-preview",
            "/api/telegram/webhook",
            "/api/telegram/mira-preview",
            "/api/telegram/wallet-alert-preview",
            "/api/mira/claim-preview",
            "/api/ton/status",
            "/api/ton/risk-rules",
            "/api/ton/wallet-risk-preview",
        ],
        "safety": {
            "telegramSendsEnabled": False,
            "webhookRegistrationEnabled": False,
            "networkCalls": False,
            "secretDisplayEnabled": False,
            "workbenchCanTriggerLiveActions": False,
        },
    }


def _telegram_webhook_info() -> dict | None:
    """Read-only Telegram webhook metadata without exposing bot tokens."""
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not token:
        return None

    import json
    import urllib.request

    url = f"https://api.telegram.org/bot{token}/getWebhookInfo"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception:
        return None

    if not isinstance(payload, dict) or not payload.get("ok"):
        return None
    result = payload.get("result") or {}
    if not isinstance(result, dict):
        return None

    webhook_url = str(result.get("url") or "").strip()
    return {
        "url_set": bool(webhook_url),
        "pending_update_count": int(result.get("pending_update_count") or 0),
        "last_error_message": result.get("last_error_message"),
    }


def _pending_token_from_request(value: str) -> str:
    pending = _PENDING_TELEGRAM_CHALLENGES.get(value)
    if pending:
        return pending["token"]
    return value


def _telegram_user_from_init_data(init_data: dict) -> dict:
    user = init_data.get("user") or {}
    if not isinstance(user, dict):
        user = {}
    return {
        key: value
        for key, value in {
            "id": user.get("id"),
            "username": user.get("username"),
            "first_name": user.get("first_name"),
            "last_name": user.get("last_name"),
            "language_code": user.get("language_code"),
            "is_bot": user.get("is_bot"),
        }.items()
        if value is not None
    }


def _telegram_user_from_message(message: dict) -> dict:
    chat = message.get("chat") or {}
    sender = message.get("from") or {}
    if not isinstance(chat, dict):
        chat = {}
    if not isinstance(sender, dict):
        sender = {}
    return {
        key: value
        for key, value in {
            "id": sender.get("id"),
            "chat_id": chat.get("id"),
            "username": sender.get("username"),
            "first_name": sender.get("first_name"),
            "last_name": sender.get("last_name"),
            "language_code": sender.get("language_code"),
            "is_bot": sender.get("is_bot"),
        }.items()
        if value is not None
    }


def _active_telegram_record_for_user(telegram_user: dict) -> dict | None:
    user_id = str(telegram_user.get("id", ""))
    chat_id = str(telegram_user.get("chat_id", ""))
    for record in _TELEGRAM_OPT_IN_RECORDS.values():
        stored = record.get("telegram_user") or {}
        if record.get("status") != "opted_in":
            continue
        if user_id and str(stored.get("id", "")) == user_id:
            return record
        if chat_id and str(stored.get("chat_id", "")) == chat_id:
            return record
    return None


def _mark_telegram_user_opted_out(telegram_user: dict) -> int:
    changed = 0
    user_id = str(telegram_user.get("id", ""))
    chat_id = str(telegram_user.get("chat_id", ""))
    for record in _TELEGRAM_OPT_IN_RECORDS.values():
        stored = record.get("telegram_user") or {}
        if user_id and str(stored.get("id", "")) == user_id:
            record["status"] = "opted_out"
            changed += 1
        elif chat_id and str(stored.get("chat_id", "")) == chat_id:
            record["status"] = "opted_out"
            changed += 1
    return changed


def _telegram_webhook_secret_error() -> tuple[Response, int] | None:
    configured = os.getenv("TELEGRAM_WEBHOOK_SECRET_TOKEN", "")
    if not configured:
        return jsonify({"error": "TELEGRAM_WEBHOOK_SECRET_TOKEN is not configured"}), 503
    received = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if not secrets.compare_digest(received, configured):
        return jsonify({"error": "Invalid Telegram webhook secret token"}), 401
    return None


def _create_telegram_opt_in(
    token_input: str,
    telegram_user: dict,
    scopes: list[str] | None = None,
) -> dict:
    secret, _secret_source = _telegram_registration_secret()
    pending = _PENDING_TELEGRAM_CHALLENGES.get(token_input)
    token = _pending_token_from_request(token_input)
    record_scopes = scopes or (pending or {}).get("scopes")
    verified = verify_telegram_registration_token(token, secret)
    checked = ensure_registration_token_not_replayed(
        verified,
        consumed_token_ids=_CONSUMED_TELEGRAM_TOKEN_IDS,
    )
    record = build_opt_in_record(checked, telegram_user=telegram_user, scopes=record_scopes)
    _CONSUMED_TELEGRAM_TOKEN_IDS.add(checked["token_id"])
    _PENDING_TELEGRAM_CHALLENGES.pop(checked["token_id"], None)
    _TELEGRAM_OPT_IN_RECORDS[record["record_id"]] = record
    return record


def _request_init_data(body: dict) -> str:
    return str(body.get("initData") or body.get("init_data") or "").strip()


def _public_telegram_user(telegram_user: dict) -> dict:
    return public_opt_in_status(
        {
            "telegram_user": telegram_user,
            "scopes": [],
            "challenge": {},
        }
    )["telegram_user"]


def _telegram_init_data_error(message: str, status_code: int) -> tuple[Response, int]:
    return (
        jsonify(
            {
                "schema": "0guard.telegram_miniapp_error.v1",
                "error": message,
                "safety": _telegram_mira_status_payload()["safety"],
            }
        ),
        status_code,
    )


def _telegram_miniapp_auth(
    init_data: str,
) -> tuple[dict, dict | None, tuple[Response, int] | None]:
    auth = {
        "initDataPresent": bool(init_data),
        "validated": False,
        "mode": "local_browser_preview",
        "serverSideValidationRequired": True,
        "user": None,
        "optInStatus": "not_attached",
        "record": None,
    }
    if not init_data:
        return auth, None, None

    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not bot_token:
        return auth, None, _telegram_init_data_error(
            "TELEGRAM_BOT_TOKEN is not configured",
            503,
        )
    try:
        data = validate_webapp_init_data(init_data, bot_token)
    except TelegramWebAppAuthError as exc:
        return auth, None, _telegram_init_data_error(str(exc), 401)

    telegram_user = _telegram_user_from_init_data(data)
    record = _active_telegram_record_for_user(telegram_user)
    public_record = public_opt_in_status(record) if record else None
    auth.update(
        {
            "validated": True,
            "mode": "telegram_webapp",
            "user": _public_telegram_user(telegram_user),
            "optInStatus": record.get("status") if record else "not_attached",
            "record": public_record,
        }
    )
    return auth, record, None


def _telegram_miniapp_contract_payload() -> dict:
    status = _telegram_mira_status_payload()
    return {
        "schema": "0guard.telegram_miniapp_contract.v1",
        "route": "/telegram",
        "title": "0guard Telegram Mini App",
        "launchSurface": "telegram_web_app_or_browser_preview",
        "requiredText": [
            "0guard Mini App",
            "Wallet alert",
            "Mira add-on",
            "Preview only",
            "No Telegram sends",
            "TON Risk Passport",
        ],
        "requiredSelectors": list(MINIAPP_REQUIRED_SELECTORS),
        "telegramApi": {
            "usesTelegramWebAppJs": True,
            "initDataSource": "window.Telegram.WebApp.initData",
            "serverSideValidationRequired": True,
            "sendDataUsed": False,
        },
        "apiRoutes": [
            "/api/telegram/status",
            "/api/telegram/webapp/verify",
            "/api/telegram/miniapp/contract",
            "/api/telegram/miniapp/session",
            "/api/telegram/miniapp/preview",
            "/api/telegram/miniapp/ton-preview",
            "/api/telegram/mira-preview",
            "/api/telegram/wallet-alert-preview",
            "/api/mira/claim-preview",
            "/api/ton/status",
            "/api/ton/risk-rules",
            "/api/ton/wallet-risk-preview",
            "/tonconnect-manifest.json",
        ],
        "mira": status["mira"],
        "ton": ton_status(),
        "qualityPolicy": wallet_alert_quality_policy(),
        "safety": status["safety"],
    }


def _default_miniapp_intent() -> dict:
    return {
        "action": "approve",
        "mode": "live_transaction",
        "requires_signature": True,
        "calldata": (
            "0x095ea7b3"
            "ffffffffffffffffffffffffffffffff"
            "ffffffffffffffffffffffffffffffff"
        ),
        "prompt_text": "Telegram Mini App preview for an unlimited token approval request.",
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/telegram")
def telegram_miniapp():
    return render_template("telegram_mini_app.html")


@app.route("/favicon.ico")
def favicon():
    return Response(status=204)


@app.route("/api/frontend-contract", methods=["GET"])
def api_frontend_contract():
    return jsonify(
        {
            "schema": "0guard.frontend_contract.v1",
            "route": "/",
            "mode": "read_only_pre_wallet",
            "network": "0g",
            "chainId": get_0g_config()["chain_id"],
            "requiredText": [
                "0G Hack Guard",
                "What happens before an AI agent touches a wallet?",
                "Simple view",
                "Intent Firewall",
                "Hack Signature Check",
                "Domain Guard",
                "Data Flow",
                "Telegram Mira Opt-In",
                "Mira Telegram Preview",
                "Wallet Alert Preview",
                "Telegram Mini App",
                "TON Risk Passport",
                "External Action Contract",
                "Safety Inspector",
                "no signing",
                "external sends blocked",
            ],
            "requiredSelectors": list(FRONTEND_REQUIRED_SELECTORS),
            "apiRoutes": [
                "/api/health",
                "/api/0g/status",
                "/api/0g/receipt",
                "/api/data/summary",
                "/api/data/incidents",
                "/api/data/provenance",
                "/api/data/detection-coverage",
                "/api/data/signature-map",
                "/api/osint/sources",
                "/api/osint/readiness",
                "/api/osint/signals",
                "/api/intelligence/evolving",
                "/api/intelligence/data-streams",
                "/api/roadmap",
                "/api/wallet/alert-preview",
                "/api/ton/status",
                "/api/ton/risk-rules",
                "/api/ton/wallet-risk-preview",
                "/tonconnect-manifest.json",
                "/api/integrations/cross-chain",
                "/api/integrations/cross-chain/readiness",
                "/api/integrations/virtuals-facilitator",
                "/api/integrations/ika",
                "/api/integrations/ika/evaluate",
                "/api/integrations/external-guardrails",
                "/api/integrations/external-guardrails/evaluate",
                "/api/hackathon/submission-brief",
                "/api/hackathon/submission-packet",
                "/api/hackathon/readiness",
                "/api/hackathon/threat-passport",
                "/api/telegram/status",
                "/api/telegram/webapp/verify",
                "/api/telegram/miniapp/contract",
                "/api/telegram/miniapp/session",
                "/api/telegram/miniapp/preview",
                "/api/telegram/miniapp/ton-preview",
                "/api/telegram/mira-preview",
                "/api/telegram/wallet-alert-preview",
                "/api/mira/claim-preview",
                "/api/external-action-contracts",
                "/api/evaluate",
                "/api/hack-check",
                "/api/domain?url=https%3A%2F%2Fdocs.0g.ai",
            ],
            "primaryActions": [
                "evaluate-intent",
                "play-story",
                "run-drift-scenario",
                "run-bridge-scenario",
                "run-upgrade-scenario",
                "run-safe-scenario",
                "load-deny-sample",
                "load-simulation-sample",
                "run-hack-check",
                "run-domain-check",
                "load-data-summary",
                "load-provenance-matrix",
                "load-live-provenance",
                "load-detection-coverage",
                "load-signature-map",
                "load-osint-sources",
                "load-osint-readiness",
                "load-osint-signals",
                "load-evolving-intel",
                "load-intelligence-stream-plan",
                "load-ecosystem-roadmap",
                "load-submission-brief",
                "load-submission-packet",
                "load-submission-readiness",
                "load-threat-passport",
                "load-cross-chain-catalog",
                "load-cross-chain-readiness",
                "load-virtuals-facilitator",
                "load-ika-integration",
                "load-external-guardrails",
                "run-external-guardrail-check",
                "run-wallet-alert-preview",
                "run-telegram-wallet-alert-preview",
            ],
            "safety": external_action_contracts_payload(),
        }
    )


@app.route("/api/external-action-contracts", methods=["GET"])
def api_external_action_contracts():
    return jsonify(external_action_contracts_payload())


@app.route("/api/data/summary", methods=["GET"])
def api_data_summary():
    return jsonify(incident_summary())


@app.route("/api/data/incidents", methods=["GET"])
def api_data_incidents():
    min_loss = request.args.get("min_loss_usd")
    try:
        min_loss_usd = int(min_loss) if min_loss is not None else None
    except ValueError:
        return jsonify({"error": "min_loss_usd must be an integer"}), 400
    if min_loss_usd is not None and min_loss_usd < 0:
        return jsonify({"error": "min_loss_usd must be non-negative"}), 400

    limit = request.args.get("limit")
    try:
        limit_value = int(limit) if limit is not None else 50
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    if limit_value < 1 or limit_value > 200:
        return jsonify({"error": "limit must be between 1 and 200"}), 400

    return jsonify(
        {
            "schema": "0guard.incidents.v1",
            "incidents": filter_incidents(
                chain=request.args.get("chain"),
                attack_vector=request.args.get("attack_vector"),
                min_loss_usd=min_loss_usd,
                limit=limit_value,
            ),
        }
    )


@app.route("/api/data/detection-coverage", methods=["GET"])
def api_data_detection_coverage():
    return jsonify(detection_coverage())


@app.route("/api/data/provenance", methods=["GET"])
def api_data_provenance():
    live = _truthy_query_arg("live")
    return jsonify(incident_provenance_matrix(live=live))


@app.route("/api/data/signature-map", methods=["GET"])
def api_data_signature_map():
    return jsonify(signature_map())


@app.route("/api/osint/sources", methods=["GET"])
def api_osint_sources():
    return jsonify(source_registry_public())


@app.route("/api/osint/readiness", methods=["GET"])
def api_osint_readiness():
    live = _truthy_query_arg("live")
    return jsonify(osint_readiness(live=live))


@app.route("/api/osint/signals", methods=["GET"])
def api_osint_signals():
    live = _truthy_query_arg("live")
    limit = request.args.get("limit")
    try:
        limit_value = int(limit) if limit is not None else 20
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    if limit_value < 1 or limit_value > 100:
        return jsonify({"error": "limit must be between 1 and 100"}), 400
    return jsonify(osint_signals(live=live, limit=limit_value))


@app.route("/api/intelligence/evolving", methods=["GET"])
def api_evolving_threat_intelligence():
    live = _truthy_query_arg("live")
    limit = request.args.get("limit")
    try:
        limit_value = int(limit) if limit is not None else 10
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    if limit_value < 1 or limit_value > 50:
        return jsonify({"error": "limit must be between 1 and 50"}), 400
    return jsonify(evolving_threat_intelligence(live=live, limit=limit_value))


@app.route("/api/intelligence/data-streams", methods=["GET"])
def api_intelligence_data_streams():
    return jsonify(intelligence_stream_plan())


@app.route("/api/roadmap", methods=["GET"])
def api_roadmap():
    return jsonify(ecosystem_roadmap())


@app.route("/api/wallet/alert-preview", methods=["GET", "POST"])
def api_wallet_alert_preview():
    body = (request.get_json(silent=True) or {}) if request.method == "POST" else {}
    address = body.get("address") or request.args.get("address") or ""
    if not address:
        address = DEMO_EVM_ADDRESS
    intent = body.get("intent")
    if intent is None and request.method == "GET":
        intent_type = request.args.get("intent") or request.args.get("type")
        amount = request.args.get("amount")
        to_address = request.args.get("to")
        chain = request.args.get("chain")
        asset = request.args.get("asset")
        if any(value is not None for value in (intent_type, amount, to_address, chain, asset)):
            intent = {
                "type": intent_type,
                "amount": amount,
                "to": to_address,
                "chain": chain,
                "asset": asset,
            }
    live = _truthy_value(body.get("live")) if request.method == "POST" else _truthy_query_arg("live")
    max_alerts_raw = _request_value(body, "max_alerts", 5)
    try:
        max_alerts = int(max_alerts_raw)
        preview = build_wallet_alert_preview(
            address,
            intent=intent,
            live=live,
            max_alerts=max_alerts,
        )
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(preview)


@app.route("/api/integrations/cross-chain", methods=["GET"])
def api_cross_chain_catalog():
    return jsonify(cross_chain_catalog())


@app.route("/api/integrations/cross-chain/readiness", methods=["GET"])
def api_cross_chain_readiness():
    live = _truthy_query_arg("live")
    include_non_default = _truthy_query_arg("include_non_default")
    return jsonify(
        cross_chain_readiness(live=live, include_non_default=include_non_default)
    )


@app.route("/api/integrations/virtuals-facilitator", methods=["GET"])
def api_virtuals_facilitator():
    return jsonify(virtuals_facilitator_manifest())


@app.route("/api/integrations/ika", methods=["GET"])
def api_ika_integration():
    return jsonify(ika_integration_manifest())


@app.route("/api/integrations/ika/evaluate", methods=["POST"])
def api_ika_integration_evaluate():
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(evaluate_ika_signing_request(body))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/integrations/external-guardrails", methods=["GET"])
def api_external_guardrails():
    return jsonify(external_guardrail_catalog())


@app.route("/api/integrations/external-guardrails/evaluate", methods=["POST"])
def api_external_guardrail_evaluate():
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(evaluate_external_guardrail(body))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/hackathon/submission-brief", methods=["GET"])
def api_hackathon_submission_brief():
    return jsonify(hackathon_submission_brief())


@app.route("/api/hackathon/submission-packet", methods=["GET"])
def api_hackathon_submission_packet():
    return jsonify(hackquest_submission_packet())


@app.route("/api/hackathon/readiness", methods=["GET"])
def api_hackathon_readiness():
    return jsonify(hackquest_readiness_audit())


@app.route("/api/hackathon/threat-passport", methods=["GET"])
def api_hackathon_threat_passport():
    return jsonify(threat_receipt_passport())


@app.route("/api/telegram/status", methods=["GET"])
def api_telegram_status():
    payload = _telegram_mira_status_payload()
    live_readback = _truthy_query_arg("live")
    payload["liveReadback"] = live_readback
    payload["safety"] = {**payload["safety"], "networkCalls": live_readback}
    webhook = _telegram_webhook_info() if live_readback else None
    compat = {
        "botTokenConfigured": (payload.get("miniAppAuth") or {}).get("botTokenConfigured"),
        "telegramBotUsernameConfigured": (payload.get("registration") or {}).get(
            "telegramBotUsernameConfigured"
        ),
        "secretSource": (payload.get("registration") or {}).get("secretSource"),
        "secretConfiguredForProduction": (payload.get("registration") or {}).get(
            "secretConfiguredForProduction"
        ),
        "telegramSendsEnabled": (payload.get("safety") or {}).get("telegramSendsEnabled"),
        "telegramBotUsername": os.getenv("TELEGRAM_BOT_USERNAME") or None,
    }
    if webhook:
        compat.update(
            {
                "webhookUrlSet": webhook.get("url_set"),
                "webhookPendingUpdateCount": webhook.get("pending_update_count"),
                "webhookLastErrorMessage": webhook.get("last_error_message"),
            }
        )
    return jsonify({**payload, **compat})


@app.route("/api/telegram/registrations", methods=["POST"])
def api_telegram_registrations():
    body = request.get_json(silent=True) or {}
    secret, secret_source = _telegram_registration_secret()
    try:
        challenge = build_telegram_registration_challenge(
            user_label=body.get("user_label", "demo-operator"),
            secret=secret,
            ttl_seconds=int(body.get("ttl_seconds", 900)),
        )
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

    scopes = body.get("scopes") or [DEFAULT_SCOPE]
    _PENDING_TELEGRAM_CHALLENGES[challenge["token_id"]] = {
        "token": challenge["token"],
        "scopes": scopes,
    }

    bot_username = os.getenv("TELEGRAM_BOT_USERNAME", "")
    start_link = (
        f"https://t.me/{bot_username}?start={challenge['token_id']}" if bot_username else None
    )
    public_challenge = {key: value for key, value in challenge.items() if key != "token"}
    return jsonify(
        {
            "schema": "0guard.telegram_registration_challenge.v1",
            "challenge": {
                **public_challenge,
                "start_payload": challenge["token_id"],
                "telegram_start_link": start_link,
                "secret_source": secret_source,
                "token_redacted": True,
            },
            "safety": _telegram_mira_status_payload()["safety"],
        }
    )


@app.route("/api/telegram/opt-ins", methods=["POST"])
def api_telegram_opt_ins():
    body = request.get_json(silent=True) or {}
    token_input = body.get("token") or body.get("token_id") or ""
    telegram_user = body.get("telegram_user") or {"id": "demo-local-user"}
    try:
        record = _create_telegram_opt_in(
            token_input=token_input,
            telegram_user=telegram_user,
            scopes=body.get("scopes"),
        )
    except (TokenVerificationError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(
        {
            "schema": "0guard.telegram_opt_in_response.v1",
            "record": public_opt_in_status(record),
            "safety": _telegram_mira_status_payload()["safety"],
        }
    )


@app.route("/api/telegram/webapp/verify", methods=["POST"])
def api_telegram_webapp_verify():
    body = request.get_json(silent=True) or {}
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not bot_token:
        return jsonify({"error": "TELEGRAM_BOT_TOKEN is not configured"}), 503
    try:
        data = validate_webapp_init_data(body.get("init_data", ""), bot_token)
    except TelegramWebAppAuthError as exc:
        return jsonify({"error": str(exc)}), 401
    return jsonify(
        {
            "schema": "0guard.telegram_webapp_auth.v1",
            "valid": True,
            "user": public_opt_in_status(
                {
                    "telegram_user": _telegram_user_from_init_data(data),
                    "scopes": [],
                    "challenge": {},
                }
            )["telegram_user"],
            "safety": _telegram_mira_status_payload()["safety"],
        }
    )


@app.route("/api/telegram/miniapp/contract", methods=["GET"])
def api_telegram_miniapp_contract():
    return jsonify(_telegram_miniapp_contract_payload())


@app.route("/api/telegram/miniapp/session", methods=["GET", "POST"])
def api_telegram_miniapp_session():
    body = request.get_json(silent=True) or {} if request.method == "POST" else {}
    if request.method == "GET":
        init_data = str(request.args.get("initData") or request.args.get("init_data") or "").strip()
        if init_data:
            body = {"initData": init_data}
    auth, _record, error = _telegram_miniapp_auth(_request_init_data(body))
    if error:
        return error
    return jsonify(
        {
            "schema": "0guard.telegram_miniapp_session.v1",
            "local_browser_preview": auth["mode"] == "local_browser_preview",
            "mode": auth["mode"],
            "auth": auth,
            "launch": {
                "route": "/telegram",
                "mobileFirst": True,
                "openedInsideTelegram": auth["initDataPresent"],
                "validatedTelegramUser": auth["validated"],
                "serverSideInitDataValidation": True,
                "sendDataUsed": False,
            },
            "status": _telegram_mira_status_payload(),
            "qualityPolicy": wallet_alert_quality_policy(),
            "defaultIntent": _default_miniapp_intent(),
            "safety": _telegram_mira_status_payload()["safety"],
        }
    )


@app.route("/api/telegram/miniapp/preview", methods=["GET", "POST"])
def api_telegram_miniapp_preview():
    body = request.get_json(silent=True) or {} if request.method == "POST" else {}
    if request.method == "GET":
        init_data = str(request.args.get("initData") or request.args.get("init_data") or "").strip()
        if init_data:
            body = {"initData": init_data}
    auth, auth_record, error = _telegram_miniapp_auth(_request_init_data(body))
    if error:
        return error

    record_id = body.get("record_id")
    record = auth_record
    if record_id:
        record = _TELEGRAM_OPT_IN_RECORDS.get(record_id)
        if not record:
            return jsonify({"error": "Unknown or inactive Telegram opt-in record"}), 403

    intent = body.get("intent")
    if intent is None and request.method == "GET":
        approval_intent = str(request.args.get("approval_intent") or "").strip().lower()
        if approval_intent == "deny":
            intent = {
                "type": "transfer",
                "amount": "0",
                "to": DEMO_EVM_ADDRESS,
                "chain": "0g",
                "asset": "demo",
            }
    intent = intent or _default_miniapp_intent()

    address = body.get("address") or request.args.get("address") or ""
    if not address:
        address = DEMO_EVM_ADDRESS
    try:
        wallet_preview = build_wallet_alert_preview(
            address,
            intent=intent,
            live=_truthy_value(body.get("live", False)),
            max_alerts=int(_request_value(body, "max_alerts", 3)),
        )
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

    mira_preview = build_mira_security_preview(intent, opt_in_record=record)
    top_alert = wallet_preview["alerts"][0] if wallet_preview["alerts"] else None
    top_reason = (
        wallet_preview["decision"]["blockers"]
        or wallet_preview["decision"]["warnings"]
        or ["No direct wallet alert."]
    )[0]
    return jsonify(
        {
            "schema": "0guard.telegram_miniapp_preview.v1",
            "delivery": "preview_no_send",
            "telegram_send": False,
            "network_calls": wallet_preview["safety"]["networkCalls"]
            or mira_preview["network_calls"],
            "mode": auth["mode"],
            "auth": auth,
            "walletAlert": wallet_preview,
            "mira": mira_preview,
            "message": wallet_preview["telegramPreview"],
            "uiSummary": {
                "verdict": wallet_preview["decision"]["decision"],
                "severity": wallet_preview["decision"]["severity"],
                "alertScore": top_alert["score"] if top_alert else None,
                "topReason": top_reason,
                "recommendedAction": top_alert["recommendedAction"] if top_alert else "keep watching",
            },
            "qualityPolicy": wallet_preview["qualityPolicy"],
            "safety": _telegram_mira_status_payload()["safety"],
        }
    )


@app.route("/api/telegram/miniapp/ton-preview", methods=["POST"])
def api_telegram_miniapp_ton_preview():
    body = request.get_json(silent=True) or {}
    auth, _auth_record, error = _telegram_miniapp_auth(_request_init_data(body))
    if error:
        return error
    try:
        preview = build_ton_wallet_risk_preview(
            body.get("address") or body.get("tonAddress") or "",
            intent=body.get("intent") or {},
            network=body.get("network") or "mainnet",
            live=_truthy_value(body.get("live", False)),
            include_activity=_truthy_value(body.get("include_activity", False)),
        )
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400

    mira_claim_preview = _build_mira_claim_response(
        subject={
            "type": "ton_wallet_risk_passport",
            "addressHash": preview["address"]["hash"],
            "network": preview["network"],
        },
        claims=preview["miraClaims"],
        evidence=preview["evidence"],
    )
    return jsonify(
        {
            "schema": "0guard.telegram_miniapp_ton_preview.v1",
            "delivery": "preview_no_send",
            "telegram_send": False,
            "network_calls": preview["safety"]["networkCalls"],
            "mode": auth["mode"],
            "auth": auth,
            "ton": preview,
            "miraClaimPreview": mira_claim_preview,
            "message": (
                f"0guard TON passport: {preview['decision']['decision'].upper()} "
                f"({preview['decision']['severity']}). "
                "Preview only; no TON transaction, signature, tonProof, or Telegram send."
            ),
            "safety": _telegram_mira_status_payload()["safety"],
        }
    )


@app.route("/api/telegram/webhook", methods=["POST"])
def api_telegram_webhook():
    secret_error = _telegram_webhook_secret_error()
    if secret_error:
        return secret_error

    update = request.get_json(silent=True) or {}
    message = update.get("message") or {}
    if not isinstance(message, dict):
        return jsonify({"schema": "0guard.telegram_webhook.v1", "action": "ignored"}), 200

    text = str(message.get("text") or "").strip()
    telegram_user = _telegram_user_from_message(message)

    if text.startswith("/start"):
        payload = text.removeprefix("/start").strip()
        if not payload:
            return jsonify(
                {
                    "schema": "0guard.telegram_webhook.v1",
                    "action": "registration_token_required",
                    "telegram_send": False,
                    "network_calls": False,
                }
            )
        try:
            record = _create_telegram_opt_in(token_input=payload, telegram_user=telegram_user)
        except (TokenVerificationError, ValueError) as exc:
            return jsonify({"schema": "0guard.telegram_webhook.v1", "error": str(exc)}), 400
        return jsonify(
            {
                "schema": "0guard.telegram_webhook.v1",
                "action": "opted_in",
                "record": public_opt_in_status(record),
                "telegram_send": False,
                "network_calls": False,
            }
        )

    if text.startswith("/stop"):
        changed = _mark_telegram_user_opted_out(telegram_user)
        return jsonify(
            {
                "schema": "0guard.telegram_webhook.v1",
                "action": "opted_out",
                "recordsUpdated": changed,
                "telegram_send": False,
                "network_calls": False,
            }
        )

    record = _active_telegram_record_for_user(telegram_user)
    if not record:
        return jsonify(
            {
                "schema": "0guard.telegram_webhook.v1",
                "action": "ignored_not_opted_in",
                "telegram_send": False,
                "network_calls": False,
            }
        )

    preview = build_mira_security_preview(
        {"prompt_text": text, "mode": "telegram_message", "requires_signature": False},
        opt_in_record=record,
    )
    return jsonify({"schema": "0guard.telegram_webhook.v1", "action": "preview", **preview})


@app.route("/api/telegram/mira-preview", methods=["POST"])
def api_telegram_mira_preview():
    body = request.get_json(silent=True) or {}
    record_id = body.get("record_id")
    record = _TELEGRAM_OPT_IN_RECORDS.get(record_id) if record_id else None
    if record_id and not record:
        return jsonify({"error": "Unknown or inactive Telegram opt-in record"}), 403

    intent = body.get("intent") or body
    preview = build_mira_security_preview(intent, opt_in_record=record)
    return jsonify(preview)


@app.route("/api/telegram/wallet-alert-preview", methods=["GET", "POST"])
def api_telegram_wallet_alert_preview():
    body = (request.get_json(silent=True) or {}) if request.method == "POST" else {}
    record_id = body.get("record_id")
    record = _TELEGRAM_OPT_IN_RECORDS.get(record_id) if record_id else None
    if record_id and not record:
        return jsonify({"error": "Unknown or inactive Telegram opt-in record"}), 403

    address = body.get("address") or request.args.get("address") or ""
    if not address:
        address = DEMO_EVM_ADDRESS
    intent = body.get("intent")
    if intent is None and request.method == "GET":
        intent_type = request.args.get("intent") or request.args.get("type")
        amount = request.args.get("amount")
        to_address = request.args.get("to")
        chain = request.args.get("chain")
        asset = request.args.get("asset")
        if any(value is not None for value in (intent_type, amount, to_address, chain, asset)):
            intent = {
                "type": intent_type,
                "amount": amount,
                "to": to_address,
                "chain": chain,
                "asset": asset,
            }
    try:
        preview = build_wallet_alert_preview(
            address,
            intent=intent,
            live=_truthy_value(body.get("live", False))
            if request.method == "POST"
            else _truthy_query_arg("live"),
            max_alerts=int(_request_value(body, "max_alerts", 5)),
        )
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(
        {
            "schema": "0guard.telegram_wallet_alert_preview.v1",
            "delivery": "preview_no_send",
            "telegram_send": False,
            "network_calls": preview["safety"]["networkCalls"],
            "opt_in_status": (record or {}).get("status", "not_attached"),
            "record_id": (record or {}).get("record_id"),
            "message": preview["telegramPreview"],
            "walletAlert": preview,
            "safety": _telegram_mira_status_payload()["safety"],
        }
    )


@app.route("/tonconnect-manifest.json", methods=["GET"])
def api_tonconnect_manifest():
    return jsonify(tonconnect_manifest(request.host_url))


@app.route("/api/ton/status", methods=["GET"])
def api_ton_status():
    return jsonify(ton_status())


@app.route("/api/ton/risk-rules", methods=["GET"])
def api_ton_risk_rules():
    return jsonify(ton_risk_rules())


@app.route("/api/ton/wallet-risk-preview", methods=["POST"])
def api_ton_wallet_risk_preview():
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(
            build_ton_wallet_risk_preview(
                body.get("address") or "",
                intent=body.get("intent") or {},
                network=body.get("network") or "mainnet",
                live=_truthy_value(body.get("live", False)),
                include_activity=_truthy_value(body.get("include_activity", False)),
            )
        )
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/mira/claim-preview", methods=["POST"])
def api_mira_claim_preview():
    body = request.get_json(silent=True) or {}
    return jsonify(
        _build_mira_claim_response(
            subject=body.get("subject") or {},
            claims=body.get("claims") or [],
            evidence=body.get("evidence") or [],
        )
    )


@app.route("/api/health", methods=["GET"])
def api_health():
    cfg = get_0g_config()
    return jsonify(
        {
            "schema": "0guard.health.v1",
            "ok": True,
            "service": "zg-hack-guard",
            "version": "0.1.0",
            "0g_chain_id": cfg["chain_id"],
            "0g_chain_rpc": cfg["rpc"],
            "0g_receipt_contract": cfg["receipt_contract"],
            "0g_storage_node": os.getenv("ZGS_NODE_URL", "not_configured"),
            "telegram_mira": _telegram_mira_status_payload(),
            "safety_flags": {
                "read_only": True,
                "wallet_signatures_blocked": True,
                "external_sends_blocked_from_workbench": True,
                "live_posting_enabled": False,
                "telegram_sends_enabled": False,
                "money_movement_enabled": False,
            },
        }
    )


@app.route("/healthz", methods=["GET"])
def healthz():
    payload = api_health().get_json()
    payload["schema"] = "0guard.healthz.v1"
    payload["ok"] = True
    return jsonify(payload)


@app.route("/api/0g/status", methods=["GET"])
def api_0g_status():
    return jsonify(build_0g_status())


@app.route("/api/0g/receipt", methods=["GET"])
def api_0g_receipt():
    receipt_hash = request.args.get("receipt_hash", "")
    tx_hash = request.args.get("tx_hash")
    return jsonify(verify_anchor(receipt_hash=receipt_hash, tx_hash=tx_hash))


@app.route("/api/evaluate", methods=["POST"])
def api_evaluate():
    body = request.get_json(silent=True) or {}
    intent = body.get("intent", body)
    budget = body.get("budget")
    agent_id = body.get("agent_id", "")
    decision = evaluate_intent(
        intent,
        budget=budget,
        agent_id=agent_id,
        enable_0g_anchor=body.get("enable_0g_anchor", False),
        enable_0g_storage=body.get("enable_0g_storage", False),
    )
    return jsonify(decision.to_dict())


@app.route("/api/hack-check", methods=["POST"])
def api_hack_check():
    payload = request.get_json(silent=True) or {}
    from guard0.policy import normalize_intent

    result = check_crypto_hack_signatures(normalize_intent(payload))
    return jsonify(result.to_dict())


@app.route("/api/domain", methods=["GET"])
def api_domain():
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "Missing url parameter"}), 400
    domain = _domain_decision(url)
    return jsonify(
        {
            "url": url,
            "host": domain["host"],
            "matchedAllowlistHost": domain["matched"],
            "decision": "allow" if domain["allowed"] else "review",
            "reasons": [] if domain["allowed"] else ["Domain not in curated allowlist"],
        }
    )


def _request_value(body: dict, name: str, default: object) -> object:
    if request.method == "POST" and name in body:
        return body[name]
    return request.args.get(name, default)


def _build_mira_claim_response(
    *,
    subject: dict,
    claims: list[dict],
    evidence: list[dict],
) -> dict:
    return build_mira_claim_preview(subject=subject, claims=claims, evidence=evidence)


def _domain_decision(url: str) -> dict:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.hostname or "").lower().rstrip(".")
    for allowed in DOMAIN_ALLOWLIST:
        allowed_host = allowed.lower()
        if host == allowed_host or host.endswith(f".{allowed_host}"):
            return {"host": host, "allowed": True, "matched": allowed_host}
    return {"host": host, "allowed": False, "matched": None}


def _truthy_query_arg(name: str) -> bool:
    return request.args.get(name, "").lower() in {"1", "true", "yes", "on"}


def _truthy_value(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "on"}
    return bool(value)


def main() -> None:
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8109"))
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
