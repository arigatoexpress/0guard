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

from flask import Flask, Response, jsonify, render_template, request

from guard0.crosschain import (
    cross_chain_catalog,
    cross_chain_readiness,
    virtuals_facilitator_manifest,
)
from guard0.incident_data import detection_coverage, filter_incidents, incident_summary
from guard0.mira import build_mira_security_preview
from guard0.osint import (
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

app = Flask(__name__)

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
    "#load-submission-brief",
    "#load-submission-packet",
    "#load-submission-readiness",
    "#load-threat-passport",
    "#load-cross-chain-catalog",
    "#load-cross-chain-readiness",
    "#load-virtuals-facilitator",
    "#cross-chain-output",
    "#osint-output",
    "#verify-receipt-hash",
    "#verify-receipt",
    "#telegram-register-output",
    "#mira-output",
    "#telegram-user-label",
    "#create-telegram-registration",
    "#complete-telegram-opt-in",
    "#run-mira-preview",
    "#wallet-status",
    "#telegram-status",
    "#deploy-status",
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
            "/api/telegram/webhook",
            "/api/telegram/mira-preview",
        ],
        "safety": {
            "telegramSendsEnabled": False,
            "webhookRegistrationEnabled": False,
            "networkCalls": False,
            "secretDisplayEnabled": False,
            "workbenchCanTriggerLiveActions": False,
        },
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


@app.route("/")
def index():
    return render_template("index.html")


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
                "/api/integrations/cross-chain",
                "/api/integrations/cross-chain/readiness",
                "/api/integrations/virtuals-facilitator",
                "/api/hackathon/submission-brief",
                "/api/hackathon/submission-packet",
                "/api/hackathon/readiness",
                "/api/hackathon/threat-passport",
                "/api/telegram/status",
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
                "load-submission-brief",
                "load-submission-packet",
                "load-submission-readiness",
                "load-threat-passport",
                "load-cross-chain-catalog",
                "load-cross-chain-readiness",
                "load-virtuals-facilitator",
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
    return jsonify(_telegram_mira_status_payload())


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


@app.route("/api/health", methods=["GET"])
def api_health():
    cfg = get_0g_config()
    return jsonify(
        {
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
    # Simple domain guard — can be expanded
    allowed = ["0g.ai", "hackquest.io", "github.com", "docs.0g.ai"]
    is_allowed = any(a in url.lower() for a in allowed)
    return jsonify(
        {
            "url": url,
            "decision": "allow" if is_allowed else "review",
            "reasons": [] if is_allowed else ["Domain not in curated allowlist"],
        }
    )


def _truthy_query_arg(name: str) -> bool:
    return request.args.get(name, "").lower() in {"1", "true", "yes", "on"}


def main() -> None:
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8109"))
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
