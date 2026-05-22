"""
Flask API & Dashboard for 0G Hack Guard
========================================
Endpoints:
  GET  /api/health
  GET  /api/healthz
  GET  /healthz
  GET  /api/frontend-contract
  GET  /api/external-action-contracts
  POST /api/evaluate
  POST /api/hack-check
  GET  /api/domain
"""

from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, render_template, request

from guard0.crosschain import (
    cross_chain_catalog,
    cross_chain_readiness,
    virtuals_facilitator_manifest,
)
from guard0.cyber_threats import build_cyber_threat_repository
from guard0.da_node import (
    DEFAULT_STORAGE_STATUS_PATH,
    build_da_node_status,
    build_storage_node_status,
    build_telegram_da_node_preview,
    build_telegram_storage_node_preview,
)
from guard0.deployment_readiness import build_deployment_readiness
from guard0.node_business import (
    build_0g_node_business_plan,
    build_alignment_node_status,
    build_telegram_node_business_preview,
    build_validator_capacity_status,
)
from guard0.node_readiness_proof import build_node_pi_readiness_proof_status
from guard0.peer_protection import (
    DEFAULT_PI_MESH_STATUS_PATH,
    build_0g_hot_wallet_resources,
    build_0g_private_computer_integration,
    build_peer_outreach_preview,
    build_peer_protection_plan,
    build_pi_mesh_plan,
)
from guard0.private_compute_adapter import (
    build_private_compute_paid_smoke_proof_status,
    build_private_compute_smoke_preview,
)
from guard0.case_file import build_threat_case_file
from guard0.developer_kit import developer_kit_manifest
from guard0.external_guardrails import (
    evaluate_external_guardrail,
    external_guardrail_catalog,
)
from guard0.experiments import frontier_experiments, run_frontier_experiment_preview
from guard0.hackathon_integrations import (
    arbitrum_integration_plan,
    arbitrum_open_house_buildathon_plan,
    metamask_1shot_cookoff_plan,
    metamask_1shot_permission_preview,
    metamask_integration_plan,
    next_hackathon_plan,
)
from guard0.incident_data import detection_coverage, filter_incidents, incident_summary
from guard0.historical_feature_store import build_historical_feature_store
from guard0.ika import evaluate_ika_signing_request, ika_integration_manifest
from guard0.intelligence_events import intelligence_events_snapshot
from guard0.live_detector_candidates import live_detector_candidates
from guard0.local_inference import (
    build_historical_backfill_plan,
    build_local_inference_mesh,
    build_telegram_local_inference_preview,
    build_x402_data_products,
)
from guard0.mira import build_mira_claim_preview, build_mira_security_preview
from guard0.native_preflight import build_native_preflight, hackathon_strategy
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
from guard0.product_brief import product_brief
from guard0.production_gaps import build_model_training_roadmap, build_production_gap_matrix
from guard0.proof_ladder import build_proof_ladder
from guard0.readiness import production_readiness
from guard0.roadmap import ecosystem_roadmap, intelligence_stream_plan
from guard0.reputation import (
    CURATED_DOMAIN_ALLOWLIST,
    build_reputation_probe,
    domain_decision,
    reputation_connector_manifest,
)
from guard0.reputation_backfill import build_reputation_backfill_status
from guard0.reputation_connector_worker import reputation_connector_snapshot
from guard0.reputation_adapters import (
    normalize_reputation_adapters_from_payload,
    normalize_reputation_adapter_payload,
    reputation_adapter_catalog,
)
from guard0.reputation_shadow import build_reputation_shadow_cache
from guard0.strategy_review import build_strategy_review
from guard0.ton import (
    build_ton_wallet_risk_preview,
    ton_risk_rules,
    ton_status,
    tonconnect_manifest,
)
from guard0.training_data import build_incident_detector_eval_set
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
from guard0.storage_upload_manifest import build_storage_upload_manifest
from guard0.storage_peer_diagnostics import (
    DEFAULT_STORAGE_PEER_DIAGNOSTICS_PATH,
    build_storage_peer_diagnostics,
)
from guard0.wallet_alerts import build_wallet_alert_preview, wallet_alert_quality_policy
from guard0.wallet_provider_guard import (
    build_wallet_provider_external_proof_status,
    build_wallet_provider_guard,
)
from guard0.x402_guard import (
    BASE_SEPOLIA_CAIP2,
    X402_TESTNET_FACILITATOR_URL,
    build_x402_settlement_policy,
    build_x402_settlement_proof_status,
    build_x402_wallet_preflight_paid_response,
    build_x402_wallet_preflight_dry_run,
)

app = Flask(__name__)

DEFAULT_WALLET_PROVIDER_GUARD_ORIGINS = frozenset(
    {
        "https://arigatoexpress.github.io",
        "https://guard0-miniapp-s77j6bxyra-uc.a.run.app",
        "http://localhost:8109",
        "http://localhost:8142",
        "http://127.0.0.1:8109",
        "http://127.0.0.1:8142",
    }
)

# Stable demo address used for read-only previews. Keep this constant explicit
# so GET endpoints remain usable without requiring query params.
DEMO_EVM_ADDRESS = "0x000000000000000000000000000000000000dead"

_EPHEMERAL_TELEGRAM_REGISTRATION_SECRET = secrets.token_urlsafe(32)
_PENDING_TELEGRAM_CHALLENGES: dict[str, dict] = {}
_CONSUMED_TELEGRAM_TOKEN_IDS: set[str] = set()
_TELEGRAM_OPT_IN_RECORDS: dict[str, dict] = {}
_TELEGRAM_STORE_LOADED_PATH: str | None = None
DEFAULT_TELEGRAM_OPT_IN_STORE_PATH = Path("content/telegram_opt_ins.local.json")

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
    "#run-threat-case-file",
    "#load-deny-sample",
    "#load-allow-sample",
    "#hack-input",
    "#run-hack-check",
    "#domain-input",
    "#run-domain-check",
    "#result-output",
    "#case-file-output",
    "#contract-output",
    "#zg-status-output",
    "#data-flow-output",
    "#provenance-summary",
    "#load-data-summary",
    "#load-provenance-matrix",
    "#load-live-provenance",
    "#load-detection-coverage",
    "#load-signature-map",
    "#load-historical-backfill-plan",
    "#load-historical-feature-store",
    "#load-osint-sources",
    "#load-osint-readiness",
    "#load-osint-signals",
    "#load-phishdestroy-worker",
    "#load-reputation-backfill-status",
    "#load-evolving-intel",
    "#load-cyber-threat-repository",
    "#load-intelligence-events",
    "#load-detector-candidates",
    "#load-product-brief",
    "#load-production-readiness",
    "#load-deployment-readiness",
    "#load-production-gaps",
    "#load-model-training-roadmap",
    "#load-incident-eval-set",
    "#load-submission-brief",
    "#load-submission-packet",
    "#load-submission-readiness",
    "#load-threat-passport",
    "#load-x402-data-products",
    "#load-x402-dry-run",
    "#load-x402-settlement-policy",
    "#load-cross-chain-catalog",
    "#load-cross-chain-readiness",
    "#load-arbitrum-integration",
    "#load-arbitrum-buildathon",
    "#load-metamask-integration",
    "#load-metamask-1shot-plan",
    "#run-metamask-1shot-preview",
    "#load-virtuals-facilitator",
    "#load-ika-integration",
    "#run-reputation-probe",
    "#load-reputation-adapters",
    "#load-reputation-shadow-cache",
    "#run-native-preflight",
    "#load-hackathon-strategy",
    "#load-next-hackathon-plan",
    "#load-developer-kit",
    "#load-external-guardrails",
    "#run-external-guardrail-check",
    "#cross-chain-output",
    "#osint-output",
    "#verify-receipt-hash",
    "#verify-receipt",
    "#load-da-node-status",
    "#load-storage-node-status",
    "#load-storage-peer-diagnostics",
    "#load-storage-upload-manifest",
    "#run-telegram-da-node-preview",
    "#load-node-business",
    "#load-alignment-node-status",
    "#load-validator-capacity",
    "#load-private-computer",
    "#load-private-compute-smoke-preview",
    "#load-local-inference",
    "#run-telegram-local-inference-preview",
    "#load-hot-wallet-resources",
    "#load-peer-protection",
    "#run-peer-outreach-preview",
    "#load-pi-mesh",
    "#run-telegram-node-business-preview",
    "#da-node-output",
    "#telegram-register-output",
    "#mira-output",
    "#wallet-address-input",
    "#run-wallet-alert-preview",
    "#run-telegram-wallet-alert-preview",
    "#run-wallet-provider-guard",
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
    "#load-frontier-experiments",
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
    "#miniapp-reputation-url",
    "#miniapp-reputation-label",
    "#miniapp-preview-alert",
    "#miniapp-run-mira",
    "#miniapp-ton-address",
    "#miniapp-preview-ton",
    "#miniapp-alert-message",
    "#miniapp-evidence-panel",
    "#miniapp-evidence-verdict",
    "#miniapp-evidence-source",
    "#miniapp-evidence-boundary",
    "#miniapp-evidence-receipt",
    "#miniapp-ton-output",
    "#miniapp-output",
    "#miniapp-mira-output",
    "#miniapp-quality-output",
)

DOMAIN_ALLOWLIST = CURATED_DOMAIN_ALLOWLIST


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
            {
                "id": "0g-peer-chain-message",
                "script": "future operator-approved peer sender",
                "default": "draft_only",
                "liveConfirmationFlag": (
                    "local CLI only with opt-in peer, exact message hash, and operator approval"
                ),
                "reachableFromWorkbench": False,
            },
        ],
        "blockedCapabilities": [
            "wallet signature requests",
            "raw transaction broadcasting",
            "X/Telegram posting from the browser",
            "unsolicited peer outreach",
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


def _telegram_store_path() -> Path | None:
    raw_path = os.getenv("TELEGRAM_OPT_IN_STORE_PATH", "").strip()
    raw_url = os.getenv("TELEGRAM_OPT_IN_STORE_URL", "").strip()
    if not raw_path and raw_url.startswith("file://"):
        raw_path = raw_url.removeprefix("file://")
    if not raw_path:
        if raw_url:
            return None
        if app.config.get("TESTING"):
            return None
        return DEFAULT_TELEGRAM_OPT_IN_STORE_PATH
    return Path(raw_path).expanduser()


def _telegram_store_status() -> dict[str, Any]:
    path = _telegram_store_path()
    external_url = os.getenv("TELEGRAM_OPT_IN_STORE_URL", "").strip()
    if path:
        default_path = path == DEFAULT_TELEGRAM_OPT_IN_STORE_PATH
        return {
            "mode": "local_json_default" if default_path else "local_json",
            "persistent": True,
            "configured": True,
            "path": str(path),
            "defaultLocalStore": default_path,
            "recordCount": len(_TELEGRAM_OPT_IN_RECORDS),
            "consumedTokenCount": len(_CONSUMED_TELEGRAM_TOKEN_IDS),
            "network_calls": False,
            "telegram_send": False,
        }
    if external_url:
        return {
            "mode": "external_adapter_pending",
            "persistent": False,
            "configured": True,
            "recordCount": len(_TELEGRAM_OPT_IN_RECORDS),
            "consumedTokenCount": len(_CONSUMED_TELEGRAM_TOKEN_IDS),
            "network_calls": False,
            "telegram_send": False,
        }
    return {
        "mode": "in_memory",
        "persistent": False,
        "configured": False,
        "recordCount": len(_TELEGRAM_OPT_IN_RECORDS),
        "consumedTokenCount": len(_CONSUMED_TELEGRAM_TOKEN_IDS),
        "network_calls": False,
        "telegram_send": False,
    }


def _hydrate_telegram_store() -> None:
    global _TELEGRAM_STORE_LOADED_PATH

    path = _telegram_store_path()
    if path is None:
        _TELEGRAM_STORE_LOADED_PATH = None
        return

    path_key = str(path)
    if _TELEGRAM_STORE_LOADED_PATH == path_key:
        return
    _TELEGRAM_STORE_LOADED_PATH = path_key

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(payload, dict):
        return

    records = payload.get("records")
    if isinstance(records, dict):
        for record_id, record in records.items():
            if isinstance(record_id, str) and isinstance(record, dict):
                _TELEGRAM_OPT_IN_RECORDS[record_id] = record

    consumed = payload.get("consumed_token_ids")
    if isinstance(consumed, list):
        _CONSUMED_TELEGRAM_TOKEN_IDS.update(str(token_id) for token_id in consumed)


def _persist_telegram_store() -> None:
    path = _telegram_store_path()
    if path is None:
        return

    payload = {
        "schema": "0guard.telegram_opt_in_store.v1",
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "records": _TELEGRAM_OPT_IN_RECORDS,
        "consumed_token_ids": sorted(_CONSUMED_TELEGRAM_TOKEN_IDS),
        "network_calls": False,
        "telegram_send": False,
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = path.with_suffix(f"{path.suffix}.tmp")
        tmp_path.write_text(json.dumps(payload, sort_keys=True, indent=2), encoding="utf-8")
        os.chmod(tmp_path, 0o600)
        tmp_path.replace(path)
    except OSError:
        return


def _telegram_mira_status_payload() -> dict:
    _hydrate_telegram_store()
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
            "store": _telegram_store_status(),
            "defaultScopes": [DEFAULT_SCOPE],
            "nodeScopes": [
                "da_node.digest",
                "da_node.balance",
                "storage_node.digest",
                "storage_node.peers",
                "node_business.digest",
                "peer_protection.digest",
            ],
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
            "/api/telegram/da-node-preview",
            "/api/telegram/storage-node-preview",
            "/api/telegram/node-business-preview",
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


def _telegram_bot_identity() -> dict | None:
    """Read-only Telegram Bot API identity readback without sending a message."""
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not token:
        return None

    import json
    import urllib.request

    url = f"https://api.telegram.org/bot{token}/getMe"
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        return {"status": "unreachable", "error": type(exc).__name__}

    if not isinstance(payload, dict) or not payload.get("ok"):
        return {"status": "error"}
    result = payload.get("result") or {}
    if not isinstance(result, dict):
        return {"status": "malformed"}
    return {
        "status": "ok",
        "id": result.get("id"),
        "username": result.get("username"),
        "firstName": result.get("first_name"),
        "canJoinGroups": result.get("can_join_groups"),
        "canReadAllGroupMessages": result.get("can_read_all_group_messages"),
        "supportsInlineQueries": result.get("supports_inline_queries"),
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
    _hydrate_telegram_store()
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
    _hydrate_telegram_store()
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
    if changed:
        _persist_telegram_store()
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
    _hydrate_telegram_store()
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
    _persist_telegram_store()
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


@app.route("/demo/wallet-provider-guard")
def wallet_provider_guard_demo():
    return render_template("wallet_provider_demo.html")


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
                "0G Node Ops",
                "0G AI Stack",
                "Local Inference",
                "Hot Wallet Plan",
                "Peer Protection",
                "Pi Mesh",
                "Data Flow",
                "Backfill plan",
                "Feature store",
                "Cyber threat repository",
                "x402 products",
                "Telegram Mira Opt-In",
                "Mira Telegram Preview",
                "Wallet Alert Preview",
                "Wallet Provider Guard",
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
                "/api/0g/da-node/status",
                "/api/0g/storage-node/status",
                "/api/0g/storage-node/peer-diagnostics",
                "/api/0g/node-pi-readiness-proof",
                "/api/0g/storage-upload/manifest",
                "/api/0g/alignment-node/status",
                "/api/0g/validator-capacity",
                "/api/0g/node-business",
                "/api/0g/private-computer",
                "/api/0g/private-computer/smoke-preview",
                "/api/0g/private-computer/smoke-proof",
                "/api/local-inference/status",
                "/api/telegram/local-inference-preview",
                "/api/0g/hot-wallet-resources",
                "/api/0g/peer-protection",
                "/api/0g/pi-mesh",
                "/api/peer/outreach-preview",
                "/api/0g/receipt",
                "/api/0g/proof-ladder",
                "/api/data/summary",
                "/api/data/incidents",
                "/api/data/provenance",
                "/api/data/detection-coverage",
                "/api/data/signature-map",
                "/api/data/backfill-plan",
                "/api/data/historical-feature-store",
                "/api/osint/sources",
                "/api/osint/readiness",
                "/api/osint/signals",
                "/api/intelligence/evolving",
                "/api/intelligence/cyber-threats",
                "/api/intelligence/data-streams",
                "/api/x402/data-products",
                "/api/x402/dry-run/wallet-preflight",
                "/api/x402/settlement-policy",
                "/api/x402/settlement-proof",
                "/x402/v1/wallet-preflight",
                "/api/wallet/provider-proof",
                "/api/intelligence/events",
                "/api/intelligence/detector-candidates",
                "/api/product/brief",
                "/api/product/strategy-review",
                "/api/deployment/readiness",
                "/api/production/gaps",
                "/api/production-gaps",
                "/api/model/training-roadmap",
                "/api/model/incident-eval-set",
                "/api/readyz",
                "/api/roadmap",
                "/api/experiments/frontier",
                "/api/experiments/run",
                "/api/threat-case-file",
                "/api/wallet/alert-preview",
                "/api/wallet/provider-guard",
                "/api/healthz",
                "/api/ton/status",
                "/api/ton/risk-rules",
                "/api/ton/wallet-risk-preview",
                "/tonconnect-manifest.json",
                "/api/integrations/cross-chain",
                "/api/integrations/cross-chain/readiness",
                "/api/integrations/arbitrum",
                "/api/hackathons/arbitrum-open-house",
                "/api/integrations/metamask",
                "/api/hackathons/metamask-1shot",
                "/api/hackathons/metamask-1shot/permission-preview",
                "/api/integrations/virtuals-facilitator",
                "/api/integrations/ika",
                "/api/integrations/ika/evaluate",
                "/api/reputation/probe",
                "/api/reputation/connectors",
                "/api/reputation/connectors/live",
                "/api/reputation/backfill/status",
                "/api/reputation/adapters",
                "/api/reputation/adapters/normalize",
                "/api/reputation/shadow-cache",
                "/api/native-preflight",
                "/api/hackathon/strategy",
                "/api/hackathons/next",
                "/api/developer-kit",
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
                "/api/telegram/da-node-preview",
                "/api/telegram/storage-node-preview",
                "/api/telegram/node-business-preview",
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
                "run-threat-case-file",
                "run-hack-check",
                "run-domain-check",
                "load-data-summary",
                "load-provenance-matrix",
                "load-live-provenance",
                "load-detection-coverage",
                "load-signature-map",
                "load-historical-backfill-plan",
                "load-historical-feature-store",
                "load-osint-sources",
                "load-osint-readiness",
                "load-osint-signals",
                "load-evolving-intel",
                "load-cyber-threat-repository",
                "load-intelligence-stream-plan",
                "load-intelligence-events",
                "load-product-brief",
                "load-production-readiness",
                "load-deployment-readiness",
                "load-production-gaps",
                "load-model-training-roadmap",
                "load-incident-eval-set",
                "load-ecosystem-roadmap",
                "load-frontier-experiments",
                "load-submission-brief",
                "load-submission-packet",
                "load-submission-readiness",
                "load-threat-passport",
                "load-x402-data-products",
                "load-x402-dry-run",
                "load-x402-settlement-policy",
                "load-cross-chain-catalog",
                "load-cross-chain-readiness",
                "load-arbitrum-integration",
                "load-metamask-integration",
                "load-virtuals-facilitator",
                "load-ika-integration",
                "run-reputation-probe",
                "load-reputation-backfill-status",
                "load-reputation-adapters",
                "load-reputation-shadow-cache",
                "run-native-preflight",
                "load-hackathon-strategy",
                "load-next-hackathon-plan",
                "load-developer-kit",
                "load-external-guardrails",
                "run-external-guardrail-check",
                "run-wallet-alert-preview",
                "run-telegram-wallet-alert-preview",
                "run-wallet-provider-guard",
                "load-da-node-status",
                "load-storage-node-status",
                "load-storage-peer-diagnostics",
                "load-storage-upload-manifest",
                "run-telegram-da-node-preview",
                "load-node-business",
                "load-alignment-node-status",
                "load-validator-capacity",
                "load-private-computer",
                "load-private-compute-smoke-preview",
                "load-local-inference",
                "run-telegram-local-inference-preview",
                "load-hot-wallet-resources",
                "load-peer-protection",
                "run-peer-outreach-preview",
                "load-pi-mesh",
                "run-telegram-node-business-preview",
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


@app.route("/api/data/backfill-plan", methods=["GET"])
def api_data_backfill_plan():
    return jsonify(build_historical_backfill_plan())


@app.route("/api/data/historical-feature-store", methods=["GET"])
def api_data_historical_feature_store():
    limit = request.args.get("limit")
    try:
        limit_value = int(limit) if limit is not None else None
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    if limit_value is not None and (limit_value < 1 or limit_value > 200):
        return jsonify({"error": "limit must be between 1 and 200"}), 400
    return jsonify(
        build_historical_feature_store(
            limit=limit_value,
            include_reputation=not _truthy_query_arg("no_reputation"),
        )
    )


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


@app.route("/api/intelligence/cyber-threats", methods=["GET", "POST"])
def api_intelligence_cyber_threats():
    body = request.get_json(silent=True) or {} if request.method == "POST" else {}
    live = _truthy_value(body.get("live")) if request.method == "POST" else _truthy_query_arg("live")
    limit = _request_value(body, "limit", request.args.get("limit") or 5)
    cves = (
        body.get("cveIds")
        or body.get("cve_ids")
        or body.get("cves")
        or request.args.get("cveIds")
        or request.args.get("cve_ids")
        or request.args.get("cves")
        or ""
    )
    address = (
        body.get("address")
        or body.get("target")
        or request.args.get("address")
        or request.args.get("target")
        or ""
    )
    include_ofac = (
        _truthy_value(body.get("includeOfac") or body.get("include_ofac"))
        if request.method == "POST"
        else _truthy_query_arg("include_ofac") or _truthy_query_arg("includeOfac")
    )
    try:
        return jsonify(
            build_cyber_threat_repository(
                live=live,
                limit=int(limit),
                address=str(address),
                cve_ids=cves,
                include_ofac=include_ofac,
            )
        )
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/x402/data-products", methods=["GET"])
def api_x402_data_products():
    return jsonify(build_x402_data_products())


@app.route("/api/x402/dry-run/wallet-preflight", methods=["GET", "POST"])
def api_x402_dry_run_wallet_preflight():
    body = request.get_json(silent=True) or {} if request.method == "POST" else {}
    payload = build_x402_wallet_preflight_dry_run(
        payment_header=request.headers.get("X-PAYMENT", ""),
        body=body,
    )
    return jsonify(payload), int(payload["httpStatus"])


@app.route("/api/x402/settlement-policy", methods=["GET"])
def api_x402_settlement_policy():
    return jsonify(build_x402_settlement_policy())


@app.route("/api/x402/settlement-proof", methods=["GET"])
def api_x402_settlement_proof():
    return jsonify(build_x402_settlement_proof_status())


@app.route("/x402/v1/wallet-preflight", methods=["GET"])
def x402_live_wallet_preflight():
    if not app.config.get("ZG_X402_LIVE_SETTLEMENT_MIDDLEWARE"):
        return (
            jsonify(
                {
                    "schema": "0guard.x402_live_wallet_preflight_disabled.v1",
                    "status": "settlement_disabled",
                    "reason": app.config.get("ZG_X402_LIVE_SETTLEMENT_BLOCKER")
                    or "settlement_middleware_not_active",
                    "settlementPolicyRoute": "/api/x402/settlement-policy",
                    "safety": {
                        "x402SettlementEnabled": False,
                        "paymentSettlementEnabled": False,
                        "paymentHeaderStored": False,
                        "transactionSigningEnabled": False,
                        "transactionBroadcastingEnabled": False,
                    },
                }
            ),
            503,
        )
    payload = build_x402_wallet_preflight_paid_response(
        body={
            "target": request.args.get("target", ""),
            "url": request.args.get("url", ""),
            "address": request.args.get("address", ""),
        }
    )
    response = jsonify(payload)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.route("/api/intelligence/events", methods=["GET"])
def api_intelligence_events():
    live = _truthy_query_arg("live")
    limit = request.args.get("limit")
    try:
        limit_value = int(limit) if limit is not None else 10
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    try:
        return jsonify(intelligence_events_snapshot(live=live, limit=limit_value))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/intelligence/detector-candidates", methods=["GET"])
def api_intelligence_detector_candidates():
    live = _truthy_query_arg("live")
    limit = request.args.get("limit")
    try:
        limit_value = int(limit) if limit is not None else 10
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    try:
        return jsonify(live_detector_candidates(live=live, limit=limit_value))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/product/brief", methods=["GET"])
def api_product_brief():
    return jsonify(product_brief())


@app.route("/api/product/strategy-review", methods=["GET"])
def api_product_strategy_review():
    return jsonify(build_strategy_review())


@app.route("/api/production/gaps", methods=["GET"])
@app.route("/api/production-gaps", methods=["GET"])
def api_production_gaps():
    return jsonify(build_production_gap_matrix())


@app.route("/api/deployment/readiness", methods=["GET"])
def api_deployment_readiness():
    return jsonify(build_deployment_readiness(live=_truthy_query_arg("live")))


@app.route("/api/model/training-roadmap", methods=["GET"])
def api_model_training_roadmap():
    return jsonify(build_model_training_roadmap())


@app.route("/api/model/incident-eval-set", methods=["GET"])
def api_model_incident_eval_set():
    limit = request.args.get("limit")
    try:
        limit_value = int(limit) if limit is not None else None
    except ValueError:
        return jsonify({"error": "limit must be an integer"}), 400
    if limit_value is not None and (limit_value < 1 or limit_value > 200):
        return jsonify({"error": "limit must be between 1 and 200"}), 400
    return jsonify(build_incident_detector_eval_set(limit=limit_value))


@app.route("/api/readyz", methods=["GET"])
@app.route("/readyz", methods=["GET"])
def readyz():
    return jsonify(production_readiness())


@app.route("/api/roadmap", methods=["GET"])
def api_roadmap():
    return jsonify(ecosystem_roadmap())


@app.route("/api/experiments/frontier", methods=["GET"])
def api_frontier_experiments():
    return jsonify(frontier_experiments())


@app.route("/api/experiments/run", methods=["POST"])
def api_frontier_experiment_run():
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(run_frontier_experiment_preview(body))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/wallet/alert-preview", methods=["GET", "POST"])
def api_wallet_alert_preview():
    body = (request.get_json(silent=True) or {}) if request.method == "POST" else {}
    supplied_address = body.get("address") or request.args.get("address")
    address = supplied_address or ""
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
        reputation_context = _reputation_context_from_request(body)
        try:
            preview = build_wallet_alert_preview(
                address,
                intent=intent,
                reputation_context=reputation_context,
                live=live,
                max_alerts=max_alerts,
            )
        except ValueError:
            # If the caller did not supply an address, fall back to the stable demo
            # address even if an older deployment had an invalid default.
            if supplied_address:
                raise
            preview = build_wallet_alert_preview(
                DEMO_EVM_ADDRESS,
                intent=intent,
                reputation_context=reputation_context,
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


@app.route("/api/integrations/arbitrum", methods=["GET"])
def api_arbitrum_integration():
    return jsonify(arbitrum_integration_plan())


@app.route("/api/hackathons/arbitrum-open-house", methods=["GET"])
def api_arbitrum_open_house_buildathon():
    return jsonify(arbitrum_open_house_buildathon_plan())


@app.route("/api/integrations/metamask", methods=["GET"])
def api_metamask_integration():
    return jsonify(metamask_integration_plan())


@app.route("/api/hackathons/metamask-1shot", methods=["GET"])
def api_metamask_1shot_cookoff():
    return jsonify(metamask_1shot_cookoff_plan())


@app.route("/api/hackathons/metamask-1shot/permission-preview", methods=["GET", "POST"])
def api_metamask_1shot_permission_preview():
    body = request.get_json(silent=True) or {} if request.method == "POST" else {}
    try:
        return jsonify(metamask_1shot_permission_preview(body))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


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


@app.route("/api/reputation/probe", methods=["GET", "POST"])
def api_reputation_probe():
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
    else:
        body = {
            "url": request.args.get("url") or request.args.get("domain") or "",
            "address": request.args.get("address") or request.args.get("target") or "",
            "chain": request.args.get("chain") or "",
            "surface": request.args.get("surface") or "",
        }
    try:
        return jsonify(build_reputation_probe(body))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/reputation/connectors", methods=["GET", "POST"])
def api_reputation_connectors():
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
    else:
        body = {
            "url": request.args.get("url") or request.args.get("domain") or "",
            "address": request.args.get("address") or request.args.get("target") or "",
            "chain": request.args.get("chain") or "",
            "surface": request.args.get("surface") or "",
        }
    try:
        return jsonify(reputation_connector_manifest(body))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/reputation/connectors/live", methods=["GET", "POST"])
def api_reputation_connectors_live():
    body = request.get_json(silent=True) or {} if request.method == "POST" else {}
    source_id = (
        body.get("sourceId")
        or body.get("source_id")
        or request.args.get("sourceId")
        or request.args.get("source_id")
        or "phishdestroy_destroylist"
    )
    subject_url = (
        body.get("url")
        or body.get("domain")
        or request.args.get("url")
        or request.args.get("domain")
        or ""
    )
    address = (
        body.get("address")
        or body.get("target")
        or request.args.get("address")
        or request.args.get("target")
        or ""
    )
    cves = (
        body.get("cveIds")
        or body.get("cve_ids")
        or body.get("cves")
        or request.args.get("cveIds")
        or request.args.get("cve_ids")
        or request.args.get("cves")
        or ""
    )
    live = _truthy_value(body.get("live")) if request.method == "POST" else _truthy_query_arg("live")
    limit = _request_value(body, "limit", request.args.get("limit") or 5)
    days = _request_value(body, "days", request.args.get("days") or 7)
    try:
        return jsonify(
            reputation_connector_snapshot(
                source_id=str(source_id),
                live=live,
                limit=int(limit),
                subject_url=str(subject_url),
                address=str(address),
                cve_ids=cves,
                days=int(days),
            )
        )
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/reputation/backfill/status", methods=["GET"])
def api_reputation_backfill_status():
    return jsonify(build_reputation_backfill_status())


@app.route("/api/reputation/adapters", methods=["GET"])
def api_reputation_adapters():
    return jsonify(reputation_adapter_catalog())


@app.route("/api/reputation/adapters/normalize", methods=["POST"])
def api_reputation_adapter_normalize():
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(normalize_reputation_adapter_payload(body))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/reputation/shadow-cache", methods=["GET", "POST"])
def api_reputation_shadow_cache():
    body = request.get_json(silent=True) or {} if request.method == "POST" else None
    try:
        return jsonify(build_reputation_shadow_cache(body))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/native-preflight", methods=["POST"])
def api_native_preflight():
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(build_native_preflight(body))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


def _wallet_provider_allowed_origin(origin: str | None) -> str | None:
    normalized = (origin or "").strip().rstrip("/")
    if not normalized:
        return None
    configured = {
        item.strip().rstrip("/")
        for item in os.getenv("ZEROGUARD_WALLET_PROVIDER_ALLOWED_ORIGINS", "").split(",")
        if item.strip()
    }
    allowed = DEFAULT_WALLET_PROVIDER_GUARD_ORIGINS | configured
    if "*" in allowed:
        return normalized
    if normalized in allowed:
        return normalized
    parsed = urlparse(normalized)
    if parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}:
        return normalized
    return None


def _wallet_provider_guard_body(body: dict[str, object]) -> dict[str, object]:
    """Use the browser Origin header as authority when it is present."""

    header_origin = (request.headers.get("Origin") or "").strip().rstrip("/")
    if not header_origin:
        return body

    allowed_origin = _wallet_provider_allowed_origin(header_origin)
    if not allowed_origin:
        raise ValueError("wallet provider origin is not allowlisted")

    reported_origin = str(body.get("origin") or "").strip().rstrip("/")
    if reported_origin and reported_origin != allowed_origin:
        raise ValueError("wallet provider origin mismatch")

    return {**body, "origin": allowed_origin}


def _wallet_provider_cors(response: Response, *, status_code: int = 200) -> Response:
    response.status_code = status_code
    allowed_origin = _wallet_provider_allowed_origin(request.headers.get("Origin"))
    if allowed_origin:
        response.headers["Access-Control-Allow-Origin"] = allowed_origin
        response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Access-Control-Max-Age"] = "600"
        response.headers["Vary"] = "Origin"
    return response


@app.route("/api/wallet/provider-guard", methods=["POST", "OPTIONS"])
def api_wallet_provider_guard():
    if request.method == "OPTIONS":
        return _wallet_provider_cors(jsonify({}), status_code=204)
    body = request.get_json(silent=True) or {}
    try:
        return _wallet_provider_cors(
            jsonify(build_wallet_provider_guard(_wallet_provider_guard_body(body)))
        )
    except (TypeError, ValueError) as exc:
        return _wallet_provider_cors(jsonify({"error": str(exc)}), status_code=400)


@app.route("/api/wallet/provider-proof", methods=["GET"])
def api_wallet_provider_proof():
    return jsonify(build_wallet_provider_external_proof_status())


@app.route("/api/hackathon/strategy", methods=["GET"])
def api_hackathon_strategy():
    return jsonify(hackathon_strategy())


@app.route("/api/hackathons/next", methods=["GET"])
def api_next_hackathon_plan():
    return jsonify(next_hackathon_plan())


@app.route("/api/developer-kit", methods=["GET"])
def api_developer_kit():
    return jsonify(developer_kit_manifest())


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
    identity = _telegram_bot_identity() if live_readback else None
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
        "botApiIdentity": identity,
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
            reputation_context=_reputation_context_from_request(body),
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

    if text.lower().split(maxsplit=1)[0] in {"/da", "/node", "/balance"}:
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
        preview = build_telegram_da_node_preview(
            live=_truthy_query_arg("live"),
            opt_in_record=record,
        )
        return jsonify(
            {
                "schema": "0guard.telegram_webhook.v1",
                "action": "da_node_preview",
                **preview,
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

    supplied_address = body.get("address") or request.args.get("address")
    address = supplied_address or ""
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
        live = (
            _truthy_value(body.get("live", False))
            if request.method == "POST"
            else _truthy_query_arg("live")
        )
        max_alerts = int(_request_value(body, "max_alerts", 5))
        reputation_context = _reputation_context_from_request(body)
        try:
            preview = build_wallet_alert_preview(
                address,
                intent=intent,
                reputation_context=reputation_context,
                live=live,
                max_alerts=max_alerts,
            )
        except ValueError:
            if supplied_address:
                raise
            preview = build_wallet_alert_preview(
                DEMO_EVM_ADDRESS,
                intent=intent,
                reputation_context=reputation_context,
                live=live,
                max_alerts=max_alerts,
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


@app.route("/api/telegram/da-node-preview", methods=["GET", "POST"])
def api_telegram_da_node_preview():
    body = (request.get_json(silent=True) or {}) if request.method == "POST" else {}
    record_id = body.get("record_id")
    record = _TELEGRAM_OPT_IN_RECORDS.get(record_id) if record_id else None
    if record_id and not record:
        return jsonify({"error": "Unknown or inactive Telegram opt-in record"}), 403

    live = (
        _truthy_value(body.get("live", False))
        if request.method == "POST"
        else _truthy_query_arg("live")
    )
    status = (
        body["status"]
        if isinstance(body.get("status"), dict)
        else build_da_node_status(live=live)
    )
    return jsonify(build_telegram_da_node_preview(status=status, opt_in_record=record))


@app.route("/api/telegram/storage-node-preview", methods=["GET", "POST"])
def api_telegram_storage_node_preview():
    body = (request.get_json(silent=True) or {}) if request.method == "POST" else {}
    record_id = body.get("record_id")
    record = _TELEGRAM_OPT_IN_RECORDS.get(record_id) if record_id else None
    if record_id and not record:
        return jsonify({"error": "Unknown or inactive Telegram opt-in record"}), 403

    live = (
        _truthy_value(body.get("live", False))
        if request.method == "POST"
        else _truthy_query_arg("live")
    )
    status = (
        body["status"]
        if isinstance(body.get("status"), dict)
        else build_storage_node_status(live=live)
    )
    return jsonify(build_telegram_storage_node_preview(status=status, opt_in_record=record))


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
    # Compatibility note: callers historically expected some safety flags at the
    # top level. Keep both top-level booleans and the structured `safety_flags`
    # payload so monitors can be simple while UIs can stay structured.
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
            "0g_da_node": build_da_node_status(live=False),
            "0g_storage_node_status": build_storage_node_status(live=False),
            "0g_node_business": build_0g_node_business_plan(live=False),
            "0g_private_computer": build_0g_private_computer_integration(),
            "local_inference_mesh": build_local_inference_mesh(live=False),
            "x402_data_products": build_x402_data_products(),
            "x402_settlement_policy": build_x402_settlement_policy(),
            "historical_backfill_plan": build_historical_backfill_plan(),
            "historical_feature_store": build_historical_feature_store(limit=3),
            "production_gaps": build_production_gap_matrix(),
            "model_training_roadmap": build_model_training_roadmap(),
            "incident_eval_set": build_incident_detector_eval_set(limit=3),
            "0g_hot_wallet_resources": build_0g_hot_wallet_resources(),
            "peer_protection": build_peer_protection_plan(live=False),
            "pi_mesh": build_pi_mesh_plan(),
            "telegram_mira": _telegram_mira_status_payload(),
            "read_only": True,
            "telegram_sends_enabled": False,
            "money_movement_enabled": False,
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


@app.route("/api/healthz", methods=["GET"])
@app.route("/healthz/", methods=["GET"])
@app.route("/healthz", methods=["GET"])
def healthz():
    payload = api_health().get_json()
    payload["schema"] = "0guard.healthz.v1"
    payload["ok"] = True
    return jsonify(payload)


@app.route("/api/0g/status", methods=["GET"])
def api_0g_status():
    return jsonify(build_0g_status())


@app.route("/api/0g/da-node/status", methods=["GET"])
def api_0g_da_node_status():
    return jsonify(build_da_node_status(live=_truthy_query_arg("live")))


@app.route("/api/0g/storage-node/status", methods=["GET"])
def api_0g_storage_node_status():
    status_file = DEFAULT_STORAGE_STATUS_PATH if _truthy_query_arg("snapshot") else None
    live = _truthy_query_arg("live")
    if status_file:
        return jsonify(build_storage_node_status(live=live, status_file=status_file))
    return jsonify(build_storage_node_status(live=live))


@app.route("/api/0g/storage-node/peer-diagnostics", methods=["GET"])
def api_0g_storage_node_peer_diagnostics():
    status_file = DEFAULT_STORAGE_PEER_DIAGNOSTICS_PATH if _truthy_query_arg("snapshot") else None
    return jsonify(build_storage_peer_diagnostics(status_file=status_file))


@app.route("/api/0g/node-pi-readiness-proof", methods=["GET"])
def api_0g_node_pi_readiness_proof():
    return jsonify(build_node_pi_readiness_proof_status())


@app.route("/api/0g/storage-upload/manifest", methods=["GET"])
def api_0g_storage_upload_manifest():
    return jsonify(build_storage_upload_manifest())


@app.route("/api/0g/alignment-node/status", methods=["GET"])
def api_0g_alignment_node_status():
    return jsonify(build_alignment_node_status(live=_truthy_query_arg("live")))


@app.route("/api/0g/validator-capacity", methods=["GET"])
def api_0g_validator_capacity():
    return jsonify(build_validator_capacity_status())


@app.route("/api/0g/node-business", methods=["GET"])
def api_0g_node_business():
    return jsonify(build_0g_node_business_plan(live=_truthy_query_arg("live")))


@app.route("/api/0g/private-computer", methods=["GET"])
def api_0g_private_computer():
    return jsonify(build_0g_private_computer_integration(live=_truthy_query_arg("live")))


@app.route("/api/0g/private-computer/smoke-preview", methods=["GET", "POST"])
def api_0g_private_computer_smoke_preview():
    body = request.get_json(silent=True) or {} if request.method == "POST" else {}
    return jsonify(build_private_compute_smoke_preview(body))


@app.route("/api/0g/private-computer/smoke-proof", methods=["GET"])
def api_0g_private_computer_smoke_proof():
    return jsonify(build_private_compute_paid_smoke_proof_status())


@app.route("/api/local-inference/status", methods=["GET"])
def api_local_inference_status():
    return jsonify(build_local_inference_mesh(live=_truthy_query_arg("live")))


@app.route("/api/telegram/local-inference-preview", methods=["GET", "POST"])
def api_telegram_local_inference_preview():
    body = (request.get_json(silent=True) or {}) if request.method == "POST" else {}
    record_id = body.get("record_id")
    record = _TELEGRAM_OPT_IN_RECORDS.get(record_id) if record_id else None
    if record_id and not record:
        return jsonify({"error": "Unknown or inactive Telegram opt-in record"}), 403

    live = (
        _truthy_value(body.get("live", False))
        if request.method == "POST"
        else _truthy_query_arg("live")
    )
    mesh = (
        body["mesh"]
        if isinstance(body.get("mesh"), dict)
        else build_local_inference_mesh(live=live)
    )
    return jsonify(build_telegram_local_inference_preview(mesh, opt_in_record=record))


@app.route("/api/0g/hot-wallet-resources", methods=["GET"])
def api_0g_hot_wallet_resources():
    return jsonify(build_0g_hot_wallet_resources())


@app.route("/api/0g/peer-protection", methods=["GET"])
def api_0g_peer_protection():
    return jsonify(build_peer_protection_plan(live=_truthy_query_arg("live")))


@app.route("/api/0g/pi-mesh", methods=["GET"])
def api_0g_pi_mesh():
    status_file = DEFAULT_PI_MESH_STATUS_PATH if _truthy_query_arg("snapshot") else None
    return jsonify(build_pi_mesh_plan(status_file=status_file))


@app.route("/api/peer/outreach-preview", methods=["GET", "POST"])
def api_peer_outreach_preview():
    body = request.get_json(silent=True) or {}
    return jsonify(build_peer_outreach_preview(body))


@app.route("/api/telegram/node-business-preview", methods=["GET", "POST"])
def api_telegram_node_business_preview():
    body = (request.get_json(silent=True) or {}) if request.method == "POST" else {}
    record_id = body.get("record_id")
    record = _TELEGRAM_OPT_IN_RECORDS.get(record_id) if record_id else None
    if record_id and not record:
        return jsonify({"error": "Unknown or inactive Telegram opt-in record"}), 403

    live = (
        _truthy_value(body.get("live", False))
        if request.method == "POST"
        else _truthy_query_arg("live")
    )
    plan = (
        body["businessPlan"]
        if isinstance(body.get("businessPlan"), dict)
        else build_0g_node_business_plan(live=live)
    )
    return jsonify(build_telegram_node_business_preview(plan, opt_in_record=record))


@app.route("/api/0g/receipt", methods=["GET"])
def api_0g_receipt():
    receipt_hash = request.args.get("receipt_hash") or request.args.get("receipt") or ""
    tx_hash = request.args.get("tx_hash")
    return jsonify(verify_anchor(receipt_hash=receipt_hash, tx_hash=tx_hash))


@app.route("/api/0g/proof-ladder", methods=["GET", "POST"])
def api_0g_proof_ladder():
    if request.method == "POST":
        body = request.get_json(silent=True) or {}
    else:
        body = {
            "surface": request.args.get("surface") or "evm",
            "operation": request.args.get("operation") or "approve",
            "chain": request.args.get("chain") or "eip155:16661",
            "intent": {
                "action": request.args.get("action") or "approve",
                "mode": request.args.get("mode") or "live_transaction",
                "requires_signature": request.args.get("requires_signature", "true").lower()
                not in {"0", "false", "no", "off"},
                "prompt_text": request.args.get("prompt_text")
                or "Build a 0G proof packet before asking a wallet to sign.",
            },
        }
    try:
        return jsonify(build_proof_ladder(body))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


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


@app.route("/api/threat-case-file", methods=["POST"])
def api_threat_case_file():
    body = request.get_json(silent=True) or {}
    try:
        return jsonify(build_threat_case_file(body))
    except (TypeError, ValueError) as exc:
        return jsonify({"error": str(exc)}), 400


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


def _reputation_context_from_request(body: dict) -> dict | None:
    explicit = body.get("reputation") or body.get("reputation_context")
    if isinstance(explicit, dict):
        context = dict(explicit)
        return _merge_reputation_adapter_context(context, body, explicit)

    source = body if request.method == "POST" else request.args
    evidence = source.get("sourceEvidence") or source.get("source_evidence") or []
    labels = source.get("labels") or source.get("label") or []
    context = {
        "url": source.get("url") or source.get("domain") or source.get("website") or "",
        "address": (
            source.get("counterparty")
            or source.get("target")
            or source.get("target_contract")
            or source.get("to")
            or ""
        ),
        "chain": source.get("chain") or source.get("caip2") or "",
        "surface": source.get("surface") or "",
        "labels": labels,
        "sourceEvidence": evidence,
    }
    context = _merge_reputation_adapter_context(
        context,
        body,
        *([] if source is body else [source]),
    )
    if any(value for value in context.values()):
        return context
    return None


def _merge_reputation_adapter_context(
    context: dict,
    *payloads: Any,
) -> dict:
    adapter_previews: list[dict] = []
    for payload in payloads:
        if isinstance(payload, dict):
            adapter_previews.extend(normalize_reputation_adapters_from_payload(payload))
    if not adapter_previews:
        return context

    source_evidence = context.get("sourceEvidence") or context.get("source_evidence") or []
    if isinstance(source_evidence, dict):
        source_evidence = [source_evidence]
    if not isinstance(source_evidence, list):
        source_evidence = []
    merged = [item for item in source_evidence if isinstance(item, dict)]
    for preview in adapter_previews:
        merged.extend(preview.get("derivedEvidence") or [])
    context["sourceEvidence"] = merged
    context["adapterEvidence"] = {
        "sourceIds": [preview["sourceId"] for preview in adapter_previews],
        "derivedEvidenceCount": sum(preview["derivedEvidenceCount"] for preview in adapter_previews),
        "rawPayloadsReturned": False,
    }
    return context


def _build_mira_claim_response(
    *,
    subject: dict,
    claims: list[dict],
    evidence: list[dict],
) -> dict:
    return build_mira_claim_preview(subject=subject, claims=claims, evidence=evidence)


def _domain_decision(url: str) -> dict:
    return domain_decision(url)


def _truthy_query_arg(name: str) -> bool:
    return request.args.get(name, "").lower() in {"1", "true", "yes", "on"}


def _truthy_value(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _maybe_install_x402_testnet_middleware() -> None:
    app.config["ZG_X402_LIVE_SETTLEMENT_MIDDLEWARE"] = False
    app.config["ZG_X402_LIVE_SETTLEMENT_BLOCKER"] = "settlement_env_gate_disabled"
    if not _truthy_value(os.environ.get("ZG_X402_ENABLE_SETTLEMENT")):
        return
    if _truthy_value(os.environ.get("ZG_X402_ALLOW_MAINNET")):
        app.config["ZG_X402_LIVE_SETTLEMENT_BLOCKER"] = "mainnet_settlement_not_allowed_here"
        return

    policy = build_x402_settlement_policy()
    payment = policy.get("paymentRequirement") or {}
    pay_to = str(payment.get("payTo") or "").strip()
    if not payment.get("payToConfigured") or not pay_to:
        app.config["ZG_X402_LIVE_SETTLEMENT_BLOCKER"] = "pay_to_address_missing"
        return

    try:
        from x402 import x402ResourceServerSync
        from x402.http import (
            FacilitatorConfig,
            HTTPFacilitatorClientSync,
            PaymentOption,
            RouteConfig,
        )
        from x402.http.middleware.flask import payment_middleware
        from x402.mechanisms.evm.exact import ExactEvmServerScheme
    except ImportError as exc:
        app.config["ZG_X402_LIVE_SETTLEMENT_BLOCKER"] = f"x402_dependency_missing:{exc}"
        return

    facilitator = HTTPFacilitatorClientSync(FacilitatorConfig(url=X402_TESTNET_FACILITATOR_URL))
    server = x402ResourceServerSync(facilitator)
    server.register(BASE_SEPOLIA_CAIP2, ExactEvmServerScheme())
    payment_middleware(
        app,
        {
            "GET /x402/v1/wallet-preflight": RouteConfig(
                accepts=PaymentOption(
                    scheme="exact",
                    pay_to=pay_to,
                    price="$0.01",
                    network=BASE_SEPOLIA_CAIP2,
                ),
                resource="https://guard0-miniapp-s77j6bxyra-uc.a.run.app/x402/v1/wallet-preflight",
                description="ZeroGuard wallet preflight verdict packet",
                mime_type="application/json",
            )
        },
        server,
    )
    app.config["ZG_X402_LIVE_SETTLEMENT_MIDDLEWARE"] = True
    app.config["ZG_X402_LIVE_SETTLEMENT_BLOCKER"] = ""


_maybe_install_x402_testnet_middleware()


def main() -> None:
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8109"))
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    main()
