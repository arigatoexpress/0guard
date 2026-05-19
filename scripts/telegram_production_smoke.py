#!/usr/bin/env python3
"""Production smoke test for the 0guard Telegram bot and Mini App.

The script intentionally redacts all bot/user identifiers and never prints the
bot token. It can read the token from an environment variable or from GCP Secret
Manager through the local `gcloud` CLI.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import requests

DEFAULT_BASE_URL = "https://guard0-miniapp-s77j6bxyra-uc.a.run.app"
FALLBACK_BASE_URLS: tuple[str, ...] = (
    "https://candidate-acdc011---guard0-miniapp-s77j6bxyra-uc.a.run.app",
    "https://candidate-6f07f89---guard0-miniapp-s77j6bxyra-uc.a.run.app",
)
DEFAULT_GCLOUD_PROJECT = "sapphire-479610"
DEFAULT_BOT_SECRET = "guard0-telegram-bot-token"
DEFAULT_WEBHOOK_SECRET = "guard0-telegram-webhook-secret-token"
PROOF_WALLET = "0x885b0892D241Cb5033C9995e09cA521d54f936b5"
APPROVAL_CALLDATA = (
    "0x095ea7b3"
    "ffffffffffffffffffffffffffffffff"
    "ffffffffffffffffffffffffffffffff"
)

ROUTE_PROBES: tuple[tuple[str, str], ...] = (
    ("intelligence_events", "/api/intelligence/events?live=1&limit=1"),
    ("detector_candidates", "/api/intelligence/detector-candidates?live=1&limit=1"),
    ("reputation_connectors_live", "/api/reputation/connectors/live?live=1&limit=1"),
    ("integrations_arbitrum", "/api/integrations/arbitrum"),
    ("integrations_metamask", "/api/integrations/metamask"),
    ("hackathons_next", "/api/hackathons/next"),
    ("native_preflight_get", "/api/native-preflight"),
    ("external_guardrails_evaluate_get", "/api/integrations/external-guardrails/evaluate"),
    ("ika_evaluate_get", "/api/integrations/ika/evaluate"),
)


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="0guard Telegram production smoke")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--bot-token-env", default="TELEGRAM_BOT_TOKEN")
    parser.add_argument("--gcloud-project", default=DEFAULT_GCLOUD_PROJECT)
    parser.add_argument("--bot-token-secret", default=DEFAULT_BOT_SECRET)
    parser.add_argument("--webhook-secret", default=DEFAULT_WEBHOOK_SECRET)
    parser.add_argument("--skip-telegram-api", action="store_true")
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    args = parser.parse_args(argv)

    token = "" if args.skip_telegram_api else _load_secret(args.bot_token_env, args.bot_token_secret, args.gcloud_project)
    webhook_secret = "" if args.skip_telegram_api else _load_secret("", args.webhook_secret, args.gcloud_project)
    base_url = _select_base_url(args.base_url.rstrip("/"))

    checks: list[Check] = []
    payload: dict[str, Any] = {"baseUrl": base_url, "tokenPrinted": False}

    health_path, health = _load_health(base_url)
    safety_flags = health.get("safety_flags") or {}
    payload["health"] = {
        "path": health_path,
        "schema": health.get("schema", "legacy"),
        "ok": health.get("ok"),
        "service": health.get("service"),
        "readOnly": safety_flags.get("read_only"),
        "telegramSendsEnabled": safety_flags.get("telegram_sends_enabled"),
        "moneyMovementEnabled": safety_flags.get("money_movement_enabled"),
    }
    checks.extend(
        [
            Check("health_endpoint", health.get("service") == "zg-hack-guard", health_path),
            Check("health_read_only", safety_flags.get("read_only") is True, str(safety_flags.get("read_only"))),
            Check("health_telegram_sends_disabled", safety_flags.get("telegram_sends_enabled") is False, _disabled_label(safety_flags.get("telegram_sends_enabled"))),
            Check("health_money_movement_disabled", safety_flags.get("money_movement_enabled") is False, _disabled_label(safety_flags.get("money_movement_enabled"))),
        ]
    )

    status = _get_json(f"{base_url}/api/telegram/status")
    payload["telegramStatus"] = _status_summary(status)
    checks.extend(
        [
            Check("cloud_run_bot_token_configured", status["miniAppAuth"]["botTokenConfigured"] is True, str(status["miniAppAuth"]["botTokenConfigured"])),
            Check("cloud_run_bot_username_configured", status["registration"]["telegramBotUsernameConfigured"] is True, str(status["registration"]["telegramBotUsernameConfigured"])),
            Check("telegram_sends_disabled", status["safety"]["telegramSendsEnabled"] is False, _disabled_label(status["safety"]["telegramSendsEnabled"])),
            Check("registration_secret_env", status["registration"]["secretSource"] == "env", status["registration"]["secretSource"]),
        ]
    )

    session = _post_json(f"{base_url}/api/telegram/miniapp/session", {})
    payload["browserPreviewSession"] = {
        "schema": session.get("schema"),
        "mode": session.get("mode"),
        "validated": (session.get("auth") or {}).get("validated"),
        "telegramSendsEnabled": (session.get("safety") or {}).get("telegramSendsEnabled"),
    }
    checks.append(Check("browser_preview_session", session.get("mode") == "local_browser_preview", str(session.get("mode"))))

    if token:
        signed_session = _post_json(
            f"{base_url}/api/telegram/miniapp/session",
            {"initData": _signed_demo_init_data(token)},
        )
        auth = signed_session.get("auth") or {}
        payload["signedTelegramSession"] = {
            "schema": signed_session.get("schema"),
            "mode": signed_session.get("mode"),
            "validated": auth.get("validated"),
            "user": auth.get("user"),
            "telegramSendsEnabled": (signed_session.get("safety") or {}).get("telegramSendsEnabled"),
        }
        checks.append(Check("signed_init_data_validates", auth.get("validated") is True, str(auth.get("validated"))))

    preview = _post_json(
        f"{base_url}/api/telegram/miniapp/preview",
        {
            "address": PROOF_WALLET,
            "intent": {
                "action": "approve",
                "mode": "live_transaction",
                "requires_signature": True,
                "calldata": APPROVAL_CALLDATA,
            },
        },
    )
    payload["miniAppPreview"] = {
        "schema": preview.get("schema"),
        "walletDecision": ((preview.get("walletAlert") or {}).get("decision") or {}).get("decision"),
        "miraSchema": (preview.get("mira") or {}).get("schema"),
        "telegramSend": preview.get("telegram_send"),
        "networkCalls": preview.get("network_calls"),
    }
    checks.extend(
        [
            Check("miniapp_preview_schema", preview.get("schema") == "0guard.telegram_miniapp_preview.v1", str(preview.get("schema"))),
            Check("wallet_alert_denies", payload["miniAppPreview"]["walletDecision"] == "deny", str(payload["miniAppPreview"]["walletDecision"])),
            Check("mira_preview_attached", payload["miniAppPreview"]["miraSchema"] == "0guard.mira_preview.v1", str(payload["miniAppPreview"]["miraSchema"])),
            Check("miniapp_preview_no_send", preview.get("telegram_send") is False, _disabled_label(preview.get("telegram_send"))),
            Check("miniapp_preview_no_network_calls", preview.get("network_calls") is False, _disabled_label(preview.get("network_calls"))),
        ]
    )

    payload["routeProbes"] = _route_probes(base_url)

    if token:
        bot = _telegram_readbacks(token)
        payload["telegramApi"] = bot
        checks.extend(
            [
                Check("telegram_get_me", bot["getMe"]["ok"] is True and bot["getMe"]["username"] == "Raris0guardBot", str(bot["getMe"])),
                Check("telegram_menu_button", bot["menuButton"]["webAppUrl"] == f"{base_url}/telegram", str(bot["menuButton"])),
                Check("telegram_webhook_set", bot["webhook"]["urlSet"] is True, str(bot["webhook"])),
                Check("telegram_webhook_no_last_error", not bot["webhook"].get("lastErrorMessage"), bot["webhook"].get("lastErrorMessage") or "none"),
            ]
        )

    if token and webhook_secret:
        webhook_route = _post_json(
            f"{base_url}/api/telegram/webhook",
            {
                "message": {
                    "chat": {"id": 1234},
                    "from": {"id": 8675309, "username": "demo_operator", "is_bot": False},
                    "text": "/start",
                }
            },
            headers={"X-Telegram-Bot-Api-Secret-Token": webhook_secret},
        )
        payload["webhookRoute"] = {
            "schema": webhook_route.get("schema"),
            "action": webhook_route.get("action"),
            "telegramSend": webhook_route.get("telegram_send"),
            "networkCalls": webhook_route.get("network_calls"),
        }
        checks.extend(
            [
                Check("webhook_route_secret_header", webhook_route.get("schema") == "0guard.telegram_webhook.v1", str(webhook_route.get("schema"))),
                Check("webhook_route_no_send", webhook_route.get("telegram_send") is False, _disabled_label(webhook_route.get("telegram_send"))),
            ]
        )

    payload["checks"] = [check.__dict__ for check in checks]
    payload["ok"] = all(check.ok for check in checks)
    if args.format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(_markdown(payload))
    return 0 if payload["ok"] else 1


def _select_base_url(requested: str) -> str:
    candidates: list[str] = []
    for url in (requested, DEFAULT_BASE_URL, *FALLBACK_BASE_URLS):
        normalized = url.rstrip("/")
        if normalized and normalized not in candidates:
            candidates.append(normalized)

    last_error: Exception | None = None
    for candidate in candidates:
        try:
            _load_health(candidate)
        except requests.RequestException as exc:
            last_error = exc
            continue
        return candidate

    if last_error is not None:
        raise last_error
    return requested


def _load_secret(env_name: str, secret_name: str, project: str) -> str:
    if env_name and os.getenv(env_name):
        return os.environ[env_name]
    try:
        result = subprocess.run(
            [
                "gcloud",
                "secrets",
                "versions",
                "access",
                "latest",
                f"--secret={secret_name}",
                f"--project={project}",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip()


def _get_json(url: str) -> dict[str, Any]:
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.json()


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
    response = requests.post(url, json=payload, headers=headers or {}, timeout=30)
    response.raise_for_status()
    return response.json()


def _route_probes(base_url: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for name, path in ROUTE_PROBES:
        url = f"{base_url}{path}"
        try:
            start = time.monotonic()
            resp = requests.get(url, timeout=25)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            results.append({"name": name, "path": path, "status": resp.status_code, "elapsedMs": elapsed_ms})
        except requests.RequestException as exc:
            results.append({"name": name, "path": path, "status": None, "error": str(exc)})
    return results


def _load_health(base_url: str) -> tuple[str, dict[str, Any]]:
    try:
        return "/api/healthz", _get_json(f"{base_url}/api/healthz")
    except requests.HTTPError as exc:
        if exc.response is None or exc.response.status_code != 404:
            raise
    return "/api/health", _get_json(f"{base_url}/api/health")


def _signed_demo_init_data(bot_token: str) -> str:
    fields = {
        "auth_date": str(int(time.time())),
        "query_id": "AAH0guard-smoke",
        "user": json.dumps(
            {"id": 8675309, "username": "demo_operator", "first_name": "Demo"},
            separators=(",", ":"),
        ),
    }
    data_check_string = "\n".join(f"{key}={fields[key]}" for key in sorted(fields))
    secret_key = hmac.new(b"WebAppData", bot_token.encode(), hashlib.sha256).digest()
    signature = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()
    return urlencode({**fields, "hash": signature})


def _telegram_readbacks(bot_token: str) -> dict[str, Any]:
    base = f"https://api.telegram.org/bot{bot_token}"
    get_me = _get_json(f"{base}/getMe")
    menu = _get_json(f"{base}/getChatMenuButton")
    webhook = _get_json(f"{base}/getWebhookInfo")
    commands = _get_json(f"{base}/getMyCommands")
    menu_result = menu.get("result") or {}
    webhook_result = webhook.get("result") or {}
    return {
        "getMe": {
            "ok": get_me.get("ok"),
            "username": (get_me.get("result") or {}).get("username"),
            "isBot": (get_me.get("result") or {}).get("is_bot"),
        },
        "menuButton": {
            "type": menu_result.get("type"),
            "text": menu_result.get("text"),
            "webAppUrl": (menu_result.get("web_app") or {}).get("url"),
        },
        "webhook": {
            "urlSet": bool(webhook_result.get("url")),
            "pendingUpdateCount": webhook_result.get("pending_update_count"),
            "allowedUpdates": webhook_result.get("allowed_updates"),
            "lastErrorMessage": webhook_result.get("last_error_message"),
        },
        "commands": commands.get("result") or [],
    }


def _disabled_label(value: Any) -> str:
    return "disabled" if value is False else str(value)


def _status_summary(status: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": status.get("schema"),
        "botTokenConfigured": (status.get("miniAppAuth") or {}).get("botTokenConfigured"),
        "telegramBotUsernameConfigured": (status.get("registration") or {}).get(
            "telegramBotUsernameConfigured"
        ),
        "secretSource": (status.get("registration") or {}).get("secretSource"),
        "secretConfiguredForProduction": (status.get("registration") or {}).get(
            "secretConfiguredForProduction"
        ),
        "telegramSendsEnabled": (status.get("safety") or {}).get("telegramSendsEnabled"),
    }


def _markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# 0guard Telegram Production Smoke",
        "",
        f"Base URL: {payload['baseUrl']}",
        f"Overall: {'ok' if payload['ok'] else 'failed'}",
        "Token printed: false",
        "",
        "## Checks",
    ]
    for check in payload["checks"]:
        mark = "ready" if check["ok"] else "blocked"
        lines.append(f"- `{mark}` {check['name']}: {check['detail']}")

    probes = payload.get("routeProbes") or []
    if probes:
        lines.extend(["", "## Route Probes (diagnostic)"])
        for probe in probes:
            status = probe.get("status")
            if status is None:
                lines.append(f"- `warn` {probe['name']}: error={probe.get('error','unknown')} path={probe['path']}")
            else:
                elapsed = probe.get("elapsedMs")
                elapsed_label = f" ({elapsed}ms)" if isinstance(elapsed, int) else ""
                lines.append(f"- `info` {probe['name']}: {status}{elapsed_label} {probe['path']}")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
