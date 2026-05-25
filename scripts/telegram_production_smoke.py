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
SAPPHIRE_PROGRESS_URLS: tuple[str, ...] = (
    "https://sapphirealpha.xyz/api/0guard/progress",
    "https://www.sapphirealpha.xyz/api/0guard/progress",
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
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=None,
        help="HTTP timeout used for all requests (default: 12s when --skip-telegram-api else 30s).",
    )
    parser.add_argument(
        "--route-timeout-seconds",
        type=float,
        default=None,
        help="HTTP timeout for route probe GETs (default: 12s when --skip-telegram-api else 25s).",
    )
    parser.add_argument(
        "--budget-seconds",
        type=float,
        default=None,
        help="Overall time budget for all checks (default: 20s when --skip-telegram-api else unlimited).",
    )
    parser.add_argument(
        "--route-budget-seconds",
        type=float,
        default=None,
        help="Time budget for route probes (default: 10s when --skip-telegram-api else unlimited).",
    )
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    args = parser.parse_args(argv)

    http_timeout = (
        args.timeout_seconds if args.timeout_seconds is not None else (20.0 if args.skip_telegram_api else 30.0)
    )
    route_timeout = (
        args.route_timeout_seconds
        if args.route_timeout_seconds is not None
        else (20.0 if args.skip_telegram_api else 25.0)
    )
    overall_budget = args.budget_seconds if args.budget_seconds is not None else (75.0 if args.skip_telegram_api else None)
    route_budget = (
        args.route_budget_seconds
        if args.route_budget_seconds is not None
        else (55.0 if args.skip_telegram_api else None)
    )
    deadline = (time.monotonic() + overall_budget) if overall_budget else None

    token = "" if args.skip_telegram_api else _load_secret(args.bot_token_env, args.bot_token_secret, args.gcloud_project)
    webhook_secret = "" if args.skip_telegram_api else _load_secret("", args.webhook_secret, args.gcloud_project)
    requested_base_url = args.base_url.rstrip("/")
    sapphire_discovered_base_urls = _discover_base_urls_from_sapphire(timeout=http_timeout)
    sapphire_active_base_url = sapphire_discovered_base_urls[0] if sapphire_discovered_base_urls else None
    candidates = _base_url_candidates(
        requested_base_url,
        sapphire_discovered_base_urls=sapphire_discovered_base_urls,
    )
    try:
        base_url = _select_base_url(
            requested_base_url,
            sapphire_discovered_base_urls=sapphire_discovered_base_urls,
            timeout=http_timeout,
            deadline=deadline,
        )
    except (requests.RequestException, TimeoutError) as exc:
        timed_out = isinstance(exc, TimeoutError)
        payload: dict[str, Any] = {
            "baseUrl": requested_base_url,
            "sapphireActiveBaseUrl": sapphire_active_base_url,
            "baseUrlSelection": {"ok": False, "tried": candidates, "error": str(exc)},
            "error": str(exc),
            "tokenPrinted": False,
            "timedOut": timed_out,
            "checks": [],
            "ok": False,
        }
        if args.format == "json":
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(_markdown(payload))
        return 1

    checks: list[Check] = []
    payload: dict[str, Any] = {
        "baseUrl": base_url,
        "sapphireActiveBaseUrl": sapphire_active_base_url,
        "baseUrlSelection": {"ok": True, "tried": candidates},
        "tokenPrinted": False,
        "timedOut": False,
    }

    timed_out = False
    try:
        health_path, health = _load_health(base_url, timeout=http_timeout, deadline=deadline)
    except (TimeoutError, requests.RequestException) as exc:
        timed_out = isinstance(exc, TimeoutError) or isinstance(exc, requests.Timeout)
        payload["timedOut"] = True
        payload["error"] = str(exc)
        payload["checks"] = []
        payload["ok"] = False
        _emit(payload, args.format)
        return 1
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

    try:
        status = _get_json(f"{base_url}/api/telegram/status", timeout=http_timeout, deadline=deadline)
    except (TimeoutError, requests.RequestException):
        timed_out = True
        status = {}
    payload["telegramStatus"] = _status_summary(status)
    miniapp_auth = status.get("miniAppAuth") or {}
    registration = status.get("registration") or {}
    safety = status.get("safety") or {}
    checks.extend(
        [
            Check(
                "cloud_run_bot_token_configured",
                miniapp_auth.get("botTokenConfigured") is True,
                str(miniapp_auth.get("botTokenConfigured")),
            ),
            Check(
                "cloud_run_bot_username_configured",
                registration.get("telegramBotUsernameConfigured") is True,
                str(registration.get("telegramBotUsernameConfigured")),
            ),
            Check(
                "telegram_sends_disabled",
                safety.get("telegramSendsEnabled") is False,
                _disabled_label(safety.get("telegramSendsEnabled")),
            ),
            Check("registration_secret_env", registration.get("secretSource") == "env", str(registration.get("secretSource"))),
        ]
    )

    try:
        session = _post_json(
            f"{base_url}/api/telegram/miniapp/session",
            {},
            timeout=http_timeout,
            deadline=deadline,
        )
    except (TimeoutError, requests.RequestException):
        timed_out = True
        session = {}
    payload["browserPreviewSession"] = {
        "schema": session.get("schema"),
        "mode": session.get("mode"),
        "validated": (session.get("auth") or {}).get("validated"),
        "telegramSendsEnabled": (session.get("safety") or {}).get("telegramSendsEnabled"),
    }
    checks.append(Check("browser_preview_session", session.get("mode") == "local_browser_preview", str(session.get("mode"))))

    if token:
        try:
            signed_session = _post_json(
                f"{base_url}/api/telegram/miniapp/session",
                {"initData": _signed_demo_init_data(token)},
                timeout=http_timeout,
                deadline=deadline,
            )
        except (TimeoutError, requests.RequestException):
            timed_out = True
            signed_session = {}
        auth = signed_session.get("auth") or {}
        payload["signedTelegramSession"] = {
            "schema": signed_session.get("schema"),
            "mode": signed_session.get("mode"),
            "validated": auth.get("validated"),
            "user": auth.get("user"),
            "telegramSendsEnabled": (signed_session.get("safety") or {}).get("telegramSendsEnabled"),
        }
        checks.append(Check("signed_init_data_validates", auth.get("validated") is True, str(auth.get("validated"))))

    try:
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
            timeout=http_timeout,
            deadline=deadline,
        )
    except (TimeoutError, requests.RequestException):
        timed_out = True
        preview = {}
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

    # Route probes should get their own budget window; starting the route deadline
    # before earlier health/preview checks can leave only a few seconds remaining
    # and produces confusing "budget exhausted" diagnostics.
    route_deadline = (time.monotonic() + route_budget) if route_budget else None
    payload["routeProbes"] = _route_probes(base_url, timeout=route_timeout, deadline=route_deadline)

    if token:
        try:
            bot = _telegram_readbacks(token, timeout=http_timeout)
        except (TimeoutError, requests.RequestException):
            timed_out = True
            bot = {}
        payload["telegramApi"] = bot
        get_me = bot.get("getMe") or {}
        menu_button = bot.get("menuButton") or {}
        webhook = bot.get("webhook") or {}
        checks.extend(
            [
                Check(
                    "telegram_get_me",
                    get_me.get("ok") is True and get_me.get("username") == "Raris0guardBot",
                    str(get_me),
                ),
                Check(
                    "telegram_menu_button",
                    menu_button.get("webAppUrl") == f"{base_url}/telegram",
                    str(menu_button),
                ),
                Check("telegram_webhook_set", webhook.get("urlSet") is True, str(webhook)),
                Check(
                    "telegram_webhook_no_last_error",
                    not webhook.get("lastErrorMessage"),
                    webhook.get("lastErrorMessage") or "none",
                ),
            ]
        )

    if token and webhook_secret:
        try:
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
                timeout=http_timeout,
                deadline=deadline,
            )
        except (TimeoutError, requests.RequestException):
            timed_out = True
            webhook_route = {}
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
    if timed_out:
        payload["timedOut"] = True
    payload["ok"] = all(check.ok for check in checks)
    _emit(payload, args.format)
    return 0 if payload["ok"] else 1


def _emit(payload: dict[str, Any], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(_markdown(payload))


def _select_base_url(
    requested: str,
    *,
    sapphire_discovered_base_urls: list[str] | None = None,
    timeout: float,
    deadline: float | None = None,
) -> str:
    candidates = _base_url_candidates(
        requested,
        sapphire_discovered_base_urls=sapphire_discovered_base_urls,
    )
    preferred = candidates[0] if candidates else requested
    requested_error: Exception | None = None
    last_error: Exception | None = None

    try:
        _load_health(preferred, timeout=timeout, deadline=deadline)
        return preferred
    except (requests.RequestException, TimeoutError) as exc:
        if preferred == requested:
            requested_error = exc
        last_error = exc

    for candidate in candidates:
        if candidate == preferred:
            continue
        try:
            _load_health(candidate, timeout=timeout, deadline=deadline)
        except (requests.RequestException, TimeoutError) as exc:
            last_error = exc
            continue
        return candidate

    if preferred != requested:
        try:
            _load_health(requested, timeout=timeout, deadline=deadline)
            return requested
        except (requests.RequestException, TimeoutError) as exc:
            requested_error = exc
            last_error = exc

    if requested_error is not None:
        raise requested_error
    if last_error is not None:
        raise last_error
    return requested


def _base_url_candidates(
    requested: str,
    *,
    sapphire_discovered_base_urls: list[str] | None = None,
) -> list[str]:
    candidates: list[str] = []
    ordered_urls = (
        (*(sapphire_discovered_base_urls or []), requested, DEFAULT_BASE_URL)
        if requested.rstrip("/") == DEFAULT_BASE_URL.rstrip("/") and sapphire_discovered_base_urls
        else (requested, *(sapphire_discovered_base_urls or []), DEFAULT_BASE_URL)
    )
    for url in ordered_urls:
        normalized = url.rstrip("/")
        if normalized and normalized not in candidates:
            candidates.append(normalized)
    return candidates


def _discover_base_urls_from_sapphire(*, timeout: float) -> list[str]:
    headers = {"User-Agent": "0guard-telegram-smoke/1.0"}
    discovered: list[str] = []
    for url in SAPPHIRE_PROGRESS_URLS:
        for attempt in range(2):
            try:
                response = requests.get(url, timeout=timeout, headers=headers)
            except requests.RequestException:
                if attempt == 0:
                    time.sleep(0.4)
                    continue
                break
            if response.status_code != 200:
                break
            if "application/json" not in response.headers.get("content-type", ""):
                break
            try:
                data = response.json()
            except ValueError:
                break
            for key in ("base_url", "baseUrl", "candidate_url", "candidateUrl"):
                value = data.get(key)
                if isinstance(value, str):
                    normalized = value.strip().rstrip("/")
                    if normalized and normalized not in discovered:
                        discovered.append(normalized)
            break
    return discovered


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


def _get_json(url: str, *, timeout: float, deadline: float | None = None) -> dict[str, Any]:
    response = requests.get(url, timeout=_bounded_timeout(timeout, deadline))
    response.raise_for_status()
    return response.json()


def _post_json(
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
    *,
    timeout: float,
    deadline: float | None = None,
) -> dict[str, Any]:
    response = requests.post(
        url,
        json=payload,
        headers=headers or {},
        timeout=_bounded_timeout(timeout, deadline),
    )
    response.raise_for_status()
    return response.json()


def _route_probes(base_url: str, *, timeout: float, deadline: float | None = None) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for name, path in ROUTE_PROBES:
        if deadline is not None and time.monotonic() >= deadline:
            results.append(
                {
                    "name": "route_probe_budget",
                    "path": path,
                    "status": None,
                    "error": "time budget exhausted",
                }
            )
            break
        url = f"{base_url}{path}"
        try:
            start = time.monotonic()
            resp = requests.get(url, timeout=_bounded_timeout(timeout, deadline))
            elapsed_ms = int((time.monotonic() - start) * 1000)
            results.append({"name": name, "path": path, "status": resp.status_code, "elapsedMs": elapsed_ms})
        except (requests.RequestException, TimeoutError) as exc:
            results.append({"name": name, "path": path, "status": None, "error": str(exc)})
    return results


def _load_health(base_url: str, *, timeout: float, deadline: float | None = None) -> tuple[str, dict[str, Any]]:
    try:
        return "/api/healthz", _get_json(f"{base_url}/api/healthz", timeout=timeout, deadline=deadline)
    except requests.HTTPError as exc:
        if exc.response is None or exc.response.status_code != 404:
            raise
    return "/api/health", _get_json(f"{base_url}/api/health", timeout=timeout, deadline=deadline)


def _bounded_timeout(timeout: float, deadline: float | None) -> float:
    if deadline is None:
        return timeout
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("time budget exhausted")
    return max(0.5, min(timeout, remaining))


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


def _telegram_readbacks(bot_token: str, *, timeout: float) -> dict[str, Any]:
    base = f"https://api.telegram.org/bot{bot_token}"
    get_me = _get_json(f"{base}/getMe", timeout=timeout)
    menu = _get_json(f"{base}/getChatMenuButton", timeout=timeout)
    webhook = _get_json(f"{base}/getWebhookInfo", timeout=timeout)
    commands = _get_json(f"{base}/getMyCommands", timeout=timeout)
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
        *(["Timed out: true"] if payload.get("timedOut") is True else []),
        *(["", f"Error: {payload['error']}"] if payload.get("error") else []),
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
                level = "info" if probe.get("name") == "route_probe_budget" else "warn"
                lines.append(f"- `{level}` {probe['name']}: error={probe.get('error','unknown')} path={probe['path']}")
            else:
                elapsed = probe.get("elapsedMs")
                elapsed_label = f" ({elapsed}ms)" if isinstance(elapsed, int) else ""
                lines.append(f"- `info` {probe['name']}: {status}{elapsed_label} {probe['path']}")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
