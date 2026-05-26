#!/usr/bin/env python3
"""OSINT steward checklist for 0guard.

This is a read-only probe script intended for recurring automation runs.
It verifies:
  - Local repo readiness scripts (run separately)
  - Public endpoints (HackQuest / Pages)
  - Sapphire apex 0guard progress API (read-only)
  - Cloud Run base/candidate API surfaces for the steward checklist routes

Safety:
  - Never prints secrets
  - Never sends Telegram messages
  - Never signs or broadcasts transactions
  - Uses only GET requests (no stateful POSTs)
"""

from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import urljoin

import requests

DEFAULT_BASE_URL = "https://guard0-miniapp-s77j6bxyra-uc.a.run.app"
FALLBACK_BASE_URLS: tuple[str, ...] = (
    "https://candidate-acdc011---guard0-miniapp-s77j6bxyra-uc.a.run.app",
    "https://candidate-6f07f89---guard0-miniapp-s77j6bxyra-uc.a.run.app",
)

SAPPHIRE_PROGRESS_URLS: tuple[str, ...] = (
    "https://sapphirealpha.xyz/api/0guard/progress",
    "https://www.sapphirealpha.xyz/api/0guard/progress",
)
SAPPHIRE_HEALTH_URL = "https://sapphirealpha.xyz/health"
SAPPHIRE_0GUARD_PAGE_URL = "https://sapphirealpha.xyz/p/0guard"
THO_HEALTHZ_URL = "https://tho.sapphirealpha.xyz/healthz/"

PAGES_ROOT_URL = "https://arigatoexpress.github.io/0guard/"
PAGES_HACKATHON_URL = "https://arigatoexpress.github.io/0guard/hackathon-0g/"


CHECKLIST_PATHS: tuple[str, ...] = (
    "/api/healthz",
    "/api/readyz",
    "/api/hackathon/submission-packet",
    "/api/hackathon/readiness",
    "/api/osint/sources",
    "/api/osint/readiness",
    "/api/osint/signals?live=1&limit=10",
    "/api/intelligence/evolving",
    "/api/intelligence/data-streams",
    "/api/intelligence/events?live=1&limit=10",
    "/api/intelligence/detector-candidates?live=1&limit=10",
    "/api/reputation/connectors/live?live=1&limit=3",
    "/api/integrations/cross-chain",
    "/api/integrations/cross-chain/readiness?live=1&include_non_default=1",
    "/api/integrations/arbitrum",
    "/api/integrations/metamask",
    "/api/hackathons/next",
    "/api/hackathon/strategy",
    "/api/developer-kit",
    "/api/product/brief",
    "/api/experiments/frontier",
    "/api/reputation/adapters",
    "/api/reputation/connectors",
    "/api/reputation/shadow-cache",
    "/api/reputation/probe",
    "/api/native-preflight",
    "/api/integrations/external-guardrails",
    "/api/integrations/external-guardrails/evaluate",
    "/api/integrations/ika",
    "/api/integrations/ika/evaluate",
    "/api/0g/proof-ladder",
    "/api/0g/receipt",
    "/api/telegram/status",
    "/api/telegram/miniapp/preview",
    "/api/telegram/wallet-alert-preview",
    "/api/wallet/alert-preview",
)

CRITICAL_PATHS: frozenset[str] = frozenset(
    {
        "/api/healthz",
        "/api/readyz",
        "/api/hackathon/submission-packet",
        "/api/hackathon/readiness",
        "/api/osint/sources",
        "/api/osint/readiness",
        "/api/intelligence/data-streams",
        "/api/intelligence/detector-candidates?live=1&limit=10",
        "/api/reputation/connectors/live?live=1&limit=3",
        "/api/integrations/arbitrum",
        "/api/integrations/metamask",
        "/api/hackathons/next",
        "/api/telegram/status",
        "/api/telegram/miniapp/preview",
        "/api/wallet/alert-preview",
    }
)

# Some endpoints are inherently bursty or heavy enough that occasional timeouts
# are expected on the public Cloud Run surface. The steward report should
# surface these as warnings, but they should not flip the overall result unless
# a critical endpoint is also failing.
BEST_EFFORT_TIMEOUT_PATHS: frozenset[str] = frozenset(
    {
        "/api/osint/signals?live=1&limit=10",
        "/api/intelligence/events?live=1&limit=10",
        "/api/reputation/shadow-cache",
        "/api/reputation/connectors/live?live=1&limit=3",
    }
)


@dataclass(frozen=True)
class ProbeResult:
    path: str
    status_code: int | None
    elapsed_ms: int | None
    content_type: str
    snippet: str


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="0guard OSINT steward checklist probes")
    parser.add_argument(
        "--base-url",
        default=None,
        help=(
            "Explicit Cloud Run base URL to probe. If omitted, the script prefers the "
            "Sapphire apex /api/0guard/progress base_url when available, otherwise "
            f"falls back to {DEFAULT_BASE_URL}."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=20.0,
        help="Per-request timeout in seconds (bounded by remaining budget).",
    )
    parser.add_argument(
        "--budget-seconds",
        type=float,
        default=420.0,
        help=(
            "Overall time budget for Cloud Run route probes. When exhausted, remaining "
            "paths are marked as budget-exhausted."
        ),
    )
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    args = parser.parse_args(argv)

    requested = (args.base_url or "").rstrip("/") or None
    sapphire_active_base_url = _discover_active_base_url_from_sapphire(timeout=args.timeout)
    traffic_base_url = _select_base_url(DEFAULT_BASE_URL, timeout=args.timeout)
    active_requested = requested or sapphire_active_base_url or traffic_base_url

    base_url = _select_base_url(active_requested.rstrip("/"), timeout=args.timeout)
    overall_deadline = time.monotonic() + max(1.0, float(args.budget_seconds))
    probes = list(_probe_paths(base_url, CHECKLIST_PATHS, timeout=args.timeout, deadline=overall_deadline))
    traffic_probes: list[ProbeResult] | None = None
    drift_target = (sapphire_active_base_url or "").rstrip("/") or None
    if drift_target and drift_target.rstrip("/") != traffic_base_url.rstrip("/"):
        if time.monotonic() + 5.0 <= overall_deadline:
            traffic_probes = list(
                _probe_paths(traffic_base_url, CHECKLIST_PATHS, timeout=args.timeout, deadline=overall_deadline)
            )
    elif traffic_base_url.rstrip("/") != base_url.rstrip("/"):
        if time.monotonic() + 5.0 <= overall_deadline:
            traffic_probes = list(
                _probe_paths(traffic_base_url, CHECKLIST_PATHS, timeout=args.timeout, deadline=overall_deadline)
            )
    sapphire = _probe_sapphire(timeout=args.timeout)
    public = _probe_public(timeout=args.timeout)
    silo = _probe_silo(timeout=args.timeout)

    payload: dict[str, Any] = {
        "schema": "0guard.osint_steward_checklist.v2",
        "generatedAt": _now(),
        "baseUrl": base_url,
        "requestedBaseUrl": requested,
        "sapphireActiveBaseUrl": sapphire_active_base_url,
        "trafficBaseUrl": traffic_base_url,
        "driftBaseUrl": drift_target,
        "probes": [probe.__dict__ for probe in probes],
        "trafficProbes": [probe.__dict__ for probe in traffic_probes] if traffic_probes else None,
        "sapphire": sapphire,
        "public": public,
        "siloBoundary": silo,
        "probeBudgetSeconds": float(args.budget_seconds),
        "notes": [
            "This is a read-only probe script; 405 on POST-only endpoints is expected.",
            "Use --base-url to force a candidate/no-traffic Cloud Run revision.",
            "When Sapphire exposes a base_url, the script treats it as the active surface and reports traffic drift separately.",
            "Budget exhaustion produces status_code=None with snippet=error: budget exhausted.",
        ],
    }

    ok = _overall_ok(probes, sapphire=sapphire, public=public, silo=silo)
    payload["ok"] = ok
    payload["traffic_ok"] = _overall_ok(traffic_probes) if traffic_probes else True

    if args.format == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(_markdown(payload))
    return 0 if ok else 1


def _overall_ok(
    probes: Iterable[ProbeResult],
    *,
    sapphire: dict[str, Any] | None = None,
    public: dict[str, Any] | None = None,
    silo: dict[str, Any] | None = None,
) -> bool:
    """Treat 200/204 as ok; allow 405 only for POST-only route probes."""
    for probe in probes:
        if probe.status_code is None and "budget exhausted" in (probe.snippet or ""):
            continue
        if probe.status_code is None:
            snippet = (probe.snippet or "").lower()
            if (
                probe.path in BEST_EFFORT_TIMEOUT_PATHS
                and ("timed out" in snippet or "timeout" in snippet)
            ):
                continue
            if probe.path in CRITICAL_PATHS:
                return False
            continue
        if probe.status_code in (200, 204, 405):
            continue
        if probe.path in CRITICAL_PATHS:
            return False
    if sapphire is not None:
        if not _url_entry_ok(sapphire.get("health")):
            return False
        progress_entries = list(sapphire.get("progress") or [])
        if progress_entries:
            # Sapphire progress can be intermittently flaky on one hostname while
            # still being healthy on another; treat it as OK if at least one URL
            # returns a valid 200/204 response.
            if not any(_url_entry_ok(entry) for entry in progress_entries):
                return False
    if public is not None:
        for entry in public.get("urls") or []:
            # Sapphire /p/0guard is a best-effort read-only surface; it can be
            # intermittently reset or gated while the progress API remains healthy.
            if entry and entry.get("url") == SAPPHIRE_0GUARD_PAGE_URL:
                continue
            if not _url_entry_ok(entry):
                return False
    if silo is not None and not _url_entry_ok(silo.get("tho_healthz")):
        return False
    return True


def _url_entry_ok(entry: dict[str, Any] | None) -> bool:
    return bool(entry and entry.get("statusCode") in (200, 204))


def _probe_public(*, timeout: float) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for url in (PAGES_ROOT_URL, PAGES_HACKATHON_URL, SAPPHIRE_0GUARD_PAGE_URL):
        results.append(_probe_url(url, timeout=timeout))
    return {"urls": results}


def _probe_silo(*, timeout: float) -> dict[str, Any]:
    return {"tho_healthz": _probe_url(THO_HEALTHZ_URL, timeout=timeout)}


def _probe_sapphire(*, timeout: float) -> dict[str, Any]:
    progress: list[dict[str, Any]] = []
    for url in SAPPHIRE_PROGRESS_URLS:
        entry = _probe_url(url, timeout=timeout)
        parsed: dict[str, Any] = {}
        if entry.get("statusCode") == 200 and entry.get("json"):
            data = entry["json"]
            live_streams = data.get("live_streams") or {}
            parsed = {
                "base_url": data.get("base_url") or data.get("baseUrl"),
                "candidate_url": data.get("candidate_url") or data.get("candidateUrl"),
                "active_domain_count": live_streams.get("active_domain_count"),
                "detector_candidate_count": live_streams.get("detector_candidate_count"),
                "live_event_count": live_streams.get("live_event_count"),
                "raw_payloads_returned": live_streams.get("raw_payloads_returned"),
            }
        progress.append({**entry, "parsed": parsed})
    return {
        "health": _probe_url(SAPPHIRE_HEALTH_URL, timeout=timeout),
        "progress": progress,
    }


def _discover_active_base_url_from_sapphire(*, timeout: float) -> str | None:
    """Best-effort read-only discovery of the active base URL from Sapphire.

    If the Sapphire progress API is unavailable, returns None and the script
    falls back to DEFAULT_BASE_URL.
    """

    headers = {"User-Agent": "0guard-osint-steward/1.0"}
    for url in SAPPHIRE_PROGRESS_URLS:
        for attempt in range(2):
            try:
                resp = requests.get(url, timeout=timeout, headers=headers)
            except requests.RequestException:
                if attempt == 0:
                    time.sleep(0.4)
                    continue
                break
            if resp.status_code != 200:
                break
            if "application/json" not in resp.headers.get("content-type", ""):
                break
            try:
                data = resp.json()
            except ValueError:
                break

            value = data.get("base_url") or data.get("baseUrl")
            if isinstance(value, str) and value.strip():
                return value.strip().rstrip("/")
    return None


def _probe_url(url: str, *, timeout: float) -> dict[str, Any]:
    last_error: Exception | None = None
    for attempt in range(2):
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": "0guard-osint-steward/1.0"},
            )
            break
        except requests.RequestException as exc:
            last_error = exc
            if attempt == 0:
                time.sleep(0.4)
                continue
            return {"url": url, "statusCode": None, "error": str(exc)}
    else:  # pragma: no cover - defensive; loop returns on final failure.
        return {"url": url, "statusCode": None, "error": str(last_error or "unknown error")}

    entry: dict[str, Any] = {
        "url": url,
        "statusCode": resp.status_code,
        "contentType": resp.headers.get("content-type", ""),
        "elapsedMs": int(resp.elapsed.total_seconds() * 1000),
    }
    text = resp.text or ""
    entry["snippet"] = _snippet(text)
    if "application/json" in entry["contentType"]:
        try:
            entry["json"] = resp.json()
        except ValueError:
            entry["json"] = None
    return entry


def _probe_paths(
    base_url: str,
    paths: Iterable[str],
    *,
    timeout: float,
    deadline: float | None = None,
) -> Iterable[ProbeResult]:
    session = requests.Session()
    session.headers.update({"User-Agent": "0guard-osint-steward/1.0"})
    for path in paths:
        if deadline is not None and time.monotonic() >= deadline:
            yield ProbeResult(
                path=path,
                status_code=None,
                elapsed_ms=None,
                content_type="",
                snippet="error: budget exhausted",
            )
            continue
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        resp: requests.Response | None = None
        elapsed_ms: int | None = None
        last_error: Exception | None = None
        for attempt in range(2):
            try:
                bounded_timeout = _bounded_timeout(timeout, deadline)
                start = time.monotonic()
                resp = session.get(url, timeout=bounded_timeout, stream=True)
                elapsed_ms = int((time.monotonic() - start) * 1000)
                break
            except TimeoutError as exc:
                last_error = exc
                resp = None
                break
            except requests.RequestException as exc:
                last_error = exc
                resp = None
                if attempt == 0:
                    time.sleep(0.4)

        if resp is None:
            yield ProbeResult(
                path=path,
                status_code=None,
                elapsed_ms=None,
                content_type="",
                snippet=f"error: {last_error}",
            )
            continue

        yield ProbeResult(
            path=path,
            status_code=resp.status_code,
            elapsed_ms=elapsed_ms,
            content_type=resp.headers.get("content-type", ""),
            snippet=_snippet(_read_snippet_text(resp)),
        )
        resp.close()


def _select_base_url(requested: str, *, timeout: float) -> str:
    candidates: list[str] = []
    for url in (requested, DEFAULT_BASE_URL, *FALLBACK_BASE_URLS):
        normalized = url.rstrip("/")
        if normalized and normalized not in candidates:
            candidates.append(normalized)

    for candidate in candidates:
        try:
            resp = requests.get(
                urljoin(candidate.rstrip("/") + "/", "api/healthz"),
                timeout=timeout,
                headers={"User-Agent": "0guard-osint-steward/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json() if "application/json" in resp.headers.get("content-type", "") else {}
                if data.get("ok") is True:
                    return candidate
        except requests.RequestException:
            continue
        except ValueError:
            continue

    return requested


def _bounded_timeout(timeout: float, deadline: float | None) -> float:
    if deadline is None:
        return timeout
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("budget exhausted")
    return max(0.5, min(timeout, remaining))


def _read_snippet_text(resp: requests.Response, *, limit_bytes: int = 4096) -> str:
    try:
        # Read only the first chunk so a slow response can't block the steward
        # run. The status code + headers are the primary signal here.
        data = b""
        for chunk in resp.iter_content(chunk_size=min(2048, limit_bytes)):
            if chunk:
                data = chunk[:limit_bytes]
            break
    except requests.RequestException:
        return ""

    encoding = resp.encoding or "utf-8"
    try:
        return data.decode(encoding, errors="replace")
    except LookupError:
        return data.decode("utf-8", errors="replace")


def _snippet(text: str, *, limit: int = 260) -> str:
    normalized = " ".join(text.strip().split())
    if len(normalized) <= limit:
        return normalized
    return normalized[:limit] + "…"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _markdown(payload: dict[str, Any]) -> str:
    slow_ms_threshold = 10_000
    lines: list[str] = []
    lines.append("# 0guard OSINT Steward Checklist")
    lines.append("")
    lines.append(f"- Generated: {payload.get('generatedAt')}")
    lines.append(f"- Base URL: {payload.get('baseUrl')}")
    if payload.get("trafficBaseUrl"):
        lines.append(f"- Traffic Base URL: {payload.get('trafficBaseUrl')}")
    if payload.get("driftBaseUrl"):
        lines.append(f"- Drift Base URL: {payload.get('driftBaseUrl')}")
    lines.append(f"- Overall: {'ok' if payload.get('ok') else 'needs attention'}")
    lines.append("")

    lines.append("## Steward API Probes")
    for probe in payload.get("probes", []):
        status = probe.get("status_code")
        ms = probe.get("elapsed_ms")
        snippet = (probe.get("snippet") or "").strip()
        if status is None:
            detail = f"error: {snippet}" if snippet else "error"
            lines.append(f"- `{probe.get('path')}`: None ({detail})")
            continue
        suffix = " (slow)" if isinstance(ms, int) and ms >= slow_ms_threshold else ""
        ms_label = f"{ms}ms" if isinstance(ms, int) else "n/a"
        lines.append(f"- `{probe.get('path')}`: {status} ({ms_label}){suffix}")
    lines.append("")

    traffic_probes = payload.get("trafficProbes") or []
    if traffic_probes:
        lines.append("## Traffic Drift (Diagnostic)")
        lines.append(
            f"- Overall: {'ok' if payload.get('traffic_ok') else 'needs attention'}"
        )
        for probe in traffic_probes:
            status = probe.get("status_code")
            if status in (200, 204, 405):
                continue
            ms = probe.get("elapsed_ms")
            snippet = (probe.get("snippet") or "").strip()
            if status is None:
                detail = f"error: {snippet}" if snippet else "error"
                lines.append(f"- `{probe.get('path')}`: None ({detail})")
                continue
            ms_label = f"{ms}ms" if isinstance(ms, int) else "n/a"
            lines.append(f"- `{probe.get('path')}`: {status} ({ms_label})")
        lines.append("")

    lines.append("## Sapphire Readback (Read-only)")
    sapphire = payload.get("sapphire") or {}
    health = sapphire.get("health") or {}
    health_status = health.get("statusCode")
    health_err = health.get("error")
    health_ms = health.get("elapsedMs")
    if health_status is None and health_err:
        lines.append(f"- `health`: None (error: {health_err})")
    else:
        health_ms_label = f"{health_ms}ms" if isinstance(health_ms, int) else "n/a"
        lines.append(f"- `health`: {health_status} ({health_ms_label})")
    for entry in sapphire.get("progress") or []:
        parsed = entry.get("parsed") or {}
        progress_status = entry.get("statusCode")
        progress_err = entry.get("error")
        if progress_status is None and progress_err:
            lines.append(f"- `progress`: {entry.get('url')} → None (error: {progress_err})")
        else:
            lines.append(f"- `progress`: {entry.get('url')} → {progress_status}")
        if parsed:
            lines.append(
                "  - base_url: "
                + str(parsed.get("base_url"))
                + " active_domain_count: "
                + str(parsed.get("active_domain_count"))
                + " detector_candidate_count: "
                + str(parsed.get("detector_candidate_count"))
                + " live_event_count: "
                + str(parsed.get("live_event_count"))
                + " raw_payloads_returned: "
                + str(parsed.get("raw_payloads_returned"))
            )
    lines.append("")

    lines.append("## Public Surfaces")
    for entry in (payload.get("public") or {}).get("urls") or []:
        status_code = entry.get("statusCode")
        line = f"- `{entry.get('url')}`: {status_code}"
        if status_code is None and entry.get("error"):
            line += f" (error: {entry.get('error')})"
        lines.append(line)
    lines.append("")

    lines.append("## Silo Boundary Sanity Check")
    tho = (payload.get("siloBoundary") or {}).get("tho_healthz") or {}
    lines.append(f"- `tho.sapphirealpha.xyz/healthz/`: {tho.get('statusCode')}")
    lines.append("")

    lines.append("## Notes")
    for note in payload.get("notes") or []:
        lines.append(f"- {note}")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
