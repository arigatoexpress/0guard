"""Deployment-readiness packet for ZeroGuard promotion decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

import requests

from guard0.readiness import production_readiness

DEPLOYMENT_READINESS_SCHEMA = "0guard.deployment_readiness.v1"

GITHUB_PAGES_ROOT_URL = "https://arigatoexpress.github.io/0guard/"
HACKATHON_PROOF_HUB_URL = "https://arigatoexpress.github.io/0guard/hackathon-0g/"
MAINNET_PROOF_JSON_URL = (
    "https://arigatoexpress.github.io/0guard/hackathon-0g/mainnet-proof.json"
)
CLOUD_RUN_BASE_URL = "https://guard0-miniapp-s77j6bxyra-uc.a.run.app"
CLOUD_RUN_PROJECT = "sapphire-479610"
CLOUD_RUN_SERVICE = "guard0-miniapp"
CLOUD_RUN_REGION = "us-central1"

HttpGetter = Callable[..., Any]


def build_deployment_readiness(
    *,
    live: bool = False,
    http_get: HttpGetter | None = None,
    timeout_seconds: float = 5.0,
    local_readiness: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a no-side-effect promotion packet for app, docs, and proof surfaces."""

    readiness = local_readiness or _safe_local_readiness()
    local_checks = _checks_by_id(readiness)
    live_probes = _build_live_probes(
        live=live,
        http_get=http_get or requests.get,
        timeout_seconds=timeout_seconds,
    )
    gates = _promotion_gates(readiness, local_checks, live_probes, live=live)
    return {
        "schema": DEPLOYMENT_READINESS_SCHEMA,
        "generatedAt": _now(),
        "mode": "read_only_deployment_promotion_packet",
        "status": _status_from_gates(gates),
        "ok": all(gate["status"] == "ok" for gate in gates),
        "localReadiness": _local_readiness_summary(readiness),
        "deploymentTargets": _deployment_targets(),
        "publicSurfaces": _public_surfaces(),
        "liveProbes": live_probes,
        "promotionGates": gates,
        "nextActions": _next_actions(gates),
        "commands": _commands(),
        "safety": _safety(live=live),
    }


def _safe_local_readiness() -> dict[str, Any]:
    try:
        payload = production_readiness()
    except Exception as exc:  # pragma: no cover - defensive runtime fallback
        return {
            "schema": "0guard.readyz.unavailable",
            "generatedAt": _now(),
            "status": "unavailable",
            "ok": False,
            "reviewCount": None,
            "hardGates": ["local_readiness_unavailable"],
            "checks": [],
            "error": f"{type(exc).__name__}: {exc}",
        }
    return payload if isinstance(payload, dict) else {"status": "invalid_payload", "checks": []}


def _deployment_targets() -> list[dict[str, Any]]:
    return [
        {
            "id": "github_pages",
            "class": "static_public_proof_hub",
            "url": GITHUB_PAGES_ROOT_URL,
            "repoConfig": ".github/workflows/pages.yml",
            "deployTrigger": "push to main affecting docs/** or workflow_dispatch",
            "codifiedInRepo": True,
            "containsSecrets": False,
        },
        {
            "id": "cloud_run_miniapp",
            "class": "hosted_flask_api_and_telegram_shell",
            "url": CLOUD_RUN_BASE_URL,
            "project": CLOUD_RUN_PROJECT,
            "service": CLOUD_RUN_SERVICE,
            "region": CLOUD_RUN_REGION,
            "codifiedInRepo": False,
            "promotionRisk": "deploying from a dirty local tree can publish unreviewed WIP",
        },
        {
            "id": "render_blueprint",
            "class": "docker_web_service",
            "repoConfig": "render.yaml",
            "healthPath": "/api/health",
            "codifiedInRepo": True,
            "promotionRisk": "dashboard blueprint activation is external to repo CI",
        },
        {
            "id": "local_docker",
            "class": "container_smoke",
            "repoConfig": "Dockerfile",
            "healthPath": "/api/healthz",
            "codifiedInRepo": True,
            "containsSecrets": False,
        },
    ]


def _public_surfaces() -> list[dict[str, Any]]:
    return [
        {
            "id": "public_proof_hub",
            "url": HACKATHON_PROOF_HUB_URL,
            "purpose": "judge-facing static proof hub",
        },
        {
            "id": "mainnet_proof_json",
            "url": MAINNET_PROOF_JSON_URL,
            "purpose": "machine-readable 0G mainnet anchor proof",
        },
        {
            "id": "hosted_telegram_shell",
            "url": f"{CLOUD_RUN_BASE_URL}/telegram",
            "purpose": "hosted Mini App shell with sends disabled",
        },
        {
            "id": "hosted_readiness",
            "url": f"{CLOUD_RUN_BASE_URL}/api/readyz",
            "purpose": "hosted production-readiness readback",
        },
    ]


def _build_live_probes(
    *,
    live: bool,
    http_get: HttpGetter,
    timeout_seconds: float,
) -> dict[str, Any]:
    if not live:
        return {
            "mode": "not_requested",
            "requested": False,
            "targets": {
                "githubPagesRoot": _not_checked(GITHUB_PAGES_ROOT_URL),
                "proofHub": _not_checked(HACKATHON_PROOF_HUB_URL),
                "mainnetProofJson": _not_checked(MAINNET_PROOF_JSON_URL),
                "cloudRunHealthz": _not_checked(f"{CLOUD_RUN_BASE_URL}/api/healthz"),
                "cloudRunReadyz": _not_checked(f"{CLOUD_RUN_BASE_URL}/api/readyz"),
            },
        }

    targets = {
        "githubPagesRoot": _http_probe(http_get, GITHUB_PAGES_ROOT_URL, timeout_seconds),
        "proofHub": _http_probe(http_get, HACKATHON_PROOF_HUB_URL, timeout_seconds),
        "mainnetProofJson": _http_probe(http_get, MAINNET_PROOF_JSON_URL, timeout_seconds),
        "cloudRunHealthz": _http_probe(
            http_get,
            f"{CLOUD_RUN_BASE_URL}/api/healthz",
            timeout_seconds,
        ),
        "cloudRunReadyz": _http_probe(
            http_get,
            f"{CLOUD_RUN_BASE_URL}/api/readyz",
            timeout_seconds,
        ),
    }
    proof_payload = targets["mainnetProofJson"].get("json") or {}
    readyz_payload = targets["cloudRunReadyz"].get("json") or {}
    healthz_payload = targets["cloudRunHealthz"].get("json") or {}
    targets["mainnetProofJson"]["proofReady"] = (
        targets["mainnetProofJson"].get("ok") is True
        and proof_payload.get("schema") == "0guard.mainnet_proof.v1"
        and int(proof_payload.get("chain_id") or 0) == 16661
        and str(proof_payload.get("contract_address") or "").startswith("0x")
    )
    targets["cloudRunReadyz"]["schemaCurrent"] = (
        targets["cloudRunReadyz"].get("ok") is True
        and readyz_payload.get("schema") == "0guard.readyz.v1"
        and isinstance(readyz_payload.get("hardGates"), list)
        and bool(readyz_payload.get("status"))
    )
    targets["cloudRunHealthz"]["safetyLocksPresent"] = (
        targets["cloudRunHealthz"].get("ok") is True
        and healthz_payload.get("read_only") is True
        and healthz_payload.get("telegram_sends_enabled") is False
        and healthz_payload.get("money_movement_enabled") is False
    )
    return {
        "mode": "live_http_readback",
        "requested": True,
        "timeoutSeconds": timeout_seconds,
        "targets": targets,
    }


def _http_probe(http_get: HttpGetter, url: str, timeout_seconds: float) -> dict[str, Any]:
    try:
        response = http_get(url, timeout=timeout_seconds)
        status_code = int(getattr(response, "status_code", 0) or 0)
        headers = getattr(response, "headers", {}) or {}
        text = getattr(response, "text", "") or ""
        payload: dict[str, Any] | None = None
        try:
            parsed = response.json()
            payload = parsed if isinstance(parsed, dict) else {"jsonType": type(parsed).__name__}
        except (ValueError, TypeError, AttributeError):
            payload = None
        return {
            "url": url,
            "checked": True,
            "ok": 200 <= status_code < 400,
            "statusCode": status_code,
            "contentType": headers.get("content-type") or headers.get("Content-Type"),
            "contentLength": len(text),
            "json": payload,
        }
    except requests.RequestException as exc:
        return {
            "url": url,
            "checked": True,
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
        }


def _not_checked(url: str) -> dict[str, Any]:
    return {
        "url": url,
        "checked": False,
        "ok": None,
        "reason": "live_probe_not_requested",
    }


def _promotion_gates(
    readiness: dict[str, Any],
    local_checks: dict[str, dict[str, Any]],
    probes: dict[str, Any],
    *,
    live: bool,
) -> list[dict[str, Any]]:
    targets = probes.get("targets") or {}
    return [
        _gate(
            "local_readiness_review",
            "Local readiness has no unresolved production gates.",
            "ok" if readiness.get("ok") is True else "review",
            {
                "status": readiness.get("status"),
                "reviewCount": readiness.get("reviewCount"),
                "hardGates": readiness.get("hardGates") or [],
            },
            "Resolve or explicitly scope remaining hard gates before calling the app production-ready.",
        ),
        _gate(
            "pages_public_proof_reachable",
            "GitHub Pages proof hub and mainnet proof JSON are reachable.",
            _probe_gate_status(targets.get("mainnetProofJson"), live, truth_key="proofReady"),
            {
                "proofHub": _probe_summary(targets.get("proofHub")),
                "mainnetProofJson": _probe_summary(targets.get("mainnetProofJson")),
            },
            "Run the Pages workflow or merge docs changes when the proof hub is stale.",
        ),
        _gate(
            "hosted_api_reachable",
            "Hosted Cloud Run API answers health checks with safety locks on.",
            _probe_gate_status(targets.get("cloudRunHealthz"), live, truth_key="safetyLocksPresent"),
            {"cloudRunHealthz": _probe_summary(targets.get("cloudRunHealthz"))},
            "Deploy only from a reviewed clean revision, then read back /api/healthz.",
        ),
        _gate(
            "hosted_api_schema_current",
            "Hosted Cloud Run readiness schema matches the local readiness contract.",
            _probe_gate_status(targets.get("cloudRunReadyz"), live, truth_key="schemaCurrent"),
            {"cloudRunReadyz": _probe_summary(targets.get("cloudRunReadyz"))},
            "Promote the current app after tests, then verify /api/readyz exposes status and hardGates.",
        ),
        _check_gate(
            "storage_peer_depth",
            "0G storage node has enough peers for larger funding and production claims.",
            local_checks.get("storage_node_funded_soak"),
            "Keep the funded soak running, verify UDP/libp2p discovery, and wait for peer depth.",
        ),
        _check_gate(
            "telegram_live_identity",
            "Telegram bot identity and webhook proof are configured server-side.",
            local_checks.get("telegram_live_identity"),
            "Load bot identity into the target runtime and read back /api/telegram/status?live=1.",
        ),
        _check_gate(
            "storage_upload_readback",
            "A public-safe threat bundle has live 0G Storage upload and readback proof.",
            local_checks.get("storage_upload_readback"),
            "Run a budgeted SDK upload/readback of the reviewed bundle before claiming storage production.",
        ),
        _check_gate(
            "private_compute_paid_smoke",
            "0G Private Computer paid smoke has executed under a budget gate.",
            local_checks.get("private_compute_paid_smoke"),
            "Use a server-side app key and a prompt-minimized smoke after budget caps are fixed.",
        ),
        _check_gate(
            "x402_settlement_path",
            "x402 paid route has a settlement readback path and caps.",
            local_checks.get("x402_settlement_path"),
            "Keep the dry-run 402 route, then add testnet/live settlement only after caps and refunds.",
        ),
        _gate(
            "clean_revision_for_app_deploy",
            "App deploy happens from a reviewed clean revision, not a large dirty worktree.",
            "review",
            {
                "apiInspectsGit": False,
                "knownRisk": "local development often has uncommitted WIP during autonomous runs",
                "requiredOperatorCheck": "git status --short && pytest && docker smoke",
            },
            "Create a review branch or commit, run tests, then deploy Cloud Run/Render from that revision.",
        ),
    ]


def _check_gate(
    gate_id: str,
    summary: str,
    check: dict[str, Any] | None,
    next_step: str,
) -> dict[str, Any]:
    if not check:
        return _gate(
            gate_id,
            summary,
            "review",
            {"checkPresent": False},
            next_step,
        )
    return _gate(
        gate_id,
        summary,
        "ok" if check.get("status") == "ok" else "review",
        {
            "checkPresent": True,
            "checkStatus": check.get("status"),
            "detail": check.get("detail") or {},
        },
        next_step,
    )


def _probe_gate_status(probe: dict[str, Any] | None, live: bool, *, truth_key: str) -> str:
    if not live:
        return "unknown"
    if not probe or probe.get("ok") is not True:
        return "review"
    return "ok" if probe.get(truth_key) is True else "review"


def _gate(
    gate_id: str,
    summary: str,
    status: str,
    detail: dict[str, Any],
    next_step: str,
) -> dict[str, Any]:
    return {
        "id": gate_id,
        "status": status,
        "summary": summary,
        "detail": detail,
        "nextStep": next_step,
    }


def _status_from_gates(gates: list[dict[str, Any]]) -> str:
    statuses = {gate["status"] for gate in gates}
    if "review" in statuses:
        return "promotion_review"
    if "unknown" in statuses:
        return "preview_ready_live_probe_pending"
    return "promotion_ready"


def _next_actions(gates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    review_gates = [gate for gate in gates if gate["status"] == "review"]
    if not review_gates:
        return [
            {
                "rank": 1,
                "id": "run_live_probe_and_preview_deploy",
                "action": "Run /api/deployment/readiness?live=1, then promote from a clean revision.",
            }
        ]
    return [
        {
            "rank": index + 1,
            "id": gate["id"],
            "action": gate["nextStep"],
        }
        for index, gate in enumerate(review_gates[:5])
    ]


def _commands() -> list[dict[str, Any]]:
    return [
        {
            "id": "local_tests",
            "command": ".venv/bin/python -m pytest",
            "safeNow": True,
            "purpose": "full local regression pass before any promotion",
        },
        {
            "id": "local_browser_smoke",
            "command": ".venv/bin/python scripts/browser_smoke.py --url http://127.0.0.1:8109",
            "safeNow": True,
            "purpose": "verify the dashboard route and packaged assets",
        },
        {
            "id": "github_pages_redeploy_current_main",
            "command": "gh workflow run pages.yml --repo arigatoexpress/0guard --ref main",
            "safeNow": True,
            "purpose": "republish already-committed public proof docs without deploying local WIP",
        },
        {
            "id": "local_docker_smoke",
            "command": "docker build -t 0guard:local . && docker run --rm -p 8110:8109 0guard:local",
            "safeNow": True,
            "purpose": "container smoke before Render or Cloud Run promotion",
        },
        {
            "id": "cloud_run_deploy_after_clean_revision",
            "command": (
                "gcloud run deploy guard0-miniapp --source . --region us-central1 "
                "--project sapphire-479610 --allow-unauthenticated"
            ),
            "safeNow": False,
            "blockedBy": ["clean_revision_required", "secret_env_review_required"],
            "purpose": "host the current Flask/Mini App runtime after review",
        },
        {
            "id": "mainnet_contract_or_receipt_write",
            "command": "python3 scripts/deploy_0g.py --network mainnet",
            "safeNow": False,
            "blockedBy": ["mainnet_money_movement", "fresh_operator_approval_required"],
            "purpose": "mainnet spend path; never invoked by the workbench",
        },
    ]


def _checks_by_id(readiness: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(check.get("id")): check
        for check in readiness.get("checks", [])
        if isinstance(check, dict) and check.get("id")
    }


def _local_readiness_summary(readiness: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": readiness.get("schema"),
        "status": readiness.get("status"),
        "ok": readiness.get("ok"),
        "reviewCount": readiness.get("reviewCount"),
        "hardGates": readiness.get("hardGates") or [],
        "generatedAt": readiness.get("generatedAt"),
    }


def _probe_summary(probe: dict[str, Any] | None) -> dict[str, Any]:
    if not probe:
        return {"checked": False, "ok": None, "reason": "probe_missing"}
    json_payload = probe.get("json") if isinstance(probe.get("json"), dict) else {}
    return {
        "url": probe.get("url"),
        "checked": probe.get("checked"),
        "ok": probe.get("ok"),
        "statusCode": probe.get("statusCode"),
        "schema": json_payload.get("schema"),
        "status": json_payload.get("status"),
        "hardGatesPresent": isinstance(json_payload.get("hardGates"), list),
        "proofReady": probe.get("proofReady"),
        "schemaCurrent": probe.get("schemaCurrent"),
        "safetyLocksPresent": probe.get("safetyLocksPresent"),
        "error": probe.get("error"),
    }


def _safety(*, live: bool) -> dict[str, bool]:
    return {
        "readOnly": True,
        "networkCalls": live,
        "liveHttpReadbackOnly": live,
        "privateKeysRead": False,
        "privateKeysReturned": False,
        "secretDisplayEnabled": False,
        "telegramSendsEnabled": False,
        "socialPostingEnabled": False,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "paymentSettlementEnabled": False,
        "mainnetWritesEnabled": False,
        "moneyMovementEnabled": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
