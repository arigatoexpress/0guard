"""Derived-only reputation backfill artifacts.

The live connector is intentionally separate from the persisted feature store.
This module promotes reviewed connector snapshots into local artifacts that can
be scheduled later without turning public or paid routes into raw feed mirrors.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guard0.reputation_connector_worker import (
    PHISHDESTROY_ACTIVE_DOMAINS_URL,
    PHISHDESTROY_PUBLIC_SOURCE_URL,
    PHISHDESTROY_SOURCE_ID,
    reputation_connector_snapshot,
)

REPUTATION_BACKFILL_RUN_SCHEMA = "0guard.reputation_backfill_run.v1"
REPUTATION_BACKFILL_STATUS_SCHEMA = "0guard.reputation_backfill_status.v1"
DEFAULT_REPUTATION_BACKFILL_PATH = Path(
    "data/backfill/reputation_features/phishdestroy/latest.json"
)


def run_phishdestroy_reputation_backfill(
    *,
    live: bool = False,
    limit: int = 5,
    subject_url: str = "",
    out_path: str | Path = DEFAULT_REPUTATION_BACKFILL_PATH,
    write: bool = True,
    snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build and optionally persist a PhishDestroy derived-feature backfill run."""

    if limit < 1 or limit > 50:
        raise ValueError("limit must be between 1 and 50")

    path = Path(out_path)
    connector_snapshot = snapshot or reputation_connector_snapshot(
        source_id=PHISHDESTROY_SOURCE_ID,
        live=live,
        limit=limit,
        subject_url=subject_url,
    )
    run = _build_run(
        connector_snapshot=connector_snapshot,
        live=live,
        limit=limit,
        subject_url=subject_url,
        out_path=path,
        write_requested=write,
    )
    if write:
        run["persistence"]["written"] = True
        _write_json(path, run)
        run["persistence"]["fileHash"] = _hash_bytes(path.read_bytes())
    return run


def build_reputation_backfill_status(
    path: str | Path = DEFAULT_REPUTATION_BACKFILL_PATH,
) -> dict[str, Any]:
    """Return the latest derived-feature backfill posture with no network calls."""

    latest_path = Path(path)
    base = {
        "schema": REPUTATION_BACKFILL_STATUS_SCHEMA,
        "generatedAt": _now(),
        "mode": "local_backfill_status_no_network_calls",
        "sourceId": PHISHDESTROY_SOURCE_ID,
        "sourceName": "PhishDestroy active-domain feed",
        "sourceLink": PHISHDESTROY_PUBLIC_SOURCE_URL,
        "feedLink": PHISHDESTROY_ACTIVE_DOMAINS_URL,
        "path": _display_path(latest_path),
        "latestRunExists": latest_path.exists(),
        "scheduleManifest": _schedule_manifest(latest_path),
        "rightsPolicy": _rights_policy(),
        "safety": _safety(live_connector_fetch=False, write_local_artifact=False),
    }
    if not latest_path.exists():
        return {
            **base,
            "status": "missing",
            "derivedEvidenceCount": 0,
            "parsedDomainCount": 0,
            "feedHash": "",
            "snapshotHash": "",
            "fileHash": "",
            "nextAction": "Run scripts/reputation_backfill_worker.py with --live after reviewing source terms and network posture.",
        }

    try:
        payload = json.loads(latest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            **base,
            "status": "unreadable",
            "error": f"{type(exc).__name__}: {exc}",
            "derivedEvidenceCount": 0,
            "parsedDomainCount": 0,
            "feedHash": "",
            "snapshotHash": "",
            "fileHash": "",
        }

    fetch = payload.get("fetch") if isinstance(payload.get("fetch"), dict) else {}
    receipt = payload.get("snapshotReceipt") if isinstance(payload.get("snapshotReceipt"), dict) else {}
    derived = payload.get("derivedEvidence") if isinstance(payload.get("derivedEvidence"), list) else []
    generated_at = str(payload.get("generatedAt") or "")
    return {
        **base,
        "status": _status_from_payload(payload),
        "latestSchema": payload.get("schema"),
        "latestGeneratedAt": generated_at,
        "latestAgeSeconds": _age_seconds(generated_at),
        "derivedEvidenceCount": len(derived),
        "parsedDomainCount": int(fetch.get("parsedDomainCount") or 0),
        "sampledEvidenceCount": int(fetch.get("sampledEvidenceCount") or len(derived)),
        "ttlSeconds": int(fetch.get("ttlSeconds") or 21600),
        "feedHash": fetch.get("feedHash") or "",
        "snapshotHash": receipt.get("hash") or "",
        "runHash": (payload.get("runReceipt") or {}).get("hash") or "",
        "fileHash": _hash_bytes(latest_path.read_bytes()),
        "liveConnectorFetch": bool((payload.get("safety") or {}).get("liveConnectorFetch")),
        "rawPayloadsReturned": False,
        "rawDomainsReturned": False,
        "nextAction": "Add a supervisor schedule after this latest derived-only run is stable and source terms remain acceptable.",
    }


def _build_run(
    *,
    connector_snapshot: dict[str, Any],
    live: bool,
    limit: int,
    subject_url: str,
    out_path: Path,
    write_requested: bool,
) -> dict[str, Any]:
    fetch = connector_snapshot.get("fetch") if isinstance(connector_snapshot.get("fetch"), dict) else {}
    derived = (
        connector_snapshot.get("derivedEvidence")
        if isinstance(connector_snapshot.get("derivedEvidence"), list)
        else []
    )
    receipt = (
        connector_snapshot.get("snapshotReceipt")
        if isinstance(connector_snapshot.get("snapshotReceipt"), dict)
        else {}
    )
    run = {
        "schema": REPUTATION_BACKFILL_RUN_SCHEMA,
        "generatedAt": _now(),
        "mode": "live_fetch_derived_only" if live else "dry_run_no_live_fetch",
        "status": _fetch_status(fetch),
        "sourceId": PHISHDESTROY_SOURCE_ID,
        "sourceName": "PhishDestroy active-domain feed",
        "sourceLink": PHISHDESTROY_PUBLIC_SOURCE_URL,
        "feedLink": PHISHDESTROY_ACTIVE_DOMAINS_URL,
        "input": {
            "live": live,
            "limit": limit,
            "subjectUrlProvided": bool(subject_url),
            "subjectRawReturned": False,
        },
        "fetch": {
            "status": _fetch_status(fetch),
            "httpStatus": fetch.get("httpStatus"),
            "latencyMs": fetch.get("latencyMs"),
            "contentType": fetch.get("contentType", ""),
            "contentLength": fetch.get("contentLength", 0),
            "etag": fetch.get("etag"),
            "lastModified": fetch.get("lastModified"),
            "feedHash": fetch.get("feedHash", ""),
            "parsedDomainCount": fetch.get("parsedDomainCount", 0),
            "sampledEvidenceCount": fetch.get("sampledEvidenceCount", len(derived)),
            "ttlSeconds": fetch.get("ttlSeconds", 21600),
        },
        "subject": connector_snapshot.get("subject") or {},
        "derivedEvidenceCount": len(derived),
        "derivedEvidence": derived,
        "reputationPreview": connector_snapshot.get("reputationPreview") or {},
        "snapshotReceipt": receipt,
        "scheduleManifest": _schedule_manifest(out_path),
        "rightsPolicy": _rights_policy(),
        "safety": _safety(live_connector_fetch=live, write_local_artifact=write_requested),
        "persistence": {
            "written": False,
            "path": _display_path(out_path),
            "fileHash": "",
        },
    }
    run["runReceipt"] = {
        "hash": _hash_json(
            {
                "schema": run["schema"],
                "generatedAt": run["generatedAt"],
                "sourceId": run["sourceId"],
                "fetch": run["fetch"],
                "derivedEvidence": run["derivedEvidence"],
                "snapshotReceipt": run["snapshotReceipt"],
                "rightsPolicy": run["rightsPolicy"],
            }
        ),
        "algorithm": "sha256_canonical_json",
        "zeroGChainReady": True,
        "zeroGStorageReady": True,
        "liveAnchorPerformed": False,
        "liveUploadPerformed": False,
    }
    return run


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f"{path.name}.tmp")
    tmp_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    tmp_path.replace(path)


def _schedule_manifest(out_path: Path) -> dict[str, Any]:
    return {
        "supervisorInstalled": False,
        "recommendedIntervalSeconds": 21600,
        "ttlSeconds": 21600,
        "command": (
            "PYTHONPATH=src .venv/bin/python scripts/reputation_backfill_worker.py "
            f"--source {PHISHDESTROY_SOURCE_ID} --live --out {_display_path(out_path)}"
        ),
        "writesRawPayloads": False,
        "requiresSecret": False,
    }


def _rights_policy() -> dict[str, Any]:
    return {
        "rawPayloadsReturned": False,
        "rawPayloadResaleAllowed": False,
        "rawDomainsReturned": False,
        "sourceLinksOrHashesOnly": True,
        "derivedEvidenceOnly": True,
        "paidRouteEligible": True,
        "paidRouteOutput": "derived labels, counts, hashes, freshness, and source links only",
    }


def _safety(*, live_connector_fetch: bool, write_local_artifact: bool) -> dict[str, bool]:
    return {
        "readOnlyNetwork": True,
        "networkCalls": live_connector_fetch,
        "liveConnectorFetch": live_connector_fetch,
        "writeLocalArtifact": write_local_artifact,
        "rawPayloadsReturned": False,
        "rawDomainsReturned": False,
        "privateKeyRequired": False,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "telegramSendsEnabled": False,
        "socialPostingEnabled": False,
        "paymentSettlementEnabled": False,
        "bridgingEnabled": False,
        "swappingEnabled": False,
    }


def _status_from_payload(payload: dict[str, Any]) -> str:
    if payload.get("schema") != REPUTATION_BACKFILL_RUN_SCHEMA:
        return "schema_mismatch"
    status = str(payload.get("status") or "")
    if status == "ok":
        return "ready"
    return status or "unknown"


def _fetch_status(fetch: dict[str, Any]) -> str:
    return str(fetch.get("status") or "unknown")


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(Path.cwd()))
    except ValueError:
        return str(path)


def _age_seconds(value: str) -> int | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0, int((_now_dt() - parsed).total_seconds()))


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _now() -> str:
    return _now_dt().replace(microsecond=0).isoformat()


def _now_dt() -> datetime:
    return datetime.now(timezone.utc)
