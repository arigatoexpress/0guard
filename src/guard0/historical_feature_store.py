"""Seed historical feature-store artifacts for ZeroGuard.

This module turns the existing curated incident eval rows and the first
derived-only reputation backfill into a queryable seed feature store. It does
not fetch live feeds, store raw upstream payloads, train a model, settle x402,
upload to 0G Storage, or expose private operational data.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guard0.reputation_backfill import (
    DEFAULT_REPUTATION_BACKFILL_PATH,
    build_reputation_backfill_status,
)
from guard0.training_data import build_incident_detector_eval_set

HISTORICAL_FEATURE_STORE_SCHEMA = "0guard.historical_feature_store.v1"
HISTORICAL_FEATURE_ROW_SCHEMA = "0guard.historical_feature_row.v1"
HISTORICAL_FEATURE_EXPORT_SCHEMA = "0guard.historical_feature_store_export.v1"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_HISTORICAL_FEATURE_STORE_PATH = (
    REPO_ROOT / "data" / "backfill" / "historical_feature_store" / "seed.v1.jsonl"
)


def build_historical_feature_store(
    *,
    limit: int | None = None,
    include_reputation: bool = True,
) -> dict[str, Any]:
    """Build a public-safe seed feature-store payload from local artifacts."""

    if limit is not None and (limit < 1 or limit > 200):
        raise ValueError("limit must be between 1 and 200")

    incident_eval = build_incident_detector_eval_set(limit=limit)
    rows = [_incident_feature_row(row) for row in incident_eval["rows"]]

    reputation_status = build_reputation_backfill_status(DEFAULT_REPUTATION_BACKFILL_PATH)
    if include_reputation:
        reputation_row = _reputation_feature_row(reputation_status)
        if reputation_row:
            rows.append(reputation_row)

    counts_by_type = Counter(str(row.get("featureType") or "unknown") for row in rows)
    source_runs = _source_runs(
        incident_eval=incident_eval,
        reputation_status=reputation_status,
        include_reputation=include_reputation,
    )
    return {
        "schema": HISTORICAL_FEATURE_STORE_SCHEMA,
        "generatedAt": _now(),
        "mode": "seed_feature_store_from_local_artifacts_no_network",
        "featureCount": len(rows),
        "featureCountsByType": dict(sorted(counts_by_type.items())),
        "sourceRuns": source_runs,
        "storage": {
            "defaultJsonlPath": _relative_repo_path(DEFAULT_HISTORICAL_FEATURE_STORE_PATH),
            "format": "immutable_run_jsonl_with_latest_alias",
            "scalePath": "DuckDB or SQLite query index after wider 2020-present backfill",
            "zeroGStoragePath": "public-safe derived bundle after live upload/readback proof",
        },
        "queryCapabilities": [
            "featureType",
            "observedAt",
            "chain",
            "attackVector",
            "sourceId",
            "expectedDecision",
            "receiptHash",
        ],
        "qualityGates": [
            "Every row carries a row hash, source refs, and rights metadata.",
            "Raw feed bodies, raw domains, payment headers, private keys, and chat bodies are excluded.",
            "Model use is explanation/eval only; deterministic policy remains authoritative.",
        ],
        "rightsPolicy": _rights_policy(),
        "featureStoreReceipt": {
            "hash": _feature_store_hash(rows=rows, source_runs=source_runs),
            "algorithm": "sha256_canonical_json",
            "zeroGStorageReady": True,
            "liveUploadPerformed": False,
            "x402SettlementEnabled": False,
        },
        "featureRows": rows,
        "safety": _safety(),
    }


def write_historical_feature_store_jsonl(
    path: str | Path = DEFAULT_HISTORICAL_FEATURE_STORE_PATH,
    *,
    limit: int | None = None,
    include_reputation: bool = True,
) -> dict[str, Any]:
    """Write seed feature-store rows as JSONL and return an export manifest."""

    target = Path(path)
    payload = build_historical_feature_store(
        limit=limit,
        include_reputation=include_reputation,
    )
    rows = payload["featureRows"]
    target.parent.mkdir(parents=True, exist_ok=True)
    run_path = _immutable_run_path(target, payload)
    run_path.parent.mkdir(parents=True, exist_ok=True)

    with run_path.open("x", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
            handle.write("\n")

    target_tmp = target.with_suffix(f"{target.suffix}.tmp")
    target_tmp.write_text(run_path.read_text(encoding="utf-8"), encoding="utf-8")
    target_tmp.replace(target)

    file_hash = _hash_bytes(run_path.read_bytes())
    return {
        "schema": HISTORICAL_FEATURE_EXPORT_SCHEMA,
        "generatedAt": _now(),
        "path": _relative_repo_path(target),
        "latestAliasPath": _relative_repo_path(target),
        "immutableRunPath": _relative_repo_path(run_path),
        "latestAliasUpdated": True,
        "featureCount": len(rows),
        "featureCountsByType": payload["featureCountsByType"],
        "featureStoreReceipt": payload["featureStoreReceipt"],
        "fileHash": file_hash,
        "rightsPolicy": payload["rightsPolicy"],
        "safety": payload["safety"],
    }


def _incident_feature_row(row: dict[str, Any]) -> dict[str, Any]:
    incident_context = ((row.get("input") or {}).get("incidentContext") or {})
    expected = row.get("expected") or {}
    rights = row.get("rights") or {}
    source_refs = row.get("sourceRefs") if isinstance(row.get("sourceRefs"), list) else []
    case_id = str(row.get("caseId") or "unknown")
    receipt_hash = str(expected.get("receiptHash") or "")
    payload = {
        "schema": HISTORICAL_FEATURE_ROW_SCHEMA,
        "featureId": f"incident_detector_trace:{case_id}:{receipt_hash[:16]}",
        "featureType": "incident_detector_trace",
        "observedAt": incident_context.get("date") or "",
        "entity": {
            "caseId": case_id,
            "chain": incident_context.get("chain") or "unknown",
            "protocol": incident_context.get("protocol") or "unknown",
            "attackVector": incident_context.get("attackVector") or "unknown",
        },
        "features": {
            "expectedDecision": expected.get("decision"),
            "severity": expected.get("severity"),
            "split": row.get("split"),
            "lossUsdBucket": _loss_bucket(incident_context.get("lossUsd")),
            "blockerCount": len(expected.get("blockers") or []),
            "warningCount": len(expected.get("warnings") or []),
            "signatureCount": len(expected.get("signaturesMatched") or []),
            "iocCount": len(expected.get("iocsHit") or []),
            "sourceUrlCount": rights.get("sourceUrlCount", 0),
        },
        "labels": {
            "decision": expected.get("decision"),
            "attackVector": incident_context.get("attackVector"),
            "chain": incident_context.get("chain"),
            "attribution": incident_context.get("attribution"),
        },
        "sourceRefs": source_refs,
        "rights": {
            "rightsClass": rights.get("rightsClass", "public_source_derived_defensive_eval"),
            "rawPayloadResaleAllowed": False,
            "paidVendorPayloadIncluded": bool(rights.get("paidVendorPayloadIncluded", False)),
            "sourceUrlCount": rights.get("sourceUrlCount", 0),
        },
        "receipts": {
            "policyReceiptHash": receipt_hash,
            "datasetFingerprint": row.get("datasetFingerprint"),
        },
        "modelUse": {
            "allowed": ["summarize", "dedupe", "explain", "score_faithfulness"],
            "notAllowed": [
                "approve_transactions",
                "override_policy_verdict",
                "move_funds",
                "store_private_wallet_data",
            ],
        },
        "safety": _row_safety(),
    }
    payload["rowHash"] = _hash_json(payload)
    return payload


def _reputation_feature_row(status: dict[str, Any]) -> dict[str, Any] | None:
    if not status.get("latestRunExists"):
        return None
    source_id = str(status.get("sourceId") or "phishdestroy_destroylist")
    feed_hash = str(status.get("feedHash") or "")
    generated_at = str(status.get("latestGeneratedAt") or status.get("generatedAt") or "")
    rights = status.get("rightsPolicy") if isinstance(status.get("rightsPolicy"), dict) else {}
    payload = {
        "schema": HISTORICAL_FEATURE_ROW_SCHEMA,
        "featureId": f"reputation_feed_summary:{source_id}:{feed_hash[:16] or 'local'}",
        "featureType": "reputation_feed_snapshot_summary",
        "observedAt": generated_at,
        "entity": {
            "sourceId": source_id,
            "sourceName": status.get("sourceName") or "PhishDestroy active-domain feed",
            "subjectType": "domain_reputation_feed",
        },
        "features": {
            "status": status.get("status"),
            "parsedDomainCount": int(status.get("parsedDomainCount") or 0),
            "derivedEvidenceCount": int(status.get("derivedEvidenceCount") or 0),
            "sampledEvidenceCount": int(status.get("sampledEvidenceCount") or 0),
            "ttlSeconds": int(status.get("ttlSeconds") or 0),
            "feedHash": feed_hash,
            "runHash": status.get("runHash") or "",
            "snapshotHash": status.get("snapshotHash") or "",
            "rawDomainsReturned": False,
        },
        "labels": {
            "sourceId": source_id,
            "decisionHint": "deny_when_subject_matches_derived_evidence",
        },
        "sourceRefs": [
            {
                "type": "source_home",
                "sourceId": source_id,
                "url": status.get("sourceLink") or "",
            },
            {
                "type": "feed_hash",
                "sourceId": source_id,
                "url": status.get("feedLink") or "",
                "hash": feed_hash,
            },
        ],
        "rights": {
            "rightsClass": "public_source_derived_reputation_features",
            "rawPayloadResaleAllowed": bool(rights.get("rawPayloadResaleAllowed", False)),
            "rawPayloadsReturned": bool(rights.get("rawPayloadsReturned", False)),
            "rawDomainsReturned": bool(rights.get("rawDomainsReturned", False)),
            "sourceLinksOrHashesOnly": True,
        },
        "receipts": {
            "runHash": status.get("runHash") or "",
            "snapshotHash": status.get("snapshotHash") or "",
            "fileHash": status.get("fileHash") or "",
        },
        "modelUse": {
            "allowed": ["freshness_summary", "source_conflict_explanation", "dedupe"],
            "notAllowed": ["return_raw_domains", "mirror_feed", "sell_raw_payloads"],
        },
        "safety": _row_safety(),
    }
    payload["rowHash"] = _hash_json(payload)
    return payload


def _source_runs(
    *,
    incident_eval: dict[str, Any],
    reputation_status: dict[str, Any],
    include_reputation: bool,
) -> list[dict[str, Any]]:
    runs = [
        {
            "id": "incident_detector_eval_set",
            "schema": incident_eval.get("schema"),
            "sourceDataset": incident_eval.get("sourceDataset"),
            "datasetFingerprint": incident_eval.get("datasetFingerprint"),
            "caseCount": incident_eval.get("caseCount"),
            "defaultOutputPath": incident_eval.get("defaultOutputPath"),
            "rawPayloadsReturned": False,
        }
    ]
    if include_reputation:
        runs.append(
            {
                "id": "phishdestroy_reputation_backfill",
                "schema": reputation_status.get("latestSchema")
                or reputation_status.get("schema"),
                "status": reputation_status.get("status"),
                "path": reputation_status.get("path"),
                "latestRunExists": reputation_status.get("latestRunExists"),
                "derivedEvidenceCount": reputation_status.get("derivedEvidenceCount"),
                "parsedDomainCount": reputation_status.get("parsedDomainCount"),
                "feedHash": reputation_status.get("feedHash"),
                "rawPayloadsReturned": False,
                "rawDomainsReturned": False,
            }
        )
    return runs


def _feature_store_hash(*, rows: list[dict[str, Any]], source_runs: list[dict[str, Any]]) -> str:
    return _hash_json(
        {
            "schema": HISTORICAL_FEATURE_STORE_SCHEMA,
            "sourceRuns": source_runs,
            "rowHashes": [row.get("rowHash") for row in rows],
        }
    )


def _immutable_run_path(target: Path, payload: dict[str, Any]) -> Path:
    timestamp = str(payload.get("generatedAt") or _now()).replace("-", "").replace(":", "")
    timestamp = timestamp.replace("+0000", "Z").replace("+00:00", "Z")
    timestamp = "".join(char for char in timestamp if char.isalnum() or char in {"T", "Z"})
    receipt_hash = ((payload.get("featureStoreReceipt") or {}).get("hash") or "nohash")[:12]
    base = target.parent / "runs" / f"{timestamp}-{receipt_hash}.jsonl"
    if not base.exists():
        return base
    for index in range(1, 100):
        candidate = target.parent / "runs" / f"{timestamp}-{receipt_hash}-{index}.jsonl"
        if not candidate.exists():
            return candidate
    raise FileExistsError(f"could not allocate immutable feature-store run path for {target}")


def _loss_bucket(value: Any) -> str:
    try:
        loss = int(value or 0)
    except (TypeError, ValueError):
        return "unknown"
    if loss >= 100_000_000:
        return "100m_plus"
    if loss >= 10_000_000:
        return "10m_to_100m"
    if loss >= 1_000_000:
        return "1m_to_10m"
    if loss > 0:
        return "under_1m"
    return "none"


def _rights_policy() -> dict[str, bool | str]:
    return {
        "rawPayloadsReturned": False,
        "rawPayloadResaleAllowed": False,
        "rawDomainsReturned": False,
        "rawChatsStored": False,
        "paymentHeadersStored": False,
        "sourceLinksOrHashesOnly": True,
        "paidRouteEligible": "derived_rows_only_after_terms_and_x402_caps",
    }


def _row_safety() -> dict[str, bool]:
    return {
        "networkCalls": False,
        "rawPayloadsReturned": False,
        "privateKeysReturned": False,
        "paymentHeadersStored": False,
        "telegramSendsEnabled": False,
        "transactionSigningEnabled": False,
        "moneyMovementEnabled": False,
    }


def _safety() -> dict[str, bool]:
    return {
        **_row_safety(),
        "readOnly": True,
        "trainingRunStarted": False,
        "x402SettlementEnabled": False,
        "liveStorageUpload": False,
        "liveStorageGatewayReadback": False,
    }


def _relative_repo_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
