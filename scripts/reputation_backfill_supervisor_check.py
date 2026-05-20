#!/usr/bin/env python3
"""Fail-closed freshness check for derived-only reputation backfills."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guard0.reputation_backfill import build_reputation_backfill_status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--latest",
        default="data/backfill/reputation_features/phishdestroy/latest.json",
        help="Latest derived-only backfill artifact to validate.",
    )
    parser.add_argument(
        "--worker-output",
        default="",
        help="Optional JSON output from a no-write live worker smoke run.",
    )
    args = parser.parse_args()

    summary = validate_supervisor_inputs(
        latest_path=Path(args.latest),
        worker_output_path=Path(args.worker_output) if args.worker_output else None,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["ok"] else 1


def validate_supervisor_inputs(
    *,
    latest_path: Path,
    worker_output_path: Path | None = None,
) -> dict[str, Any]:
    status = build_reputation_backfill_status(latest_path)
    failures: list[str] = []
    if status.get("status") != "ready":
        failures.append("latest_status_not_ready")
    if status.get("latestRunExists") is not True:
        failures.append("latest_artifact_missing")
    if _fresh_within_ttl(status) is not True:
        failures.append("latest_artifact_stale")
    if int(status.get("derivedEvidenceCount") or 0) <= 0:
        failures.append("latest_missing_derived_evidence")
    if int(status.get("parsedDomainCount") or 0) <= 0:
        failures.append("latest_missing_parsed_domains")
    if status.get("rawPayloadsReturned") is not False:
        failures.append("latest_raw_payloads_flag_not_false")
    if status.get("rawDomainsReturned") is not False:
        failures.append("latest_raw_domains_flag_not_false")

    worker = _load_json(worker_output_path) if worker_output_path else None
    if worker_output_path and worker is None:
        failures.append("worker_output_unreadable")
    if isinstance(worker, dict):
        worker_failures = _worker_failures(worker)
        failures.extend(worker_failures)

    return {
        "schema": "0guard.reputation_backfill_supervisor_check.v1",
        "generatedAt": _now(),
        "ok": not failures,
        "failures": failures,
        "latest": {
            "path": str(latest_path),
            "status": status.get("status"),
            "latestAgeSeconds": status.get("latestAgeSeconds"),
            "ttlSeconds": status.get("ttlSeconds"),
            "freshWithinTtl": _fresh_within_ttl(status),
            "derivedEvidenceCount": status.get("derivedEvidenceCount"),
            "parsedDomainCount": status.get("parsedDomainCount"),
            "rawPayloadsReturned": status.get("rawPayloadsReturned"),
            "rawDomainsReturned": status.get("rawDomainsReturned"),
        },
        "workerSmoke": _worker_summary(worker),
        "safety": {
            "rawPayloadsReturned": False,
            "rawDomainsReturned": False,
            "transactionSigningEnabled": False,
            "transactionBroadcastingEnabled": False,
            "telegramSendsEnabled": False,
            "paymentSettlementEnabled": False,
            "writeLocalArtifact": False,
        },
    }


def _worker_failures(worker: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    fetch = worker.get("fetch") if isinstance(worker.get("fetch"), dict) else {}
    safety = worker.get("safety") if isinstance(worker.get("safety"), dict) else {}
    rights = worker.get("rightsPolicy") if isinstance(worker.get("rightsPolicy"), dict) else {}
    persistence = worker.get("persistence") if isinstance(worker.get("persistence"), dict) else {}
    if worker.get("schema") != "0guard.reputation_backfill_run.v1":
        failures.append("worker_schema_mismatch")
    if worker.get("status") != "ok":
        failures.append("worker_status_not_ok")
    if fetch.get("status") != "ok":
        failures.append("worker_fetch_not_ok")
    if int(fetch.get("parsedDomainCount") or 0) <= 0:
        failures.append("worker_missing_parsed_domains")
    if int(worker.get("derivedEvidenceCount") or 0) <= 0:
        failures.append("worker_missing_derived_evidence")
    if safety.get("rawPayloadsReturned") is not False:
        failures.append("worker_raw_payloads_flag_not_false")
    if safety.get("rawDomainsReturned") is not False:
        failures.append("worker_raw_domains_flag_not_false")
    if safety.get("writeLocalArtifact") is not False:
        failures.append("worker_write_local_artifact_enabled")
    if rights.get("rawPayloadResaleAllowed") is not False:
        failures.append("worker_raw_payload_resale_allowed")
    if persistence.get("written") is not False:
        failures.append("worker_persistence_written")
    return failures


def _worker_summary(worker: Any) -> dict[str, Any]:
    if not isinstance(worker, dict):
        return {"provided": False}
    fetch = worker.get("fetch") if isinstance(worker.get("fetch"), dict) else {}
    safety = worker.get("safety") if isinstance(worker.get("safety"), dict) else {}
    return {
        "provided": True,
        "status": worker.get("status"),
        "fetchStatus": fetch.get("status"),
        "parsedDomainCount": fetch.get("parsedDomainCount"),
        "derivedEvidenceCount": worker.get("derivedEvidenceCount"),
        "rawPayloadsReturned": safety.get("rawPayloadsReturned"),
        "rawDomainsReturned": safety.get("rawDomainsReturned"),
        "writeLocalArtifact": safety.get("writeLocalArtifact"),
    }


def _load_json(path: Path | None) -> Any:
    if path is None:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _fresh_within_ttl(status: dict[str, Any]) -> bool | None:
    age = status.get("latestAgeSeconds")
    ttl = status.get("ttlSeconds")
    if age is None or ttl is None:
        return None
    try:
        return int(age) <= int(ttl)
    except (TypeError, ValueError):
        return None


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


if __name__ == "__main__":
    sys.exit(main())
