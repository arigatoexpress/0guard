"""Rights-aware model eval/backfill artifacts for ZeroGuard."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guard0.crypto_hack_guard import check_crypto_hack_signatures
from guard0.incident_data import (
    dataset_fingerprint,
    incident_to_detection_payload,
    load_incident_dataset,
    validate_incident_dataset,
)
from guard0.policy import evaluate_intent

INCIDENT_EVAL_SET_SCHEMA = "0guard.incident_detector_eval_set.v1"
INCIDENT_EVAL_CASE_SCHEMA = "0guard.incident_detector_eval_case.v1"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INCIDENT_EVAL_PATH = REPO_ROOT / "data" / "evals" / "incident_detector_eval.v1.jsonl"


def build_incident_detector_eval_set(*, limit: int | None = None) -> dict[str, Any]:
    """Build deterministic eval rows from the curated incident corpus."""

    dataset = load_incident_dataset()
    validation = validate_incident_dataset(dataset)
    incidents = list(dataset.get("incidents") or [])
    if limit is not None:
        incidents = incidents[:limit]

    rows = [_incident_eval_case(incident, dataset) for incident in incidents]
    return {
        "schema": INCIDENT_EVAL_SET_SCHEMA,
        "generatedAt": _now(),
        "mode": "deterministic_eval_preview_no_training_run",
        "datasetFingerprint": dataset_fingerprint(dataset),
        "sourceDataset": "data/april_2026_incidents.json",
        "caseCount": len(rows),
        "validation": validation.to_dict(),
        "defaultOutputPath": _relative_repo_path(DEFAULT_INCIDENT_EVAL_PATH),
        "rows": rows,
        "qualityGates": [
            "Each row must include a deterministic expected verdict.",
            "Each row must carry source refs, rights policy, and rawPayloadResaleAllowed=false.",
            "Model output is evaluated for faithful explanation only, not policy authority.",
        ],
        "safety": _safety(),
    }


def write_incident_detector_eval_jsonl(path: str | Path = DEFAULT_INCIDENT_EVAL_PATH) -> dict[str, Any]:
    """Write the deterministic incident eval set as JSONL and return a manifest."""

    target = Path(path)
    payload = build_incident_detector_eval_set()
    rows = payload["rows"]
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
            handle.write("\n")
    return {
        "schema": "0guard.incident_detector_eval_export.v1",
        "generatedAt": _now(),
        "path": _relative_repo_path(target),
        "caseCount": len(rows),
        "datasetFingerprint": payload["datasetFingerprint"],
        "safety": payload["safety"],
    }


def _incident_eval_case(incident: dict[str, Any], dataset: dict[str, Any]) -> dict[str, Any]:
    intent = incident_to_detection_payload(incident)
    hack = check_crypto_hack_signatures(intent).to_dict()
    policy = evaluate_intent(intent, agent_id=f"incident-{incident.get('id')}").to_dict()
    source_refs = _source_refs(incident)
    return {
        "schema": INCIDENT_EVAL_CASE_SCHEMA,
        "caseId": f"april-2026-incident-{incident.get('id')}",
        "split": _stable_split(int(incident.get("id") or 0)),
        "datasetFingerprint": dataset_fingerprint(dataset),
        "input": {
            "task": "Explain the deterministic ZeroGuard verdict from the packet. Do not change the verdict.",
            "intent": intent,
            "incidentContext": {
                "protocol": incident.get("protocol"),
                "date": incident.get("date"),
                "chain": incident.get("chain"),
                "attackVector": incident.get("attack_vector"),
                "lossUsd": incident.get("loss_usd"),
                "attribution": incident.get("attribution"),
                "lesson": incident.get("lesson"),
            },
        },
        "expected": {
            "decision": policy["decision"],
            "severity": policy["severity"],
            "receiptHash": policy["receipt_hash"],
            "blockers": policy["blockers"],
            "warnings": policy["warnings"],
            "signaturesMatched": hack["signatures_matched"],
            "iocsHit": hack["iocs_hit"],
        },
        "sourceRefs": source_refs,
        "rights": {
            "rightsClass": "public_source_derived_defensive_eval",
            "rawPayloadResaleAllowed": False,
            "sourceUrlCount": len([ref for ref in source_refs if ref.get("url")]),
            "paidVendorPayloadIncluded": False,
        },
        "modelUse": {
            "allowed": ["summarize", "dedupe", "explain", "score_faithfulness"],
            "notAllowed": [
                "approve_transactions",
                "override_policy_verdict",
                "move_funds",
                "send_telegram",
                "train_on_raw_paid_payloads",
            ],
        },
    }


def _source_refs(incident: dict[str, Any]) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for url in incident.get("source_urls") or []:
        refs.append({"type": "source_url", "url": url})
    for evidence in incident.get("derived_source_evidence") or []:
        if not isinstance(evidence, dict):
            continue
        refs.append(
            {
                "type": "derived_source_evidence",
                "sourceId": evidence.get("source_id"),
                "url": evidence.get("source_url"),
                "recordHash": evidence.get("record_hash"),
                "rightsEnvelope": evidence.get("rights_envelope"),
                "reviewStatus": evidence.get("review_status"),
            }
        )
    return refs


def _stable_split(incident_id: int) -> str:
    if incident_id % 5 == 0:
        return "test"
    if incident_id % 3 == 0:
        return "validation"
    return "eval"


def _relative_repo_path(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _safety() -> dict[str, bool]:
    return {
        "readOnly": True,
        "liveNetworkCalls": False,
        "trainingRunStarted": False,
        "paidInferenceEnabled": False,
        "rawPayloadsReturned": False,
        "privateKeysReturned": False,
        "telegramSendsEnabled": False,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "moneyMovementEnabled": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
