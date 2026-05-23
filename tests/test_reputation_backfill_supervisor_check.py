"""Tests for reputation backfill freshness supervision."""

import json
import importlib.util
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "reputation_backfill_supervisor_check.py"
SPEC = importlib.util.spec_from_file_location("reputation_backfill_supervisor_check", SCRIPT_PATH)
assert SPEC and SPEC.loader
supervisor_check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(supervisor_check)
validate_supervisor_inputs = supervisor_check.validate_supervisor_inputs


def test_reputation_backfill_supervisor_check_passes_for_fresh_derived_artifacts(tmp_path):
    latest = tmp_path / "latest.json"
    latest.write_text(
        json.dumps(
            {
                "schema": "0guard.reputation_backfill_run.v1",
                "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                "status": "ok",
                "fetch": {
                    "status": "ok",
                    "parsedDomainCount": 2,
                    "sampledEvidenceCount": 1,
                    "feedHash": "feedhash",
                    "ttlSeconds": 86400,
                },
                "derivedEvidence": [{"evidenceHash": "evidencehash"}],
                "snapshotReceipt": {"hash": "snapshothash"},
                "runReceipt": {"hash": "runhash"},
                "safety": {
                    "rawPayloadsReturned": False,
                    "rawDomainsReturned": False,
                    "writeLocalArtifact": True,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )
    worker_output = tmp_path / "worker.json"
    worker_output.write_text(
        json.dumps(
            {
                "schema": "0guard.reputation_backfill_run.v1",
                "status": "ok",
                "fetch": {"status": "ok", "parsedDomainCount": 3},
                "derivedEvidenceCount": 1,
                "rightsPolicy": {"rawPayloadResaleAllowed": False},
                "safety": {
                    "rawPayloadsReturned": False,
                    "rawDomainsReturned": False,
                    "writeLocalArtifact": False,
                },
                "persistence": {"written": False},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = validate_supervisor_inputs(latest_path=latest, worker_output_path=worker_output)

    assert result["schema"] == "0guard.reputation_backfill_supervisor_check.v1"
    assert result["ok"] is True
    assert result["failures"] == []
    assert result["latest"]["freshWithinTtl"] is True
    assert result["workerSmoke"]["writeLocalArtifact"] is False
    assert result["safety"]["telegramSendsEnabled"] is False


def test_reputation_backfill_supervisor_check_fails_closed_for_stale_artifact(tmp_path):
    latest = tmp_path / "latest.json"
    latest.write_text(
        json.dumps(
            {
                "schema": "0guard.reputation_backfill_run.v1",
                "generatedAt": "2020-01-01T00:00:00+00:00",
                "status": "ok",
                "fetch": {"status": "ok", "parsedDomainCount": 2, "ttlSeconds": 1},
                "derivedEvidence": [{"evidenceHash": "evidencehash"}],
                "snapshotReceipt": {"hash": "snapshothash"},
                "runReceipt": {"hash": "runhash"},
                "safety": {"rawPayloadsReturned": False, "rawDomainsReturned": False},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    result = validate_supervisor_inputs(latest_path=latest)

    assert result["ok"] is False
    assert "latest_artifact_stale" in result["failures"]
