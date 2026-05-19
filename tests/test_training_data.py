"""Tests for generated model eval data."""

import json
from pathlib import Path

from guard0.training_data import (
    build_incident_detector_eval_set,
    write_incident_detector_eval_jsonl,
)


def test_incident_detector_eval_set_is_deterministic_and_rights_aware():
    payload = build_incident_detector_eval_set(limit=3)

    assert payload["schema"] == "0guard.incident_detector_eval_set.v1"
    assert payload["mode"] == "deterministic_eval_preview_no_training_run"
    assert payload["caseCount"] == 3
    assert payload["safety"]["trainingRunStarted"] is False
    assert payload["safety"]["moneyMovementEnabled"] is False

    first = payload["rows"][0]
    assert first["schema"] == "0guard.incident_detector_eval_case.v1"
    assert first["caseId"] == "april-2026-incident-1"
    assert first["expected"]["decision"] in {"deny", "review", "allow"}
    assert first["expected"]["receiptHash"]
    assert first["rights"]["rawPayloadResaleAllowed"] is False
    assert "override_policy_verdict" in first["modelUse"]["notAllowed"]
    assert first["sourceRefs"]


def test_incident_detector_eval_jsonl_export(tmp_path):
    out_path = tmp_path / "incident_eval.jsonl"
    manifest = write_incident_detector_eval_jsonl(out_path)

    assert manifest["schema"] == "0guard.incident_detector_eval_export.v1"
    assert manifest["caseCount"] == 28
    assert manifest["safety"]["paidInferenceEnabled"] is False

    rows = [json.loads(line) for line in Path(out_path).read_text().splitlines()]
    assert len(rows) == 28
    assert rows[0]["caseId"] == "april-2026-incident-1"
    assert rows[0]["rights"]["paidVendorPayloadIncluded"] is False
