"""Tests for the seed historical feature store."""

import json
from pathlib import Path

from guard0.historical_feature_store import (
    build_historical_feature_store,
    write_historical_feature_store_jsonl,
)


def test_historical_feature_store_composes_incident_and_reputation_rows():
    payload = build_historical_feature_store(limit=3)

    assert payload["schema"] == "0guard.historical_feature_store.v1"
    assert payload["mode"] == "seed_feature_store_from_local_artifacts_no_network"
    assert payload["featureCount"] >= 4
    assert payload["featureCountsByType"]["incident_detector_trace"] == 3
    assert payload["featureCountsByType"]["reputation_feed_snapshot_summary"] == 1
    assert payload["featureStoreReceipt"]["hash"]
    assert payload["rightsPolicy"]["rawPayloadResaleAllowed"] is False
    assert payload["rightsPolicy"]["rawPayloadsReturned"] is False
    assert payload["safety"]["networkCalls"] is False
    assert payload["safety"]["x402SettlementEnabled"] is False

    first = payload["featureRows"][0]
    assert first["schema"] == "0guard.historical_feature_row.v1"
    assert first["featureType"] == "incident_detector_trace"
    assert first["entity"]["caseId"] == "april-2026-incident-1"
    assert first["features"]["expectedDecision"] in {"deny", "review", "allow"}
    assert first["rights"]["rawPayloadResaleAllowed"] is False
    assert first["receipts"]["policyReceiptHash"]
    assert first["rowHash"]
    assert "override_policy_verdict" in first["modelUse"]["notAllowed"]

    reputation = [
        row
        for row in payload["featureRows"]
        if row["featureType"] == "reputation_feed_snapshot_summary"
    ][0]
    assert reputation["features"]["parsedDomainCount"] > 0
    assert reputation["features"]["rawDomainsReturned"] is False
    assert reputation["rights"]["rawPayloadsReturned"] is False


def test_historical_feature_store_jsonl_export(tmp_path):
    out_path = tmp_path / "seed.v1.jsonl"
    manifest = write_historical_feature_store_jsonl(out_path, limit=2)

    assert manifest["schema"] == "0guard.historical_feature_store_export.v1"
    assert manifest["featureCount"] >= 3
    assert manifest["fileHash"]
    assert manifest["latestAliasPath"].endswith("seed.v1.jsonl")
    assert manifest["immutableRunPath"].endswith(".jsonl")
    assert "/runs/" in manifest["immutableRunPath"]
    assert manifest["latestAliasUpdated"] is True
    assert manifest["safety"]["transactionSigningEnabled"] is False

    rows = [json.loads(line) for line in Path(out_path).read_text().splitlines()]
    assert len(rows) == manifest["featureCount"]
    assert rows[0]["featureType"] == "incident_detector_trace"
    assert rows[-1]["rights"]["rawPayloadResaleAllowed"] is False

    run_path = tmp_path / Path(manifest["immutableRunPath"]).name
    if not run_path.exists():
        run_path = tmp_path / "runs" / Path(manifest["immutableRunPath"]).name
    assert run_path.exists()
    assert run_path.read_text() == out_path.read_text()
