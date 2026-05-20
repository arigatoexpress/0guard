"""Tests for derived-only reputation backfill artifacts."""

from guard0.reputation_backfill import (
    build_reputation_backfill_status,
    run_phishdestroy_reputation_backfill,
)


def test_reputation_backfill_persists_derived_only_latest(tmp_path):
    latest = tmp_path / "phishdestroy" / "latest.json"
    snapshot = {
        "fetch": {
            "status": "ok",
            "httpStatus": 200,
            "latencyMs": 12,
            "contentType": "application/json",
            "contentLength": 100,
            "etag": '"fixture"',
            "lastModified": None,
            "feedHash": "feedhash",
            "parsedDomainCount": 2,
            "sampledEvidenceCount": 1,
            "ttlSeconds": 21600,
        },
        "subject": {"domainHash": "subjecthash", "matchedInFeed": True, "rawDomainReturned": False},
        "rawDomains": ["docs.0g.ai.evil.example"],
        "derivedEvidence": [
            {
                "sourceId": "phishdestroy_destroylist",
                "verdict": "malicious",
                "confidence": 0.88,
                "label": "PhishDestroy phishing-domain signal",
                "categories": ["phishing_domain", "active"],
                "referenceUrlHash": "referencehash",
                "evidenceHash": "evidencehash",
            }
        ],
        "reputationPreview": {
            "schema": "0guard.reputation_probe.v1",
            "decision": {"decision": "deny"},
            "signalCount": 1,
            "rawPayloadsReturned": False,
        },
        "snapshotReceipt": {"hash": "snapshothash", "algorithm": "sha256_canonical_json"},
    }

    run = run_phishdestroy_reputation_backfill(
        live=True,
        out_path=latest,
        snapshot=snapshot,
    )

    assert run["schema"] == "0guard.reputation_backfill_run.v1"
    assert run["status"] == "ok"
    assert run["derivedEvidenceCount"] == 1
    assert run["fetch"]["parsedDomainCount"] == 2
    assert run["persistence"]["written"] is True
    assert run["persistence"]["fileHash"]
    assert run["rightsPolicy"]["rawPayloadResaleAllowed"] is False
    assert run["safety"]["transactionSigningEnabled"] is False
    assert run["runReceipt"]["liveAnchorPerformed"] is False

    raw_text = latest.read_text(encoding="utf-8")
    assert "docs.0g.ai.evil.example" not in raw_text
    assert '"rawDomains": [' not in raw_text

    status = build_reputation_backfill_status(latest)
    assert status["schema"] == "0guard.reputation_backfill_status.v1"
    assert status["status"] == "ready"
    assert status["latestRunExists"] is True
    assert status["derivedEvidenceCount"] == 1
    assert status["parsedDomainCount"] == 2
    assert status["rawPayloadsReturned"] is False
    assert status["rawDomainsReturned"] is False
    assert status["safety"]["networkCalls"] is False
    assert status["scheduleManifest"]["supervisorInstalled"] is True
    assert status["scheduleManifest"]["supervisorType"] == (
        "github_actions_scheduled_freshness_monitor"
    )


def test_reputation_backfill_status_missing_is_safe(tmp_path):
    status = build_reputation_backfill_status(tmp_path / "missing.json")

    assert status["status"] == "missing"
    assert status["latestRunExists"] is False
    assert status["derivedEvidenceCount"] == 0
    assert status["safety"]["networkCalls"] is False
    assert status["rightsPolicy"]["derivedEvidenceOnly"] is True
