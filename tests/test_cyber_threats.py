"""Tests for the Web2/Web3 cyber-threat repository surface."""

import json

from guard0.cyber_threats import build_cyber_threat_repository


def test_cyber_threat_repository_is_safe_by_default():
    repo = build_cyber_threat_repository(cve_ids="CVE-2024-3094")

    assert repo["schema"] == "0guard.cyber_threat_repository.v1"
    assert repo["live"] is False
    assert repo["mode"] == "catalog_and_local_features"
    assert repo["officialConnectorSnapshots"][0]["sourceId"] == "cisa_kev"
    assert repo["officialConnectorSnapshots"][0]["mode"] == "live_fetch_disabled"
    assert repo["officialConnectorSnapshots"][1]["sourceId"] == "nvd_cve"
    assert repo["officialConnectorSnapshots"][2]["sourceId"] == "ofac_sanctions"
    assert repo["historicalCryptoExploitCoverage"]["coverageRatio"] == 1.0
    assert {item["id"] for item in repo["mitreTtpContext"]} >= {
        "mitre_attack_lazarus_g0032",
        "mitre_attack_shai_hulud_s9008",
    }
    assert repo["rightsPolicy"]["rawPayloadResaleAllowed"] is False
    assert repo["safety"]["rawPayloadsReturned"] is False
    assert repo["safety"]["transactionSigningEnabled"] is False


def test_cyber_threat_repository_live_uses_derived_connector_snapshots(monkeypatch):
    def fake_cisa(**kwargs):
        assert kwargs["live"] is True
        return {
            "sourceId": "cisa_kev",
            "fetch": {"status": "ok"},
            "derivedEvidence": [
                {
                    "sourceId": "software_advisory_cve",
                    "verdict": "suspicious",
                    "confidence": 0.74,
                    "categories": ["software_supply_chain", "known_exploited"],
                    "evidenceHash": "kev-hash",
                }
            ],
            "snapshotReceipt": {"hash": "kev-receipt"},
        }

    def fake_nvd(**kwargs):
        assert kwargs["live"] is True
        return {
            "sourceId": "nvd_cve",
            "fetch": {"status": "ok"},
            "derivedEvidence": [],
            "snapshotReceipt": {"hash": "nvd-receipt"},
        }

    def fake_ofac(**kwargs):
        assert kwargs["live"] is True
        assert kwargs["address"] == "0x885b0892D241Cb5033C9995e09cA521d54f936b5"
        return {
            "sourceId": "ofac_sanctions",
            "fetch": {"status": "ok"},
            "derivedEvidence": [
                {
                    "sourceId": "ofac_sanctions_sls",
                    "verdict": "malicious",
                    "confidence": 0.94,
                    "categories": ["sanctions_context", "not_legal_advice"],
                    "evidenceHash": "ofac-hash",
                }
            ],
            "snapshotReceipt": {"hash": "ofac-receipt"},
        }

    monkeypatch.setattr("guard0.cyber_threats.cisa_kev_snapshot", fake_cisa)
    monkeypatch.setattr("guard0.cyber_threats.nvd_cve_snapshot", fake_nvd)
    monkeypatch.setattr("guard0.cyber_threats.ofac_sanctions_snapshot", fake_ofac)

    repo = build_cyber_threat_repository(
        live=True,
        cve_ids=["CVE-2024-3094"],
        address="0x885b0892D241Cb5033C9995e09cA521d54f936b5",
    )

    assert repo["mode"] == "live_fetch_derived_only"
    assert repo["safety"]["networkCalls"] is True
    assert repo["safety"]["liveOfacFetch"] is True
    assert len(repo["detectorPromotionCandidates"]) >= 3
    assert repo["detectorPromotionCandidates"][0]["promotionAutomatic"] is False
    encoded = json.dumps(repo)
    assert "0x885b0892D241Cb5033C9995e09cA521d54f936b5" not in encoded
