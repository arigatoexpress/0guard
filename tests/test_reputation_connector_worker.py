"""Tests for live reputation connector workers."""

import json

import pytest

from guard0.reputation_connector_worker import (
    CISA_KEV_FEED_URL,
    CISA_KEV_SOURCE_ID,
    NVD_CVE_API_URL,
    NVD_CVE_SOURCE_ID,
    OFAC_SANCTIONS_FEED_URL,
    OFAC_SANCTIONS_SOURCE_ID,
    PHISHDESTROY_ACTIVE_DOMAINS_URL,
    cisa_kev_snapshot,
    nvd_cve_snapshot,
    ofac_sanctions_snapshot,
    phishdestroy_active_domains_snapshot,
    reputation_connector_snapshot,
)


def test_phishdestroy_snapshot_fetches_and_returns_derived_only(monkeypatch):
    def fake_fetch(url: str, *, timeout_seconds: float, max_bytes: int):
        assert url == PHISHDESTROY_ACTIVE_DOMAINS_URL
        assert timeout_seconds == 6.0
        assert max_bytes >= 1_000_000
        return {
            "ok": True,
            "statusCode": 200,
            "contentType": "application/json",
            "contentLength": 53,
            "etag": '"fixture"',
            "lastModified": None,
            "elapsedMs": 12,
            "body": json.dumps(
                [
                    "docs.0g.ai.evil.example",
                    "wallet-drainer.example",
                    "docs.0g.ai.evil.example",
                ]
            ).encode(),
            "error": None,
        }

    monkeypatch.setattr("guard0.reputation_connector_worker._fetch_url", fake_fetch)

    snapshot = phishdestroy_active_domains_snapshot(
        live=True,
        subject_url="https://docs.0g.ai.evil.example/claim",
    )

    assert snapshot["schema"] == "0guard.reputation_connector_snapshot.v1"
    assert snapshot["mode"] == "live_fetch_derived_only"
    assert snapshot["live"] is True
    assert snapshot["fetch"]["status"] == "ok"
    assert snapshot["fetch"]["parsedDomainCount"] == 2
    assert snapshot["fetch"]["sampledEvidenceCount"] == 1
    assert snapshot["subject"]["matchedInFeed"] is True
    assert snapshot["subject"]["rawDomainReturned"] is False
    assert snapshot["derivedEvidence"][0]["sourceId"] == "phishdestroy_destroylist"
    assert snapshot["derivedEvidence"][0]["verdict"] == "malicious"
    assert snapshot["reputationPreview"]["decision"]["decision"] == "deny"
    assert snapshot["snapshotReceipt"]["zeroGChainReady"] is True
    assert snapshot["rightsPolicy"]["rawDomainsReturned"] is False
    assert snapshot["safety"]["networkCalls"] is True
    assert snapshot["safety"]["rawPayloadsReturned"] is False
    encoded = json.dumps(snapshot)
    assert "docs.0g.ai.evil.example" not in encoded
    assert "wallet-drainer.example" not in encoded


def test_phishdestroy_snapshot_no_network_by_default():
    snapshot = phishdestroy_active_domains_snapshot(live=False, subject_url="docs.0g.ai")

    assert snapshot["mode"] == "live_fetch_disabled"
    assert snapshot["fetch"]["status"] == "live_fetch_disabled"
    assert snapshot["derivedEvidence"] == []
    assert snapshot["safety"]["networkCalls"] is False
    assert snapshot["safety"]["liveConnectorFetch"] is False


def test_reputation_connector_snapshot_rejects_unknown_source():
    with pytest.raises(ValueError, match="unsupported live connector"):
        reputation_connector_snapshot(source_id="not_real", live=False)


def test_cisa_kev_snapshot_reduces_official_feed_to_derived_evidence(monkeypatch):
    def fake_fetch(url: str, *, timeout_seconds: float, max_bytes: int):
        assert url == CISA_KEV_FEED_URL
        assert max_bytes >= 1_000_000
        return {
            "ok": True,
            "statusCode": 200,
            "contentType": "application/json",
            "contentLength": 321,
            "etag": '"kev-fixture"',
            "lastModified": None,
            "elapsedMs": 9,
            "body": json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "cveID": "CVE-2024-3094",
                            "vendorProject": "XZ Utils",
                            "product": "XZ Utils",
                            "vulnerabilityName": "XZ Utils backdoor",
                            "dateAdded": "2024-04-01",
                            "dueDate": "2024-04-22",
                            "knownRansomwareCampaignUse": "Unknown",
                        }
                    ]
                }
            ).encode(),
            "error": None,
        }

    monkeypatch.setattr("guard0.reputation_connector_worker._fetch_url", fake_fetch)

    snapshot = cisa_kev_snapshot(live=True, cve_ids=["CVE-2024-3094"])

    assert snapshot["schema"] == "0guard.reputation_connector_snapshot.v1"
    assert snapshot["sourceId"] == CISA_KEV_SOURCE_ID
    assert snapshot["fetch"]["parsedCveCount"] == 1
    assert snapshot["fetch"]["matchedCveCount"] == 1
    assert snapshot["derivedEvidence"][0]["sourceId"] == "software_advisory_cve"
    assert snapshot["derivedEvidence"][0]["verdict"] == "suspicious"
    assert snapshot["subject"]["matchedInFeed"] is True
    assert snapshot["rightsPolicy"]["rawPayloadsReturned"] is False
    encoded = json.dumps(snapshot)
    assert "XZ Utils backdoor" not in encoded


def test_nvd_cve_snapshot_reduces_cve_api_without_description_echo(monkeypatch):
    def fake_fetch(url: str, *, timeout_seconds: float, max_bytes: int):
        assert url.startswith(NVD_CVE_API_URL)
        return {
            "ok": True,
            "statusCode": 200,
            "contentType": "application/json",
            "contentLength": 321,
            "etag": '"nvd-fixture"',
            "lastModified": None,
            "elapsedMs": 8,
            "body": json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2024-3094",
                                "published": "2024-03-29T00:00:00.000",
                                "lastModified": "2024-04-01T00:00:00.000",
                                "descriptions": [
                                    {
                                        "lang": "en",
                                        "value": "Long public vulnerability description should be hashed only.",
                                    }
                                ],
                                "metrics": {
                                    "cvssMetricV31": [
                                        {
                                            "cvssData": {"baseSeverity": "CRITICAL"},
                                        }
                                    ]
                                },
                            }
                        }
                    ]
                }
            ).encode(),
            "error": None,
        }

    monkeypatch.setattr("guard0.reputation_connector_worker._fetch_url", fake_fetch)

    snapshot = nvd_cve_snapshot(live=True, cve_ids="CVE-2024-3094")

    assert snapshot["sourceId"] == NVD_CVE_SOURCE_ID
    assert snapshot["fetch"]["parsedCveCount"] == 1
    assert snapshot["derivedEvidence"][0]["sourceId"] == "software_advisory_cve"
    assert snapshot["derivedEvidence"][0]["verdict"] == "suspicious"
    assert snapshot["safety"]["rawPayloadsReturned"] is False
    assert "Long public vulnerability description" not in json.dumps(snapshot)


def test_ofac_snapshot_screens_exact_address_without_returning_raw_list(monkeypatch):
    target = "0x885b0892D241Cb5033C9995e09cA521d54f936b5"

    def fake_fetch(url: str, *, timeout_seconds: float, max_bytes: int):
        assert url == OFAC_SANCTIONS_FEED_URL
        return {
            "ok": True,
            "statusCode": 200,
            "contentType": "text/csv",
            "contentLength": 128,
            "etag": '"ofac-fixture"',
            "lastModified": None,
            "elapsedMs": 11,
            "body": f'123,"Example Entity","SDGT","Digital Currency Address - ETH {target}"\n'.encode(),
            "error": None,
        }

    monkeypatch.setattr("guard0.reputation_connector_worker._fetch_url", fake_fetch)

    snapshot = ofac_sanctions_snapshot(live=True, address=target)

    assert snapshot["sourceId"] == OFAC_SANCTIONS_SOURCE_ID
    assert snapshot["fetch"]["parsedDigitalCurrencyAddressCount"] == 1
    assert snapshot["fetch"]["matchedAddressCount"] == 1
    assert snapshot["derivedEvidence"][0]["sourceId"] == "ofac_sanctions_sls"
    assert snapshot["derivedEvidence"][0]["verdict"] == "malicious"
    assert snapshot["subject"]["addressRedacted"] == "0x885b...36b5"
    assert snapshot["subject"]["rawAddressReturned"] is False
    assert snapshot["rightsPolicy"]["rawPayloadsReturned"] is False
    encoded = json.dumps(snapshot)
    assert target not in encoded
    assert "Example Entity" not in encoded
