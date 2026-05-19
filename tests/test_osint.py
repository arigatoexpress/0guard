"""Tests for rights-aware OSINT source and signal surfaces."""

import json

from guard0.osint import (
    evolving_threat_intelligence,
    hackathon_submission_brief,
    hackquest_readiness_audit,
    hackquest_submission_packet,
    incident_provenance_matrix,
    load_source_registry,
    osint_readiness,
    osint_signals,
    signature_map,
    source_registry_public,
    threat_receipt_passport,
)


DEFILLAMA_SAMPLE_RECORDS = [
    {
        "date": 1775001600,
        "name": "Drift Trade",
        "amount": 285_000_000,
        "chain": ["Solana"],
        "classification": "Infrastructure",
        "technique": "Compromised Admin + Fake Token Price Manipulation",
        "targetType": "DeFi Protocol",
        "bridgeHack": False,
    },
    {
        "date": 1776470400,
        "name": "Kelp",
        "amount": 293_000_000,
        "chain": ["Ethereum", "Base"],
        "classification": "Protocol Logic",
        "technique": "LayerZero OFT bridge exploit",
        "targetType": "DeFi Protocol",
        "bridgeHack": True,
    },
    {
        "date": 1777507200,
        "name": "Wasabi Perps",
        "amount": 5_500_000,
        "chain": ["Ethereum", "Base", "Berachain", "Blast"],
        "classification": "Infrastructure",
        "technique": "Admin Key Compromised",
        "targetType": "DeFi Protocol",
        "bridgeHack": False,
    },
]


def test_source_registry_exposes_rights_metadata_without_raw_payloads():
    registry = load_source_registry()
    public = source_registry_public()

    assert registry["schema"] == "0guard.osint_source_registry.v1"
    assert public["schema"] == "0guard.osint_source_registry.v1"
    assert public["sourceCount"] >= 8
    assert public["rightsPolicy"]["rawPayloadResaleAllowed"] is False
    source_ids = {source["id"] for source in public["sources"]}
    assert "defillama_hacks" in source_ids
    assert "chainalysis_blog_rss" in source_ids
    assert "forta_labelled_datasets" in source_ids
    assert "threatfox_iocs" in source_ids
    assert "chainalysis_sanctions_oracle" in source_ids
    assert "chainalysis_sanctions_api" in source_ids
    assert "trm_wallet_screening" in source_ids
    assert "trm_blockint_api" in source_ids
    assert "mitre_attack_lazarus_g0032" in source_ids
    assert "google_web_risk" in source_ids

    by_id = {source["id"]: source for source in public["sources"]}
    assert by_id["threatfox_iocs"]["enabledByDefault"] is False
    assert by_id["chainalysis_sanctions_oracle"]["enabledByDefault"] is False
    assert by_id["chainalysis_sanctions_api"]["enabledByDefault"] is False
    assert by_id["trm_wallet_screening"]["enabledByDefault"] is False
    assert by_id["trm_blockint_api"]["enabledByDefault"] is False
    assert by_id["mitre_attack_lazarus_g0032"]["enabledByDefault"] is True
    assert by_id["google_web_risk"]["enabledByDefault"] is False
    assert "not legal advice" in by_id["chainalysis_sanctions_api"]["caveats"].lower()
    assert "do not claim live trm" in by_id["trm_wallet_screening"]["caveats"].lower()
    assert "never expose" in by_id["google_web_risk"]["outputPolicy"].lower()


def test_osint_readiness_can_run_without_live_network():
    readiness = osint_readiness(live=False)

    assert readiness["schema"] == "0guard.osint_readiness.v1"
    assert readiness["live"] is False
    assert readiness["attemptedLiveChecks"] == 0
    assert readiness["readinessRatio"] is None
    assert readiness["safety"]["readOnly"] is True
    assert readiness["safety"]["rawPayloadsReturned"] is False
    assert all(source["status"] == "not_checked" for source in readiness["sources"])


def test_osint_signals_live_disabled_reports_catalog_status_only():
    signals = osint_signals(live=False, limit=5)

    assert signals["schema"] == "0guard.osint_signals.v1"
    assert signals["live"] is False
    assert signals["signalCount"] == 0
    assert signals["safety"]["rawPayloadsReturned"] is False
    assert any(item["status"] == "live_fetch_disabled" for item in signals["sourceStatus"])
    encoded = json.dumps(signals)
    assert "private_key" not in encoded.lower()


def test_osint_signals_live_includes_phishdestroy_digest(monkeypatch):
    def fake_phishdestroy_snapshot(*, live: bool, limit: int, timeout_seconds: float):
        assert live is True
        assert limit == 4
        assert timeout_seconds == 6.0
        return {
            "schema": "0guard.reputation_connector_snapshot.v1",
            "generatedAt": "2026-05-16T22:00:00+00:00",
            "sourceId": "phishdestroy_destroylist",
            "sourceLink": "https://phishdestroy.io/dataset",
            "fetch": {
                "status": "ok",
                "httpStatus": 200,
                "latencyMs": 33,
                "feedHash": "feedhash",
                "parsedDomainCount": 123,
                "sampledEvidenceCount": 4,
                "ttlSeconds": 21600,
            },
            "snapshotReceipt": {"hash": "snap"},
        }

    monkeypatch.setattr(
        "guard0.osint.phishdestroy_active_domains_snapshot",
        fake_phishdestroy_snapshot,
    )
    monkeypatch.setattr(
        "guard0.osint._fetch_url",
        lambda *args, **kwargs: type(
            "FetchResult",
            (),
            {
                "ok": False,
                "status_code": 503,
                "content_type": "",
                "elapsed_ms": 1,
                "body": b"",
                "error": "disabled in test",
            },
        )(),
    )

    signals = osint_signals(live=True, limit=4)

    phish_status = next(
        status
        for status in signals["sourceStatus"]
        if status["sourceId"] == "phishdestroy_destroylist"
    )
    assert phish_status["status"] == "ok"
    assert phish_status["parsedDomainCount"] == 123
    assert phish_status["rawPayloadReturned"] is False

    digest = next(
        signal
        for signal in signals["signals"]
        if signal["sourceId"] == "phishdestroy_destroylist"
    )
    assert digest["signalType"] == "reputation_feed_digest"
    assert digest["activeDomainCount"] == 123
    assert digest["sampledEvidenceCount"] == 4
    assert digest["rawPayloadReturned"] is False
    assert digest["recordHash"]


def test_signature_map_explains_coverage_gaps():
    mapping = signature_map()

    assert mapping["schema"] == "0guard.signature_map.v1"
    assert mapping["incidentCount"] == 28
    assert mapping["matchedCount"] == 28
    assert mapping["gapCount"] == 0
    assert mapping["coverageRatio"] == 1.0
    assert mapping["signatureCoverageRatio"] == 1.0
    assert mapping["topGaps"] == {}
    drift = next(row for row in mapping["rows"] if row["protocol"] == "Drift Protocol")
    assert drift["matched"] is True
    assert drift["gap"] is None
    quant = next(row for row in mapping["rows"] if row["protocol"] == "Quant")
    assert quant["attackVector"] == "EIP-7702 delegated batch access-control failure"
    assert quant["matched"] is True
    assert quant["gap"] is None
    assert "eip7702_delegated_batch_access_control" in quant["signaturesMatched"]


def test_evolving_threat_intelligence_stitches_detector_loop_and_0g_suite():
    intel = evolving_threat_intelligence(live=False, limit=5)

    assert intel["schema"] == "0guard.evolving_threat_intelligence.v1"
    assert intel["live"] is False
    assert intel["currentDataset"]["incidentCount"] == 28
    assert intel["currentDataset"]["sourceEvidenceCoverage"] == 1.0
    assert intel["currentDataset"]["signatureCoverageRatio"] == 1.0
    assert intel["detectorFamilies"]
    assert any(family["id"] == "behavior_sequence" for family in intel["detectorFamilies"])
    assert any(
        family["id"] == "accounting_and_numeric"
        and family["matchedIncidentCount"] >= 3
        for family in intel["detectorFamilies"]
    )
    assert intel["emergingDetectorQueue"] == []
    assert intel["liveSourceSignals"]["signalCount"] == 0
    assert intel["zeroGSuite"]["chain"]["status"] == "mainnet_anchor_live"
    assert "shortMemo" in intel["zeroGSuite"]["chain"]["readableV2Ready"]["memoFields"]
    assert intel["zeroGSuite"]["storage"]["currentRootHash"]
    assert intel["zeroGSuite"]["compute"]["status"] == "planned_no_live_inference_claim"
    assert intel["qualityBar"]["telegramSendsClaimed"] is False
    assert intel["safety"]["rawPayloadsReturned"] is False


def test_incident_provenance_matrix_correlates_source_records():
    matrix = incident_provenance_matrix(defillama_records=DEFILLAMA_SAMPLE_RECORDS)

    assert matrix["schema"] == "0guard.incident_provenance_matrix.v1"
    assert matrix["live"] is False
    assert matrix["sourceStatus"]["status"] == "injected_records"
    assert matrix["coverage"]["incidentCount"] == 28
    assert matrix["coverage"]["withMatchedEvidence"] == 3
    assert matrix["coverage"]["highConfidenceEvidenceCount"] >= 2
    assert matrix["safety"]["rawPayloadsReturned"] is False

    drift = next(row for row in matrix["rows"] if row["protocol"] == "Drift Protocol")
    assert drift["status"] == "source_linked"
    assert drift["evidence"][0]["matchedName"] == "Drift Trade"
    assert drift["evidence"][0]["confidence"] >= 0.85
    assert drift["evidence"][0]["recordHash"]

    denaria = next(row for row in matrix["rows"] if row["protocol"] == "Denaria Finance")
    assert denaria["status"] == "aggregate_only"
    assert denaria["evidence"] == []
    assert "protocol postmortem" in denaria["recommendedNextStep"]


def test_incident_provenance_matrix_uses_canonical_evidence_without_network():
    matrix = incident_provenance_matrix()

    assert matrix["schema"] == "0guard.incident_provenance_matrix.v1"
    assert matrix["sourceStatus"]["status"] == "canonical_dataset"
    assert matrix["sourceStatus"]["evidenceMode"] == "canonical_dataset_evidence"
    assert matrix["sourceStatus"]["cacheRecordsLoaded"] == 26
    assert matrix["sourceStatus"]["canonicalEvidenceRecordsLoaded"] == 28
    assert matrix["coverage"]["withMatchedEvidence"] == 28
    assert matrix["coverage"]["withDatasetSourceUrls"] == 28
    assert matrix["coverage"]["aggregateOnlyCount"] == 0
    assert matrix["safety"]["rawPayloadsReturned"] is False

    silo = next(row for row in matrix["rows"] if row["protocol"] == "Silo V2")
    assert silo["status"] == "source_linked"
    assert silo["evidence"][0]["sourceId"] == "smart_contract_hacking_attack_library"
    drift = next(row for row in matrix["rows"] if row["protocol"] == "Drift Protocol")
    assert drift["evidence"][0]["canonicalDatasetEvidence"] is True
    assert drift["recommendedNextStep"].startswith("Add protocol postmortem")


def test_incident_provenance_matrix_can_fallback_to_canonical_evidence(tmp_path):
    missing_cache = tmp_path / "missing-cache.json"

    matrix = incident_provenance_matrix(cache_path=missing_cache)

    assert matrix["sourceStatus"]["status"] == "canonical_dataset"
    assert matrix["sourceStatus"]["evidenceMode"] == "canonical_dataset_evidence"
    assert matrix["coverage"]["withMatchedEvidence"] == 28
    assert matrix["coverage"]["withDatasetSourceUrls"] == 28
    drift = next(row for row in matrix["rows"] if row["protocol"] == "Drift Protocol")
    assert drift["evidence"][0]["canonicalDatasetEvidence"] is True
    assert drift["evidence"][0]["recordHash"]


def test_hackathon_submission_brief_is_operator_ready():
    brief = hackathon_submission_brief()

    assert brief["schema"] == "0guard.hackathon_submission_brief.v1"
    assert brief["project"]["name"] == "0guard"
    assert brief["project"]["hackQuestProject"] == "https://www.hackquest.io/projects/0guard"
    assert brief["hackQuestSubmission"]["status"] == "submitted_verified"
    assert brief["deadline"]["submissionDeadline"] == "2026-05-16T23:59:00+08:00"
    assert brief["dataProduct"]["incidentCount"] == 28
    assert brief["dataProduct"]["sourceRegistryCount"] >= 8
    assert brief["trackRecommendation"]["primary"].startswith("Track 5")
    assert brief["submissionRequirements"]["publicXPost"]["mandatory"] is True
    assert "#0GHackathon" in brief["submissionRequirements"]["publicXPost"]["requiredHashtags"]
    assert any("proof trails" in item for item in brief["competitivePositioning"])
    assert brief["submissionRequirements"]["0gProof"]["status"] == "ready"
    assert brief["submissionRequirements"]["0gProof"]["contractAddress"].startswith("0x")
    assert not any("Record and upload" in item for item in brief["operatorRequired"])
    assert not any("Post public X post" in item for item in brief["operatorRequired"])
    assert any("Do not claim live 0G Compute" in item for item in brief["claimsToAvoid"])


def test_hackquest_submission_packet_is_copy_ready_and_safe():
    packet = hackquest_submission_packet()

    assert packet["schema"] == "0guard.hackquest_submission_packet.v1"
    assert packet["formFields"]["projectName"] == "0guard"
    assert packet["formFields"]["demoVideoUrl"].endswith("0guard-hackquest-demo-final.mp4")
    assert packet["formFields"]["xPostUrl"] == "https://x.com/rariwrldd/status/2054779961425461542"
    assert packet["formFields"]["0gContractAddress"] == (
        "0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc"
    )
    assert packet["formFields"]["0gExplorerUrl"].startswith("https://chainscan.0g.ai/tx/")
    assert packet["formFields"]["screenshotAsset"].endswith("0guard-workbench-provenance.png")
    assert packet["formFields"]["threatReceiptPassport"].endswith("threat-receipt-passport.md")
    assert packet["formFields"]["threatReceiptPassportApi"] == "/api/hackathon/threat-passport"
    assert packet["formFields"]["hackQuestProjectUrl"] == "https://www.hackquest.io/projects/0guard"
    assert packet["hackQuestSubmission"]["status"] == "submitted_verified"
    assert packet["recommendedTrack"].startswith("Track 5")
    assert "/api/data/provenance" in {proof["route"] for proof in packet["proofPoints"]}
    assert packet["xPost"]["mediaPath"] == packet["formFields"]["screenshotAsset"]
    assert packet["xPost"]["singlePostFile"] == "content/hackquest_x_post.json"
    assert "--dry-run" in packet["xPost"]["dryRunCommand"]
    assert "POST_TO_X_FROM_0GUARD" in packet["xPost"]["liveCommand"]
    assert packet["readiness"]["readinessRoute"] == "/api/hackathon/readiness"
    assert packet["safety"]["rawPayloadsReturned"] is False


def test_threat_receipt_passport_stitches_judge_proof_packet():
    passport = threat_receipt_passport()

    assert passport["schema"] == "0guard.threat_receipt_passport.v1"
    assert passport["agentSession"] == "agent-7857-demo"
    assert passport["sampleIntent"]["action"] == "approve"
    assert passport["receipt"]["decision"] == "deny"
    assert passport["receipt"]["severity"] == "critical"
    assert passport["receipt"]["receiptHash"]
    assert passport["receipt"]["zeroG"]["chain_anchor"]["status"] == "preflight"
    assert passport["receipt"]["zeroG"]["storage_receipt"]["root_hash"]
    assert passport["provenance"]["coverage"]["withMatchedEvidence"] == 28
    assert passport["provenance"]["aggregateOnlyGaps"] == []
    assert passport["signatureCoverage"]["incidentCount"] == 28
    assert passport["signatureCoverage"]["gapCount"] == 0
    assert passport["0gProofBoundary"]["currentStatus"] == (
        "mainnet_anchor_live_plus_read_only_workbench"
    )
    assert passport["0gProofBoundary"]["operatorPlaceholders"]["0gExplorerUrl"].startswith(
        "https://chainscan.0g.ai/tx/"
    )
    assert passport["safety"]["rawPayloadsReturned"] is False


def test_hackquest_readiness_audit_uses_mainnet_proof_file():
    audit = hackquest_readiness_audit()

    assert audit["schema"] == "0guard.hackquest_readiness_audit.v1"
    assert audit["event"]["deadline"]["utc8"] == "2026-05-16T23:59:00+08:00"
    assert audit["event"]["publicProjectUrl"] == "https://www.hackquest.io/projects/0guard"
    assert audit["mainnetRequirement"]["chainId"] == 16661
    assert audit["current0GConfig"]["chainId"] == 16661
    assert audit["submittableNow"] is True
    assert audit["current0GConfig"]["mainnetProofReady"] is True
    blockers = {item["id"] for item in audit["operatorBlockers"]}
    assert "0g_mainnet_contract" not in blockers
    assert "0g_mainnet_explorer" not in blockers
    assert "demo_video" not in blockers
    assert "public_x_post" not in blockers
    requirements = {item["id"]: item for item in audit["requirements"]}
    assert requirements["proof_packet"]["status"] == "ready"
    assert requirements["repo_professionalization"]["status"] == "ready"
    assert requirements["provenance_data"]["status"] == "ready"
    assert requirements["hackquest_submission"]["status"] == "ready"
    assert audit["hackQuestSubmission"]["submitted"] is True
    assert audit["repoProfessionalization"]["license"] == "Apache-2.0"
    assert audit["repoProfessionalization"]["assetRegistryUrl"].endswith("assets/README.md")
    assert audit["repoProfessionalization"]["generatedMediaPubliclyPromoted"] is False
    assert audit["operatorOnlyActions"] == []
    assert audit["safety"]["rawPayloadsReturned"] is False
