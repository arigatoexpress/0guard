"""Rights-aware open-source intelligence streams for 0guard."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from guard0.chain import ZERO_ADDRESS, get_0g_config
from guard0.incident_data import (
    dataset_fingerprint,
    detection_coverage,
    incident_summary,
    incident_to_detection_payload,
    load_incident_dataset,
)
from guard0.crypto_hack_guard import check_crypto_hack_signatures
from guard0.policy import evaluate_intent
from guard0.reputation_connector_worker import (
    phishdestroy_active_domains_snapshot,
    phishdestroy_digest_signal,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE_REGISTRY_PATH = REPO_ROOT / "data" / "osint_sources.json"
DEFAULT_PROVENANCE_CACHE_PATH = REPO_ROOT / "data" / "incident_provenance_cache.json"
DEFAULT_MAINNET_PROOF_PATH = REPO_ROOT / "docs" / "hackathon-0g" / "mainnet-proof.json"
DEFAULT_HACKQUEST_SUBMISSION_PROOF_PATH = (
    REPO_ROOT / "docs" / "hackathon-0g" / "hackquest-submission-proof.json"
)
DEFAULT_DEMO_VIDEO_PATH = (
    REPO_ROOT / "docs" / "hackathon-0g" / "assets" / "0guard-hackquest-demo-final.mp4"
)
DEFAULT_VEO_PACKET_PATH = REPO_ROOT / "docs" / "hackathon-0g" / "veo3-flow-production-prompt.md"
DEFAULT_ASSET_REGISTRY_PATH = REPO_ROOT / "docs" / "hackathon-0g" / "assets" / "README.md"
DEFAULT_LEGAL_POLICY_PATH = REPO_ROOT / "docs" / "LEGAL_AND_ASSET_POLICY.md"
OSINT_REGISTRY_SCHEMA = "0guard.osint_source_registry.v1"
OSINT_READINESS_SCHEMA = "0guard.osint_readiness.v1"
OSINT_SIGNALS_SCHEMA = "0guard.osint_signals.v1"
SIGNATURE_MAP_SCHEMA = "0guard.signature_map.v1"
EVOLVING_THREAT_INTEL_SCHEMA = "0guard.evolving_threat_intelligence.v1"
HACKATHON_BRIEF_SCHEMA = "0guard.hackathon_submission_brief.v1"
HACKQUEST_PACKET_SCHEMA = "0guard.hackquest_submission_packet.v1"
HACKQUEST_READINESS_SCHEMA = "0guard.hackquest_readiness_audit.v1"
THREAT_RECEIPT_PASSPORT_SCHEMA = "0guard.threat_receipt_passport.v1"
PROVENANCE_MATRIX_SCHEMA = "0guard.incident_provenance_matrix.v1"
PROVENANCE_CACHE_SCHEMA = "0guard.incident_provenance_cache.v1"
USER_AGENT = "0guard-osint/0.1 (+https://github.com/arigatoexpress/0guard)"
MAX_FETCH_BYTES = 2_000_000
HACKQUEST_OFFICIAL_URL = "https://www.hackquest.io/hackathons/0G-APAC-Hackathon"
HACKQUEST_PUBLIC_PROJECT_URL = "https://www.hackquest.io/projects/0guard"
HACKQUEST_PROJECT_ID = "f8333543-559e-48f4-b6fa-4ff447777966"
HACKQUEST_HACKATHON_ID = "57e543a9-0b08-4ba3-8326-e5cd751c0248"
HACKQUEST_DEADLINE_UTC8 = "2026-05-16T23:59:00+08:00"
HACKQUEST_DEADLINE_MDT = "2026-05-16T09:59:00-06:00"
ZGG_MAINNET_CHAIN_ID = 16661
ZGG_MAINNET_RPC = "https://evmrpc.0g.ai"
ZGG_MAINNET_EXPLORER = "https://chainscan.0g.ai"
ZGG_STORAGE_SCAN = "https://storagescan.0g.ai"
HACKQUEST_REQUIRED_HASHTAGS = ["#0GHackathon", "#BuildOn0G"]
HACKQUEST_REQUIRED_TAGS = ["@0G_labs", "@0g_CN", "@0g_Eco", "@HackQuest_"]
PUBLIC_DEMO_VIDEO_URL = (
    "https://arigatoexpress.github.io/0guard/hackathon-0g/assets/"
    "0guard-hackquest-demo-final.mp4"
)
PUBLIC_X_POST_URL = "https://x.com/rariwrldd/status/2054779961425461542"
PUBLIC_VEO_PACKET_URL = (
    "https://arigatoexpress.github.io/0guard/hackathon-0g/"
    "veo3-flow-production-prompt.md"
)
PUBLIC_ASSET_REGISTRY_URL = (
    "https://arigatoexpress.github.io/0guard/hackathon-0g/assets/README.md"
)
PUBLIC_LEGAL_POLICY_URL = (
    "https://github.com/arigatoexpress/0guard/blob/main/docs/LEGAL_AND_ASSET_POLICY.md"
)
PUBLIC_NOTICE_URL = "https://github.com/arigatoexpress/0guard/blob/main/NOTICE"
DEMO_VIDEO_PLACEHOLDER = "OPERATOR_REQUIRED_DEMO_VIDEO_URL"
X_POST_PLACEHOLDER = "OPERATOR_REQUIRED_X_POST_URL"
HACKQUEST_ONE_LINER = (
    "0guard is a 0G-native pre-wallet firewall that checks AI-agent intents "
    "against exploit intelligence before any signer can act."
)
DEFILLAMA_INCIDENT_ALIASES = {
    "driftprotocol": {"drifttrade"},
    "rheafinance": {"rhealend"},
    "voloprotocol": {"volovault"},
    "wasabiprotocol": {"wasabiperps"},
    "silov2": {"silofinance"},
}


@dataclass(frozen=True)
class FetchResult:
    ok: bool
    status_code: int | None
    url: str
    content_type: str
    elapsed_ms: int
    body: bytes
    error: str | None = None


def load_source_registry(path: str | Path | None = None) -> dict[str, Any]:
    """Load the source registry that defines rights and retrieval boundaries."""
    registry_path = Path(path) if path else DEFAULT_SOURCE_REGISTRY_PATH
    with registry_path.open("r", encoding="utf-8") as handle:
        registry = json.load(handle)
    if not isinstance(registry, dict):
        raise ValueError("OSINT source registry must be a JSON object")
    if registry.get("schema") != OSINT_REGISTRY_SCHEMA:
        raise ValueError(f"unexpected OSINT source registry schema: {registry.get('schema')}")
    sources = registry.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("OSINT source registry must include sources")
    return registry


def source_registry_public() -> dict[str, Any]:
    """Return public source metadata without raw payloads or credentials."""
    registry = load_source_registry()
    return {
        "schema": registry["schema"],
        "generatedAt": registry.get("generated_at"),
        "sourceCount": len(registry["sources"]),
        "enabledByDefaultCount": sum(
            1 for source in registry["sources"] if source.get("enabled_by_default")
        ),
        "sources": [_public_source_fields(source) for source in registry["sources"]],
        "rightsPolicy": {
            "paymentIsNotPermission": True,
            "rawPayloadResaleAllowed": False,
            "outputMode": "derived_metadata_links_hashes_and_defensive_analysis",
        },
    }


def osint_readiness(*, live: bool = False, timeout_seconds: float = 3.0) -> dict[str, Any]:
    """Check source catalog posture, optionally proving live source availability."""
    registry = load_source_registry()
    rows: list[dict[str, Any]] = []
    attempted = 0
    reachable = 0

    for source in registry["sources"]:
        row = _public_source_fields(source)
        row["enabledByDefault"] = bool(source.get("enabled_by_default"))
        row["liveChecked"] = False
        row["status"] = "not_checked"
        row["latencyMs"] = None
        row["httpStatus"] = None
        row["error"] = None

        if live and source.get("enabled_by_default"):
            attempted += 1
            result = _fetch_url(source["url"], timeout_seconds=timeout_seconds, max_bytes=2048)
            row["liveChecked"] = True
            row["status"] = "reachable" if result.ok else "degraded"
            row["latencyMs"] = result.elapsed_ms
            row["httpStatus"] = result.status_code
            row["contentType"] = result.content_type
            row["error"] = result.error
            if result.ok:
                reachable += 1

        rows.append(row)

    return {
        "schema": OSINT_READINESS_SCHEMA,
        "generatedAt": _now(),
        "rawPayloadsReturned": False,
        "live": live,
        "sourceCount": len(rows),
        "enabledByDefaultCount": sum(1 for row in rows if row["enabledByDefault"]),
        "attemptedLiveChecks": attempted,
        "reachableLiveChecks": reachable,
        "readinessRatio": round(reachable / attempted, 4) if attempted else None,
        "sources": rows,
        "safety": _osint_safety(),
    }


def osint_signals(
    *,
    live: bool = True,
    limit: int = 20,
    timeout_seconds: float = 6.0,
) -> dict[str, Any]:
    """Fetch normalized OSINT signals from enabled public streams."""
    registry = load_source_registry()
    signals: list[dict[str, Any]] = []
    source_status: list[dict[str, Any]] = []

    for source in registry["sources"]:
        if not source.get("enabled_by_default"):
            continue
        adapter = source.get("adapter")
        if adapter == "phishdestroy_destroylist":
            if not live:
                source_status.append(
                    {
                        "sourceId": source["id"],
                        "adapter": adapter,
                        "status": "live_fetch_disabled",
                    }
                )
                continue
            snapshot = phishdestroy_active_domains_snapshot(
                live=True,
                limit=min(limit, 10),
                timeout_seconds=timeout_seconds,
            )
            fetch = snapshot.get("fetch") if isinstance(snapshot.get("fetch"), dict) else {}
            source_status.append(
                {
                    "sourceId": source["id"],
                    "adapter": adapter,
                    "status": "ok" if fetch.get("status") == "ok" else "degraded",
                    "httpStatus": fetch.get("httpStatus"),
                    "latencyMs": fetch.get("latencyMs"),
                    "error": fetch.get("error"),
                    "feedHash": fetch.get("feedHash"),
                    "parsedDomainCount": fetch.get("parsedDomainCount"),
                    "rawPayloadReturned": False,
                }
            )
            digest_signal = phishdestroy_digest_signal(snapshot, source)
            if digest_signal:
                signals.append(digest_signal)
            continue
        if adapter not in ("defillama_hacks", "rss"):
            source_status.append(
                {
                    "sourceId": source["id"],
                    "adapter": adapter,
                    "status": "catalog_only",
                    "reason": "No raw payload fetched; source is used as a provenance lead.",
                }
            )
            continue
        if not live:
            source_status.append(
                {
                    "sourceId": source["id"],
                    "adapter": adapter,
                    "status": "live_fetch_disabled",
                }
            )
            continue

        result = _fetch_url(
            source["url"],
            timeout_seconds=timeout_seconds,
            max_bytes=MAX_FETCH_BYTES,
        )
        source_status.append(
            {
                "sourceId": source["id"],
                "adapter": adapter,
                "status": "ok" if result.ok else "degraded",
                "httpStatus": result.status_code,
                "latencyMs": result.elapsed_ms,
                "error": result.error,
            }
        )
        if not result.ok:
            continue
        if adapter == "defillama_hacks":
            signals.extend(_normalize_defillama_hacks(source, result.body, limit=limit))
        elif adapter == "rss":
            signals.extend(_normalize_rss_items(source, result.body, limit=limit))

    signals.sort(key=lambda item: item.get("observedAt") or "", reverse=True)
    signals = signals[:limit]
    return {
        "schema": OSINT_SIGNALS_SCHEMA,
        "generatedAt": _now(),
        "live": live,
        "signalCount": len(signals),
        "sourceStatus": source_status,
        "signals": signals,
        "safety": _osint_safety(),
    }


def signature_map(dataset: dict[str, Any] | None = None) -> dict[str, Any]:
    """Explain incident-to-signature coverage and concrete detector gaps."""
    loaded = dataset or load_incident_dataset()
    rows: list[dict[str, Any]] = []
    matched = 0
    for incident in loaded.get("incidents", []):
        payload = incident_to_detection_payload(incident)
        result = check_crypto_hack_signatures(payload).to_dict()
        is_matched = bool(result["blockers"] or result["warnings"] or result["signatures_matched"])
        if is_matched:
            matched += 1
        rows.append(
            {
                "incidentId": incident.get("id"),
                "protocol": incident.get("protocol"),
                "attackVector": incident.get("attack_vector"),
                "chain": incident.get("chain"),
                "matched": is_matched,
                "signaturesMatched": result["signatures_matched"],
                "blockers": result["blockers"],
                "warnings": result["warnings"],
                "gap": None if is_matched else _signature_gap_for_incident(incident),
                "recommendedDetector": _recommended_detector_for_incident(incident, is_matched),
                "payloadPreview": {
                    key: payload.get(key)
                    for key in ("action", "mode", "requires_signature", "calldata", "steps")
                    if payload.get(key)
                },
            }
        )

    total = len(rows)
    coverage_ratio = round(matched / total, 4) if total else 0
    return {
        "schema": SIGNATURE_MAP_SCHEMA,
        "datasetFingerprint": dataset_fingerprint(loaded),
        "incidentCount": total,
        "matchedCount": matched,
        "gapCount": total - matched,
        "coverageRatio": coverage_ratio,
        "signatureCoverageRatio": coverage_ratio,
        "topGaps": _top_gap_counts(rows),
        "rows": rows,
    }


def evolving_threat_intelligence(
    *,
    live: bool = False,
    limit: int = 10,
) -> dict[str, Any]:
    """Return the current detector roadmap as an evidence-backed intelligence loop."""
    summary = incident_summary()
    coverage = detection_coverage()
    sig_map = signature_map()
    provenance = incident_provenance_matrix(live=False)
    signals = osint_signals(live=live, limit=limit)
    mainnet_proof = _load_mainnet_proof()
    evidence_root = _record_hash(
        {
            "datasetFingerprint": summary["validation"]["fingerprint"],
            "provenanceCoverage": provenance["coverage"],
            "signatureCoverage": {
                "matched": sig_map["matchedCount"],
                "gaps": sig_map["gapCount"],
            },
        }
    )
    signal_source_ids = sorted(
        {
            status.get("sourceId")
            for status in signals["sourceStatus"]
            if isinstance(status, dict) and status.get("sourceId")
        }
    )

    return {
        "schema": EVOLVING_THREAT_INTEL_SCHEMA,
        "generatedAt": _now(),
        "live": live,
        "purpose": (
            "Turn source-cited incidents and public threat leads into pre-wallet "
            "detectors, receipt proofs, and quality-gated wallet alerts."
        ),
        "currentDataset": {
            "incidentCount": summary["stats"]["incidentCount"],
            "totalLossUsd": summary["stats"]["totalLossUsd"],
            "datasetFingerprint": summary["validation"]["fingerprint"],
            "sourceEvidenceCoverage": provenance["coverage"]["evidenceCoverageRatio"],
            "detectionCoverageRatio": coverage["coverageRatio"],
            "signatureCoverageRatio": sig_map["coverageRatio"],
        },
        "detectorFamilies": _detector_family_summary(sig_map),
        "emergingDetectorQueue": _emerging_detector_queue(sig_map),
        "liveSourceSignals": {
            "liveFetchAttempted": live,
            "signalCount": signals["signalCount"],
            "sourceStatus": signals["sourceStatus"],
            "sampleSignals": signals["signals"][: min(3, len(signals["signals"]))],
        },
        "intelligenceLoops": [
            {
                "id": "source_to_detector",
                "state": "active",
                "inputs": [
                    "canonical April 2026 incident dataset",
                    "reviewed provenance URLs",
                    "optional live OSINT signals",
                ],
                "outputs": [
                    "signature_map",
                    "emerging_detector_queue",
                    "wallet_alert_quality_policy",
                ],
            },
            {
                "id": "intent_to_receipt",
                "state": "active",
                "inputs": ["agent intent", "calldata", "mode", "signature requirement"],
                "outputs": [
                    "allow_review_deny verdict",
                    "receipt_hash",
                    "0G Chain anchor preflight",
                    "0G Storage-ready root hash",
                ],
            },
            {
                "id": "wallet_alert_triage",
                "state": "active_preview_no_send",
                "inputs": ["wallet address", "current intent", "detector result"],
                "outputs": [
                    "deduped high-signal alert preview",
                    "digest-only emerging risk notes",
                    "Telegram Mini App message preview",
                ],
            },
        ],
        "zeroGSuite": _zero_g_suite_map(mainnet_proof, evidence_root, signal_source_ids),
        "qualityBar": {
            "noMockThreatClaims": True,
            "rawPayloadsReturned": False,
            "liveComputeClaimed": False,
            "telegramSendsClaimed": False,
            "walletTrackingDefault": "preview_no_send_read_only",
            "promotionRule": (
                "A new detector becomes alert-eligible only after it has a source id, "
                "a reproducible intent/calldata pattern, and a regression test."
            ),
        },
        "safety": _osint_safety(),
    }


def incident_provenance_matrix(
    *,
    live: bool = False,
    dataset: dict[str, Any] | None = None,
    defillama_records: list[dict[str, Any]] | None = None,
    cache_path: str | Path | None = None,
    timeout_seconds: float = 6.0,
) -> dict[str, Any]:
    """Build per-incident source evidence and live-source correlation gaps."""
    loaded = dataset or load_incident_dataset()
    meta = loaded.get("meta") or {}
    aggregate_sources = meta.get("source_urls") if isinstance(meta, dict) else []
    if not isinstance(aggregate_sources, list):
        aggregate_sources = []
    canonical_evidence_count = sum(
        1
        for incident in loaded.get("incidents", [])
        if _canonical_evidence_for_incident(incident) is not None
    )

    fetched = False
    records = defillama_records if defillama_records is not None else []
    cached_evidence = (
        {}
        if defillama_records is not None
        else _load_provenance_cache(cache_path=cache_path)
    )
    source_status = {
        "sourceId": "defillama_hacks",
        "status": "injected_records"
        if defillama_records is not None
        else "live_fetch_disabled",
        "live": live,
        "error": None,
        "recordsLoaded": len(records),
        "cacheRecordsLoaded": len(cached_evidence),
        "canonicalEvidenceRecordsLoaded": canonical_evidence_count,
        "evidenceMode": "injected_records" if defillama_records is not None else "none",
    }

    if live and defillama_records is None:
        fetched = True
        result = _fetch_url(
            "https://api.llama.fi/hacks",
            timeout_seconds=timeout_seconds,
            max_bytes=MAX_FETCH_BYTES,
        )
        source_status.update(
            {
                "status": "ok" if result.ok else "degraded",
                "httpStatus": result.status_code,
                "latencyMs": result.elapsed_ms,
                "error": result.error,
            }
        )
        if result.ok:
            try:
                decoded = json.loads(result.body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                decoded = []
                source_status["status"] = "parse_error"
            if isinstance(decoded, list):
                records = [item for item in decoded if isinstance(item, dict)]
                source_status["recordsLoaded"] = len(records)
        if not records and cached_evidence:
            source_status["status"] = "degraded_cache_fallback"

    if records:
        source_status["evidenceMode"] = "live_source_records" if fetched else "injected_records"
    elif canonical_evidence_count:
        if not live and defillama_records is None:
            source_status["status"] = "canonical_dataset"
        source_status["evidenceMode"] = "canonical_dataset_evidence"
    elif cached_evidence:
        if not live and defillama_records is None:
            source_status["status"] = "reviewed_cache"
        source_status["evidenceMode"] = "reviewed_derived_cache"

    rows = []
    linked_count = 0
    high_confidence_count = 0
    dataset_source_count = 0
    use_canonical_fallback = defillama_records is None
    for incident in loaded.get("incidents", []):
        dataset_urls = incident.get("source_urls")
        if isinstance(dataset_urls, list) and dataset_urls:
            dataset_source_count += 1
        else:
            dataset_urls = []

        evidence = _defillama_evidence_for_incident(incident, records) if records else None
        if evidence is None and use_canonical_fallback:
            evidence = _canonical_evidence_for_incident(incident)
        if evidence is None and use_canonical_fallback and cached_evidence:
            evidence = cached_evidence.get(int(incident.get("id", -1)))
        if evidence:
            linked_count += 1
            if evidence["confidence"] >= 0.85:
                high_confidence_count += 1
        status = "source_linked" if evidence else "aggregate_only"
        if not evidence and not aggregate_sources:
            status = "missing_sources"

        rows.append(
            {
                "incidentId": incident.get("id"),
                "protocol": incident.get("protocol"),
                "date": incident.get("date"),
                "lossUsd": incident.get("loss_usd"),
                "chain": incident.get("chain"),
                "attackVector": incident.get("attack_vector"),
                "status": status,
                "datasetSourceUrls": dataset_urls,
                "aggregateSourceUrls": aggregate_sources,
                "evidence": [evidence] if evidence else [],
                "recommendedNextStep": _provenance_next_step(incident, evidence),
            }
        )

    incident_count = len(rows)
    evidence_coverage_ratio = round(linked_count / incident_count, 4) if incident_count else 0
    return {
        "schema": PROVENANCE_MATRIX_SCHEMA,
        "generatedAt": _now(),
        "live": live,
        "liveFetchAttempted": fetched,
        "datasetFingerprint": dataset_fingerprint(loaded),
        "sourceStatus": source_status,
        "incidentCount": incident_count,
        "withDatasetSourceUrls": dataset_source_count,
        "withMatchedEvidence": linked_count,
        "evidenceCoverageRatio": evidence_coverage_ratio,
        "coverage": {
            "incidentCount": incident_count,
            "withDatasetSourceUrls": dataset_source_count,
            "withMatchedEvidence": linked_count,
            "highConfidenceEvidenceCount": high_confidence_count,
            "aggregateOnlyCount": sum(1 for row in rows if row["status"] == "aggregate_only"),
            "evidenceCoverageRatio": evidence_coverage_ratio,
        },
        "rows": rows,
        "safety": _osint_safety(),
    }


def hackathon_submission_brief() -> dict[str, Any]:
    """Return a compact, current submission checklist and product brief."""
    summary = incident_summary()
    coverage = detection_coverage()
    sig_map = signature_map()
    sources = source_registry_public()
    provenance = incident_provenance_matrix(live=False)
    mainnet_proof = _load_mainnet_proof()
    mainnet_proof_ready = _mainnet_proof_ready(mainnet_proof)
    submission_proof = _load_hackquest_submission_proof()
    submission_ready = _hackquest_submission_ready(submission_proof)
    demo_video_ready = _demo_video_url() != DEMO_VIDEO_PLACEHOLDER
    x_post_ready = _x_post_url() != X_POST_PLACEHOLDER
    professionalization = _repo_professionalization_status()
    return {
        "schema": HACKATHON_BRIEF_SCHEMA,
        "generatedAt": _now(),
        "project": {
            "name": "0guard",
            "oneLiner": HACKQUEST_ONE_LINER,
            "repo": "https://github.com/arigatoexpress/0guard",
            "publicDemo": "https://arigatoexpress.github.io/0guard/",
            "hackQuestProject": HACKQUEST_PUBLIC_PROJECT_URL,
        },
        "hackQuestSubmission": {
            "status": "submitted_verified" if submission_ready else "ready_to_submit",
            "projectId": HACKQUEST_PROJECT_ID,
            "hackathonId": HACKQUEST_HACKATHON_ID,
            "publicProjectUrl": HACKQUEST_PUBLIC_PROJECT_URL,
            "proofFile": str(
                DEFAULT_HACKQUEST_SUBMISSION_PROOF_PATH.relative_to(REPO_ROOT)
            ),
            "verifiedAt": submission_proof.get("verified_at") if submission_proof else None,
        },
        "deadline": {
            "source": "HackQuest 0G APAC Hackathon",
            "submissionDeadline": HACKQUEST_DEADLINE_UTC8,
            "submissionDeadlineMdt": HACKQUEST_DEADLINE_MDT,
            "submissionDeadlineEdt": "2026-05-16T11:59:00-04:00",
            "preliminaryReview": "2026-05-16 to 2026-05-24",
            "rewardAnnouncement": "2026-05-29T15:59:00+08:00",
            "note": "Official HackQuest page says all final materials must be submitted before May 16, 2026 at 23:59 UTC+8.",
        },
        "trackRecommendation": {
            "primary": "Track 5: Privacy & Sovereign Infrastructure",
            "secondary": "Track 1: Agentic Infrastructure & OpenClaw Lab",
            "why": (
                "Lead with verifiable pre-wallet security, provenance, and receipt "
                "infrastructure; mention agent orchestration only as the user context."
            ),
        },
        "submissionRequirements": {
            "repo": {
                "required": True,
                "status": "ready",
                "url": "https://github.com/arigatoexpress/0guard",
            },
            "0gProof": {
                "required": True,
                "status": "ready" if mainnet_proof_ready else "operator_required",
                "needs": [
                    "0G mainnet contract address",
                    "0G mainnet Explorer link with verifiable activity",
                    "Clear proof of at least one 0G component",
                ],
                "contractAddress": mainnet_proof.get("contract_address") if mainnet_proof else None,
                "explorerUrl": mainnet_proof.get("anchor_explorer_url") if mainnet_proof else None,
            },
            "demoVideo": {
                "required": True,
                "status": "ready" if demo_video_ready else "operator_required",
                "maxDurationSeconds": 180,
                "mustShow": [
                    "core product flow",
                    "user flow or use case",
                    "how the 0G component is actually used",
                ],
            },
            "publicXPost": {
                "mandatory": True,
                "status": "ready" if x_post_ready else "operator_required",
                "requiredTags": HACKQUEST_REQUIRED_TAGS,
                "requiredHashtags": HACKQUEST_REQUIRED_HASHTAGS,
                "needs": ["project name", "demo screenshot or short demo clip"],
            },
            "documentation": {
                "required": True,
                "status": "ready_with_known_gaps",
                "judgeFastPath": "README plus docs/hackathon-0g/",
            },
            "repositoryProfessionalization": {
                "required": False,
                "status": "ready" if professionalization["ready"] else "needs_fix",
                "license": professionalization["license"],
                "publicMediaRegistry": professionalization["assetRegistryUrl"],
                "assetRegistry": professionalization["assetRegistryUrl"],
            },
        },
        "repoProfessionalization": professionalization,
        "judgeStory": [
            "AI agents can request wallet actions faster than humans can review them.",
            "0guard intercepts intent before the wallet, signer, bridge, or send path.",
            "The detector is grounded in real incident patterns and OSINT source streams.",
            "The verdict becomes a deterministic receipt ready for 0G Chain and Storage.",
            "Dangerous actions stay blocked from the workbench by design.",
        ],
        "competitivePositioning": [
            "Strong 0G submissions expose proof trails: contract addresses, storage roots, transaction hashes, demo URLs, and judge walkthroughs.",
            "0guard's wedge is not another agent memory app; it is the security/provenance layer agents should consult before signing.",
            "The submission should foreground public proof honesty: mainnet receipt anchoring exists, while live Storage upload and Compute inference remain explicitly out of scope.",
        ],
        "proofFirstChecklist": [
            "Show live /api/0g/status readback.",
            "Show /api/evaluate with 0G anchor/storage flags and the preflight receipt payload.",
            "Show /api/data/provenance?live=1 with source match counts and record hashes.",
            "Show the 0G mainnet contract address, anchor transaction, and readback proof.",
            "Show the public X post link and <=3 minute demo video link in the HackQuest form.",
        ],
        "0gIntegration": {
            "chain": (
                "PolicyReceiptAnchor is deployed on 0G mainnet and one deny receipt is anchored; "
                "the browser workbench remains read-only and produces reviewable preflight payloads."
            ),
            "storage": "Deterministic Storage-ready threat-intel receipts and root hashes.",
            "compute": "Planned 0G Compute anomaly scorer; not claimed as live inference today.",
            "agentIdentity": "Receipts can include agent_id for accountable agent sessions.",
            "crossChain": (
                "Virtuals/Base, x402, Arbitrum, Polygon, MegaETH, Monad, HyperEVM, Tempo, "
                "Lighter exchange/API, Chainlink CCIP, LayerZero V2, Wormhole NTT, and "
                "Celestia/TIA are exposed through a read-only integration fabric; live "
                "agent launch, settlement, exchange orders, exchange account "
                "actions, bridges, swaps, and signatures remain operator-only."
            ),
        },
        "dataProduct": {
            "incidentCount": summary["stats"]["incidentCount"],
            "totalLossUsd": summary["stats"]["totalLossUsd"],
            "datasetFingerprint": summary["validation"]["fingerprint"],
            "detectionCoverageRatio": coverage["coverageRatio"],
            "signatureGapCount": sig_map["gapCount"],
            "sourceRegistryCount": sources["sourceCount"],
            "provenanceCoverageRatioWithoutLiveFetch": provenance["coverage"][
                "evidenceCoverageRatio"
            ],
        },
        "autonomousWorkCompleted": [
            "Validated incident dataset and read-only coverage APIs.",
            "Rights-aware OSINT source registry and live signal normalization.",
            "Signature coverage map with recommended detector gaps.",
            "Incident provenance matrix with live DeFiLlama correlation support.",
            "Submission brief API for judge/operator readback.",
            "0G mainnet PolicyReceiptAnchor deployment and one anchored threat receipt.",
            "Read-only cross-chain integration catalog and Virtuals/Base facilitator manifest.",
            "Apache-2.0 repo posture with NOTICE, source/asset policy, and an explicit public asset registry that keeps submitted media archived behind the proof surface.",
        ],
        "operatorRequired": _operator_required_steps(),
        "claimsToAvoid": [
            "Do not claim live 0G Compute inference until a real router call is wired.",
            "Do not imply the browser can sign, trade, send Telegram messages, or move funds.",
            "Do not claim live Virtuals launch, x402 settlement, or Lighter trading/staking until an operator enables and verifies those paths.",
        ],
    }


def hackquest_submission_packet() -> dict[str, Any]:
    """Return copy-ready HackQuest fields plus remaining operator placeholders."""
    brief = hackathon_submission_brief()
    provenance = incident_provenance_matrix(live=False)
    mainnet_proof = _load_mainnet_proof()
    screenshot_path = "docs/hackathon-0g/assets/0guard-workbench-provenance.png"
    demo_script_path = "docs/hackathon-0g/final-demo-video-script.md"
    checklist_path = "docs/hackathon-0g/final-submission-checklist.md"
    repo_url = brief["project"]["repo"]
    public_demo_url = brief["project"]["publicDemo"]
    demo_video_url = _demo_video_url()
    x_post_url = _x_post_url()
    one_liner = HACKQUEST_ONE_LINER
    submission_proof = _load_hackquest_submission_proof()
    submission_ready = _hackquest_submission_ready(submission_proof)
    professionalization = brief["repoProfessionalization"]

    return {
        "schema": HACKQUEST_PACKET_SCHEMA,
        "generatedAt": _now(),
        "event": {
            "name": "0G APAC Hackathon",
            "host": "HackQuest",
            "officialUrl": HACKQUEST_OFFICIAL_URL,
            "deadline": brief["deadline"],
        },
        "readiness": {
            "ready": [
                "project_name",
                "one_line_description",
                "summary",
                "public_repo",
                "public_demo_page",
                "english_readme",
                "technical_docs",
                "demo_script",
                "x_post_draft",
                "screenshot_asset",
                "read_only_0g_status",
                "0g_mainnet_contract",
                "0g_mainnet_anchor_transaction",
                "receipt_preflight_payload",
                "storage_ready_root_hashes",
                "canonical_provenance_evidence",
                "readiness_audit",
                "threat_receipt_passport",
                "threat_receipt_passport_api",
                "apache_2_license",
                "notice_and_asset_policy",
                "asset_registry",
                "media_archive",
                *(
                    [
                        "hackquest_project_submitted",
                        "hackquest_public_readback_verified",
                    ]
                    if submission_ready
                    else []
                ),
            ],
            "operatorRequired": brief["operatorRequired"],
            "claimsToAvoid": brief["claimsToAvoid"],
            "readinessRoute": "/api/hackathon/readiness",
            "readinessCommand": ".venv/bin/python scripts/submission_readiness.py --format markdown",
        },
        "recommendedTrack": brief["trackRecommendation"]["primary"],
        "alternateTrack": brief["trackRecommendation"]["secondary"],
        "formFields": {
            "projectName": "0guard",
            "oneLineDescription": one_liner,
            "summary": (
                "0guard is a pre-wallet firewall for AI agents. It evaluates prompts, "
                "action mode, calldata, target contracts, domains, policy context, and "
                "incident-derived exploit intelligence before an agent can reach a "
                "signer. The product returns allow/review/deny verdicts, deterministic "
                "receipt hashes, a live 0G mainnet receipt anchor, and Storage-ready "
                "threat-intel root hashes. The workbench stays read-only and never "
                "holds keys, signs, broadcasts, trades, or sends Telegram messages."
            ),
            "problem": (
                "AI agents are gaining wallet and bridge tooling faster than their "
                "safety controls are maturing. Most security checks happen near signing "
                "time, after an agent has already formed a risky action. 0guard moves "
                "the review point earlier: intent first, signer later."
            ),
            "solution": (
                "0guard checks agent intent against deterministic policy rules, known "
                "exploit signatures, behavioral sequences, domain context, and "
                "source-cited incident intelligence. Risky actions are blocked before "
                "wallet custody begins, and every evaluation can become a tamper-evident "
                "receipt for 0G Chain and 0G Storage workflows."
            ),
            "0gIntegration": (
                "0guard uses 0G Chain for policy receipt anchoring, 0G Storage for "
                "portable threat-intel receipt payloads and root hashes, and a planned "
                "0G Compute layer for agent-risk anomaly scoring. Today the app reads "
                "0G status in read-only mode, has a deployed 0G mainnet "
                "PolicyReceiptAnchor with one anchored deny receipt, and returns "
                "deterministic Storage-ready root hashes without private keys or "
                "browser-side broadcasts."
            ),
            "repoUrl": repo_url,
            "publicDemoUrl": public_demo_url,
            "demoVideoUrl": demo_video_url,
            "xPostUrl": x_post_url,
            "0gContractAddress": (
                mainnet_proof.get("contract_address")
                if mainnet_proof
                else "OPERATOR_REQUIRED_0G_MAINNET_CONTRACT_ADDRESS"
            ),
            "0gExplorerUrl": (
                mainnet_proof.get("anchor_explorer_url")
                if mainnet_proof
                else "OPERATOR_REQUIRED_0G_MAINNET_EXPLORER_URL"
            ),
            "screenshotAsset": screenshot_path,
            "demoScript": demo_script_path,
            "finalChecklist": checklist_path,
            "threatReceiptPassport": "docs/hackathon-0g/threat-receipt-passport.md",
            "threatReceiptPassportApi": "/api/hackathon/threat-passport",
            "hackQuestProjectUrl": HACKQUEST_PUBLIC_PROJECT_URL,
            "hackQuestSubmissionProof": (
                "docs/hackathon-0g/hackquest-submission-proof.json"
            ),
            "license": professionalization["license"],
            "notice": "NOTICE",
            "sourceAndAssetPolicy": "docs/LEGAL_AND_ASSET_POLICY.md",
            "assetRegistry": "docs/hackathon-0g/assets/README.md",
            "mediaArchive": "docs/hackathon-0g/assets/README.md",
            "mediaArchiveUrl": professionalization["assetRegistryUrl"],
        },
        "hackQuestSubmission": brief["hackQuestSubmission"],
        "repoProfessionalization": professionalization,
        "proofPoints": [
            {
                "label": "Live 0G read proof",
                "route": "/api/0g/status",
                "claim": "Reads 0G chain status without private keys, signing, or broadcasts.",
            },
            {
                "label": "0G mainnet receipt anchor",
                "route": "docs/hackathon-0g/mainnet-proof.json",
                "claim": "Public 0G mainnet contract and anchor transaction for the deny receipt.",
            },
            {
                "label": "Receipt anchor preflight",
                "route": "/api/evaluate",
                "claim": "Returns the exact 0G Chain anchor payload when enable_0g_anchor=true.",
            },
            {
                "label": "Storage-ready root hash",
                "route": "/api/evaluate",
                "claim": "Returns deterministic threat-intel receipt payloads and root hashes.",
            },
            {
                "label": "Incident provenance",
                "route": "/api/data/provenance",
                "claim": (
                    f"{provenance['coverage']['withMatchedEvidence']}/"
                    f"{provenance['coverage']['incidentCount']} incidents have reviewed "
                    "derived source evidence without mirroring raw upstream payloads."
                ),
            },
            {
                "label": "Professional repo and media posture",
                "route": "docs/LEGAL_AND_ASSET_POLICY.md",
                "claim": (
                    "Repo license, source-rights policy, and public media archive are "
                    "explicit; proof surfaces lead with mainnet and API readbacks."
                ),
            },
        ],
        "xPost": {
            "threadFile": "content/hack_guard_thread.json",
            "singlePostFile": "content/hackquest_x_post.json",
            "mediaPath": screenshot_path,
            "requiredHashtags": brief["submissionRequirements"]["publicXPost"][
                "requiredHashtags"
            ],
            "requiredTags": brief["submissionRequirements"]["publicXPost"]["requiredTags"],
            "dryRunCommand": (
                ".venv/bin/python scripts/x_post.py --file "
                "content/hackquest_x_post.json --media "
                f"{screenshot_path} --dry-run --verbose"
            ),
            "threadDryRunCommand": (
                ".venv/bin/python scripts/x_post.py --file "
                "content/hack_guard_thread.json --thread --media "
                f"{screenshot_path} --dry-run --verbose"
            ),
            "liveCommand": (
                ".venv/bin/python scripts/x_post.py --file "
                "content/hackquest_x_post.json --media "
                f"{screenshot_path} --live-post-confirm POST_TO_X_FROM_0GUARD"
            ),
            "threadLiveCommand": (
                ".venv/bin/python scripts/x_post.py --file "
                "content/hack_guard_thread.json --thread --media "
                f"{screenshot_path} --live-post-confirm POST_TO_X_FROM_0GUARD"
            ),
        },
        "manualSubmitOrder": (
            [
                "Public readback already verifies isSubmit=true for the 0G APAC Hackathon.",
                "Monitor the public HackQuest project page and judge messages during review.",
            ]
            if submission_ready
            else [
                "Record and upload the <=3 minute demo video.",
                "Post the required X post with screenshot or short clip.",
                "Paste the formFields into HackQuest and attach repo/demo/X/0G proof links.",
                "Before final submit, re-open the public repo and Pages URL from an incognito window.",
            ]
        ),
        "safety": _osint_safety(),
    }


def threat_receipt_passport() -> dict[str, Any]:
    """Return the judge-facing proof drill as a single read-only API packet."""
    agent_id = "agent-7857-demo"
    sample_intent = {
        "action": "approve",
        "mode": "live_transaction",
        "requires_signature": True,
        "calldata": (
            "0x095ea7b3ffffffffffffffffffffffffffffffffffffffff"
            "ffffffffffffffffffffffff"
        ),
    }
    receipt = evaluate_intent(
        sample_intent,
        agent_id=agent_id,
        enable_0g_anchor=True,
        enable_0g_storage=True,
    ).to_dict()
    mainnet_proof = _load_mainnet_proof()
    provenance = incident_provenance_matrix(live=False)
    sig_map = signature_map()
    aggregate_only = [
        {
            "incidentId": row["incidentId"],
            "protocol": row["protocol"],
            "recommendedNextStep": row["recommendedNextStep"],
        }
        for row in provenance["rows"]
        if row["status"] == "aggregate_only"
    ]
    evidence_samples = []
    for row in provenance["rows"]:
        if not row["evidence"]:
            continue
        evidence = row["evidence"][0]
        evidence_samples.append(
            {
                "incidentId": row["incidentId"],
                "protocol": row["protocol"],
                "sourceUrl": evidence.get("sourceUrl"),
                "matchedName": evidence.get("matchedName"),
                "confidence": evidence.get("confidence"),
                "recordHash": evidence.get("recordHash"),
                "reviewStatus": evidence.get("canonicalReviewStatus")
                or evidence.get("cacheReviewStatus"),
            }
        )
        if len(evidence_samples) == 5:
            break

    signature_hits = [
        {
            "incidentId": row["incidentId"],
            "protocol": row["protocol"],
            "attackVector": row["attackVector"],
            "signaturesMatched": row["signaturesMatched"],
            "blockerCount": len(row["blockers"]),
            "warningCount": len(row["warnings"]),
        }
        for row in sig_map["rows"]
        if row["matched"]
    ][:5]

    return {
        "schema": THREAT_RECEIPT_PASSPORT_SCHEMA,
        "generatedAt": _now(),
        "purpose": (
            "A compact, falsifiable judge drill: agent intent in, safety verdict out, "
            "source evidence attached, receipt hash generated, and 0G proof slots explicit."
        ),
        "agentSession": agent_id,
        "sampleIntent": sample_intent,
        "receipt": {
            "decision": receipt["decision"],
            "severity": receipt["severity"],
            "receiptHash": receipt["receipt_hash"],
            "blockers": receipt["blockers"],
            "warnings": receipt["warnings"],
            "zeroG": receipt["zero_g"],
        },
        "provenance": {
            "datasetFingerprint": provenance["datasetFingerprint"],
            "sourceStatus": provenance["sourceStatus"],
            "coverage": provenance["coverage"],
            "evidenceSamples": evidence_samples,
            "aggregateOnlyGaps": aggregate_only,
        },
        "signatureCoverage": {
            "datasetFingerprint": sig_map["datasetFingerprint"],
            "incidentCount": sig_map["incidentCount"],
            "matchedCount": sig_map["matchedCount"],
            "gapCount": sig_map["gapCount"],
            "coverageRatio": sig_map["coverageRatio"],
            "topGaps": sig_map["topGaps"],
            "sampleHits": signature_hits,
        },
        "0gProofBoundary": {
            "currentStatus": (
                "mainnet_anchor_live_plus_read_only_workbench"
                if _mainnet_proof_ready(mainnet_proof)
                else "read_only_galileo_plus_preflight"
            ),
            "chainIdToday": receipt["zero_g"]["chain_anchor"]["chain_id"]
            if receipt["zero_g"].get("chain_anchor")
            else None,
            "chainAnchorStatus": receipt["zero_g"]["chain_anchor"]["status"]
            if receipt["zero_g"].get("chain_anchor")
            else None,
            "storageRootHash": (
                receipt["zero_g"].get("storage_receipt") or {}
            ).get("root_hash"),
            "hackquestFinalRequires": [
                "0G mainnet contract address",
                "0G Explorer URL with verifiable activity",
            ],
            "operatorPlaceholders": {
                "0gMainnetContractAddress": (
                    mainnet_proof.get("contract_address")
                    if mainnet_proof
                    else "OPERATOR_REQUIRED_0G_MAINNET_CONTRACT_ADDRESS"
                ),
                "0gExplorerUrl": (
                    mainnet_proof.get("anchor_explorer_url")
                    if mainnet_proof
                    else "OPERATOR_REQUIRED_0G_MAINNET_EXPLORER_URL"
                ),
                "anchorTransactionHash": (
                    mainnet_proof.get("anchor_tx_hash")
                    if mainnet_proof
                    else "OPERATOR_REQUIRED_ANCHOR_TRANSACTION_HASH"
                ),
            },
            "mainnetProof": mainnet_proof,
        },
        "reproduce": {
            "localServer": ".venv/bin/python -m guard0.app",
            "passportRoute": "curl -s http://127.0.0.1:8109/api/hackathon/threat-passport | python3 -m json.tool",
            "evaluateRoute": (
                "curl -s -X POST http://127.0.0.1:8109/api/evaluate "
                "-H 'Content-Type: application/json' "
                "-d '{\"intent\":{\"action\":\"approve\",\"mode\":\"live_transaction\","
                "\"requires_signature\":true,\"calldata\":\"0x095ea7b3ffffffffffffffff"
                "ffffffffffffffffffffffffffffffffffffffffffffffff\"},"
                "\"enable_0g_anchor\":true,\"enable_0g_storage\":true,"
                "\"agent_id\":\"agent-7857-demo\"}' | python3 -m json.tool"
            ),
            "provenanceRoute": "curl -s http://127.0.0.1:8109/api/data/provenance | python3 -m json.tool",
        },
        "claimsToAvoid": [
            "Do not claim live 0G Compute inference.",
            "Do not imply the browser can sign, broadcast, send Telegram messages, or move funds.",
        ],
        "safety": _osint_safety(),
    }


def hackquest_readiness_audit() -> dict[str, Any]:
    """Audit HackQuest submission readiness from local artifacts and runtime config."""
    cfg = get_0g_config()
    contract = str(cfg.get("receipt_contract") or ZERO_ADDRESS)
    contract_configured = contract.lower() != ZERO_ADDRESS.lower()
    mainnet_selected = int(cfg.get("chain_id", 0)) == ZGG_MAINNET_CHAIN_ID
    explorer_url = os.getenv("ZGG_RECEIPT_EXPLORER_URL") or os.getenv("ZGG_EXPLORER_URL") or ""
    proof = _load_mainnet_proof()
    proof_ready = _mainnet_proof_ready(proof)
    proof_contract = str(proof.get("contract_address", "")) if proof else ""
    proof_explorer = str(proof.get("anchor_explorer_url", "")) if proof else ""
    proof_anchor_tx = str(proof.get("anchor_tx_hash", "")) if proof else ""
    explorer_url_configured = bool(explorer_url) or bool(proof_explorer)
    submission_proof = _load_hackquest_submission_proof()
    submission_ready = _hackquest_submission_ready(submission_proof)
    mainnet_contract_ready = (mainnet_selected and contract_configured) or bool(proof_contract)
    mainnet_proof_ready = (mainnet_selected and contract_configured and bool(explorer_url)) or proof_ready
    demo_video_url = _demo_video_url()
    demo_video_ready = demo_video_url != DEMO_VIDEO_PLACEHOLDER
    x_post_url = _x_post_url()
    x_post_ready = x_post_url != X_POST_PLACEHOLDER
    x_post = _load_x_post_text(REPO_ROOT / "content" / "hackquest_x_post.json")
    x_thread = _load_x_post_text(REPO_ROOT / "content" / "hack_guard_thread.json")
    professionalization = _repo_professionalization_status()

    requirements = [
        _requirement(
            "project_info",
            "Basic project information",
            "ready" if _word_count(HACKQUEST_ONE_LINER) <= 30 else "needs_fix",
            [
                "Project name: 0guard",
                f"One-line description words: {_word_count(HACKQUEST_ONE_LINER)}/30",
            ],
            "Paste the provided project name, one-liner, and summary into HackQuest.",
        ),
        _requirement(
            "public_repo",
            "Public or judge-accessible repository",
            "ready",
            ["Repository: https://github.com/arigatoexpress/0guard"],
            "Confirm the GitHub repo is public or explicitly shared with judges.",
        ),
        _requirement(
            "0g_mainnet_contract",
            "0G mainnet contract address",
            "ready" if mainnet_contract_ready else "operator_required",
            [
                f"Configured chain ID: {cfg.get('chain_id')}",
                f"Required chain ID: {ZGG_MAINNET_CHAIN_ID}",
                f"Configured contract: {contract}",
                f"Proof file contract: {proof_contract or 'not_found'}",
            ],
            (
                "Use docs/hackathon-0g/mainnet-proof.json and the 0G contract URL in HackQuest."
                if mainnet_contract_ready
                else (
                    "Deploy PolicyReceiptAnchor on 0G mainnet, then set "
                    "ZGG_CHAIN_ID=16661, ZGG_CHAIN_RPC=https://evmrpc.0g.ai, "
                    "and ZGG_RECEIPT_CONTRACT."
                )
            ),
        ),
        _requirement(
            "0g_mainnet_explorer",
            "0G Explorer link with verifiable activity",
            "ready" if mainnet_proof_ready else "operator_required",
            [
                f"Explorer URL env configured: {bool(explorer_url)}",
                f"Proof file explorer URL: {proof_explorer or 'not_found'}",
                f"Expected explorer: {ZGG_MAINNET_EXPLORER}",
            ],
            (
                "Use the anchored receipt transaction URL from docs/hackathon-0g/mainnet-proof.json."
                if mainnet_proof_ready
                else "Anchor at least one receipt and save the 0G mainnet explorer transaction URL."
            ),
        ),
        _requirement(
            "demo_video",
            "Public demo video, 3 minutes or less",
            "ready" if demo_video_ready else "operator_required",
            [
                "Recording script: docs/hackathon-0g/final-demo-video-script.md",
                f"Video URL: {demo_video_url}",
            ],
            (
                "Use the generated public demo video URL in HackQuest."
                if demo_video_ready
                else "Record the live product flow and upload a public YouTube or Loom link."
            ),
        ),
        _requirement(
            "readme_docs",
            "README and technical documentation",
            "ready" if _paths_exist("README.md", "docs/hackathon-0g/README.md") else "needs_fix",
            [
                "README.md",
                "docs/hackathon-0g/README.md",
                "docs/hackathon-0g/submission-form-fields.md",
            ],
            "Keep the README and docs aligned with the current mainnet proof boundary.",
        ),
        _requirement(
            "public_x_post",
            "Public X post with required tags, hashtags, and media",
            "ready" if x_post_ready else "operator_required",
            [
                "Draft: content/hackquest_x_post.json",
                f"Draft length: {len(x_post)}/280",
                f"Required tags present: {_contains_all(x_post + x_thread, HACKQUEST_REQUIRED_TAGS)}",
                (
                    "Required hashtags present: "
                    f"{_contains_all(x_post + x_thread, HACKQUEST_REQUIRED_HASHTAGS)}"
                ),
                f"X post URL: {x_post_url}",
                "Media: docs/hackathon-0g/assets/0guard-workbench-provenance.png",
            ],
            (
                "Use the public X post URL in HackQuest."
                if x_post_ready
                else "Post the prepared draft with the screenshot or demo clip, then paste the X URL."
            ),
        ),
        _requirement(
            "proof_packet",
            "Copy-ready submission packet",
            "ready",
            [
                "/api/hackathon/submission-packet",
                "docs/hackathon-0g/submission-form-fields.md",
                "docs/hackathon-0g/final-submission-checklist.md",
            ],
            "Use the packet as the final form source of truth.",
        ),
        _requirement(
            "repo_professionalization",
            "License, asset policy, and media archive",
            "ready" if professionalization["ready"] else "needs_fix",
            [
                f"License: {professionalization['license']}",
                "NOTICE",
                "docs/LEGAL_AND_ASSET_POLICY.md",
                "docs/hackathon-0g/assets/README.md",
            ],
            "Keep Apache-2.0, NOTICE, source/asset policy, and asset registry public; keep generated media secondary to proof readbacks.",
        ),
        _requirement(
            "provenance_data",
            "Source-aware OSINT/provenance evidence",
            "ready",
            [
                "/api/data/provenance",
                "/api/data/provenance?live=1",
                "data/incident_provenance_cache.json",
            ],
            "Show provenance counts and raw-payload safety in the demo.",
        ),
        _requirement(
            "safety_boundary",
            "No secret, signing, send, or money-movement path in the workbench",
            "ready",
            ["/api/external-action-contracts", "/api/frontend-contract"],
            "Keep all live actions outside the browser workbench and operator-confirmed.",
        ),
        _requirement(
            "hackquest_submission",
            "HackQuest final project submission",
            "ready" if submission_ready else "operator_required",
            [
                f"Project URL: {HACKQUEST_PUBLIC_PROJECT_URL}",
                f"Project ID: {HACKQUEST_PROJECT_ID}",
                f"Hackathon ID: {HACKQUEST_HACKATHON_ID}",
                "Proof file: docs/hackathon-0g/hackquest-submission-proof.json",
                f"Proof loaded: {bool(submission_proof)}",
            ],
            (
                "No form work remains; monitor public project page and judge messages."
                if submission_ready
                else "Submit the HackQuest form with repo, demo, X URL, and 0G proof."
            ),
        ),
    ]
    counts: dict[str, int] = {}
    for requirement in requirements:
        counts[requirement["status"]] = counts.get(requirement["status"], 0) + 1

    blockers = [
        item
        for item in requirements
        if item["status"] in {"operator_required", "needs_fix"}
    ]
    return {
        "schema": HACKQUEST_READINESS_SCHEMA,
        "generatedAt": _now(),
        "event": {
            "name": "0G APAC Hackathon",
            "officialUrl": HACKQUEST_OFFICIAL_URL,
            "publicProjectUrl": HACKQUEST_PUBLIC_PROJECT_URL,
            "projectId": HACKQUEST_PROJECT_ID,
            "hackathonId": HACKQUEST_HACKATHON_ID,
            "deadline": {
                "utc8": HACKQUEST_DEADLINE_UTC8,
                "denver": HACKQUEST_DEADLINE_MDT,
            },
        },
        "mainnetRequirement": {
            "chainId": ZGG_MAINNET_CHAIN_ID,
            "rpc": ZGG_MAINNET_RPC,
            "explorer": ZGG_MAINNET_EXPLORER,
            "storageExplorer": ZGG_STORAGE_SCAN,
            "note": "HackQuest requires a 0G mainnet contract address and explorer proof.",
        },
        "current0GConfig": {
            "rpc": cfg.get("rpc"),
            "chainId": cfg.get("chain_id"),
            "receiptContract": contract,
            "mainnetSelected": mainnet_selected,
            "receiptContractConfigured": contract_configured,
            "explorerUrlConfigured": explorer_url_configured,
            "mainnetProofFile": str(DEFAULT_MAINNET_PROOF_PATH.relative_to(REPO_ROOT)),
            "mainnetProofLoaded": bool(proof),
            "mainnetProofReady": proof_ready,
            "mainnetProofContract": proof_contract or None,
            "mainnetProofExplorerUrl": proof_explorer or None,
            "mainnetProofAnchorTxHash": proof_anchor_tx or None,
        },
        "hackQuestSubmission": {
            "submitted": submission_ready,
            "proofFile": str(
                DEFAULT_HACKQUEST_SUBMISSION_PROOF_PATH.relative_to(REPO_ROOT)
            ),
            "verifiedAt": submission_proof.get("verified_at") if submission_proof else None,
            "projectUrl": HACKQUEST_PUBLIC_PROJECT_URL,
        },
        "repoProfessionalization": professionalization,
        "submittableNow": len(blockers) == 0,
        "statusCounts": counts,
        "requirements": requirements,
        "operatorBlockers": [
            {
                "id": item["id"],
                "label": item["label"],
                "operatorAction": item["operatorAction"],
            }
            for item in blockers
        ],
        "safeAutonomousWorkRemaining": [
            "Keep source/provenance docs current if official requirements change.",
            "Run the readiness audit, tests, browser smoke, and public readbacks during review.",
            "Replace the submitted video or X link only if Ari wants a later edited version.",
            "Keep any future media replacement grounded in real product capture and mainnet proof readbacks.",
        ],
        "operatorOnlyActions": []
        if submission_ready
        else ["Submit the HackQuest form."],
        "sources": [
            HACKQUEST_OFFICIAL_URL,
            "https://docs.0g.ai/developer-hub/mainnet/mainnet-overview",
        ],
        "safety": _osint_safety(),
    }


def _fetch_url(url: str, *, timeout_seconds: float, max_bytes: int) -> FetchResult:
    started = time.perf_counter()
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                body = body[:max_bytes]
            return FetchResult(
                ok=200 <= response.status < 400,
                status_code=response.status,
                url=response.geturl(),
                content_type=response.headers.get("content-type", ""),
                elapsed_ms=int((time.perf_counter() - started) * 1000),
                body=body,
            )
    except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
        return FetchResult(
            ok=False,
            status_code=getattr(getattr(exc, "code", None), "value", None),
            url=url,
            content_type="",
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            body=b"",
            error=f"{type(exc).__name__}: {exc}",
        )


def _normalize_defillama_hacks(
    source: dict[str, Any],
    body: bytes,
    *,
    limit: int,
) -> list[dict[str, Any]]:
    try:
        records = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(records, list):
        return []
    records = sorted(records, key=lambda item: item.get("date") or 0, reverse=True)[:limit]
    normalized = []
    for record in records:
        if not isinstance(record, dict):
            continue
        observed_at = _unix_to_iso(record.get("date"))
        signal = {
            "schema": "0guard.osint_signal.v1",
            "sourceId": source["id"],
            "sourceOwner": source["owner"],
            "sourceUrl": source["url"],
            "retrievalMode": source["retrieval_mode"],
            "rightsEnvelope": source["license_or_rights"],
            "outputPolicy": source["output_policy"],
            "observedAt": observed_at,
            "signalType": "crypto_incident",
            "title": str(record.get("name") or "Unnamed incident").strip(),
            "amountUsd": record.get("amount"),
            "chains": record.get("chain") or [],
            "classification": record.get("classification"),
            "technique": record.get("technique"),
            "targetType": record.get("targetType"),
            "bridgeHack": bool(record.get("bridgeHack")),
            "sourceLink": record.get("source") or source["homepage"],
        }
        signal["recordHash"] = _record_hash(signal)
        normalized.append(signal)
    return normalized


def _normalize_rss_items(
    source: dict[str, Any],
    body: bytes,
    *,
    limit: int,
) -> list[dict[str, Any]]:
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return []
    items = root.findall(".//channel/item")[:limit]
    normalized = []
    for item in items:
        title = _xml_text(item, "title")
        link = _xml_text(item, "link")
        pub_date = _xml_text(item, "pubDate")
        categories = [_clean_text(category.text) for category in item.findall("category")]
        signal = {
            "schema": "0guard.osint_signal.v1",
            "sourceId": source["id"],
            "sourceOwner": source["owner"],
            "sourceUrl": source["url"],
            "retrievalMode": source["retrieval_mode"],
            "rightsEnvelope": source["license_or_rights"],
            "outputPolicy": source["output_policy"],
            "observedAt": _parse_rss_datetime(pub_date),
            "signalType": "research_link",
            "title": title,
            "link": link,
            "categories": [value for value in categories if value],
            "securityRelevant": _security_relevant(title, categories),
        }
        signal["recordHash"] = _record_hash(signal)
        normalized.append(signal)
    return normalized


def _defillama_evidence_for_incident(
    incident: dict[str, Any],
    records: list[dict[str, Any]],
) -> dict[str, Any] | None:
    best: tuple[float, dict[str, Any]] | None = None
    for record in records:
        score = _defillama_match_score(incident, record)
        if score < 0.62:
            continue
        if best is None or score > best[0]:
            best = (score, record)
    if best is None:
        return None

    score, record = best
    source_url = record.get("source") or "https://defillama.com/hacks"
    evidence = {
        "sourceId": "defillama_hacks",
        "sourceOwner": "DeFiLlama",
        "sourceUrl": source_url,
        "evidenceType": "public_incident_index",
        "matchedName": record.get("name"),
        "observedDate": _unix_to_iso(record.get("date")),
        "amountUsd": record.get("amount"),
        "chains": record.get("chain") or [],
        "classification": record.get("classification"),
        "technique": record.get("technique"),
        "targetType": record.get("targetType"),
        "bridgeHack": bool(record.get("bridgeHack")),
        "confidence": round(min(score, 1.0), 4),
        "rightsEnvelope": (
            "Public API metadata. Use as source-cited defensive evidence; do not mirror raw dumps."
        ),
    }
    evidence["recordHash"] = _record_hash(evidence)
    return evidence


def _load_provenance_cache(
    *,
    cache_path: str | Path | None = None,
) -> dict[int, dict[str, Any]]:
    path = Path(cache_path) if cache_path else DEFAULT_PROVENANCE_CACHE_PATH
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as handle:
        cache = json.load(handle)
    if cache.get("schema") != PROVENANCE_CACHE_SCHEMA:
        raise ValueError(f"unexpected provenance cache schema: {cache.get('schema')}")
    records = cache.get("records")
    if not isinstance(records, list):
        raise ValueError("provenance cache records must be a list")

    indexed: dict[int, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        incident_id = record.get("incidentId")
        evidence = record.get("evidence")
        if not isinstance(incident_id, int) or not isinstance(evidence, dict):
            continue
        indexed[incident_id] = {
            **evidence,
            "cacheReviewStatus": record.get("reviewStatus", "derived_unreviewed"),
            "cacheGeneratedAt": cache.get("generatedAt"),
        }
    return indexed


def _canonical_evidence_for_incident(incident: dict[str, Any]) -> dict[str, Any] | None:
    records = incident.get("derived_source_evidence")
    if not isinstance(records, list) or not records:
        return None
    record = next((item for item in records if isinstance(item, dict)), None)
    if not record:
        return None
    confidence = record.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, int | float):
        confidence = 0.0
    evidence = {
        "sourceId": record.get("source_id"),
        "sourceOwner": record.get("source_owner"),
        "sourceUrl": record.get("source_url"),
        "evidenceType": record.get("evidence_type"),
        "matchedName": record.get("matched_name"),
        "observedDate": record.get("observed_date"),
        "confidence": float(confidence),
        "recordHash": record.get("record_hash"),
        "rightsEnvelope": record.get("rights_envelope"),
        "canonicalReviewStatus": record.get("review_status"),
        "canonicalDatasetEvidence": True,
    }
    return {key: value for key, value in evidence.items() if value is not None}


def _defillama_match_score(incident: dict[str, Any], record: dict[str, Any]) -> float:
    incident_name = _normalize_name(incident.get("protocol"))
    record_name = _normalize_name(record.get("name"))
    aliases = DEFILLAMA_INCIDENT_ALIASES.get(incident_name, set())
    score = 0.0

    if incident_name and incident_name == record_name:
        score += 0.52
    elif record_name in aliases:
        score += 0.52
    elif incident_name and (incident_name in record_name or record_name in incident_name):
        score += 0.38

    incident_loss = incident.get("loss_usd")
    record_amount = record.get("amount")
    if _numbers_close(incident_loss, record_amount):
        score += 0.24
    elif _numbers_close(incident_loss, record_amount, tolerance=0.12):
        score += 0.16

    if incident.get("date") == _unix_to_iso(record.get("date")):
        score += 0.16

    incident_chain = _normalize_name(incident.get("chain"))
    record_chains = {_normalize_name(chain) for chain in (record.get("chain") or [])}
    if incident_chain and incident_chain in record_chains:
        score += 0.08
    elif incident_chain == "multichain" and len(record_chains) > 1:
        score += 0.06

    return score


def _provenance_next_step(incident: dict[str, Any], evidence: dict[str, Any] | None) -> str:
    if evidence and evidence.get("canonicalDatasetEvidence"):
        return "Add protocol postmortem, transaction, or security-report URL when available."
    if evidence and evidence["confidence"] >= 0.85:
        return "Add incident-specific source URL/evidence_type/confidence to the canonical dataset."
    if evidence:
        return "Review the matched source candidate before promoting it into canonical provenance."
    if str(incident.get("attack_vector", "")).lower() == "undisclosed":
        return "Wait for a postmortem or trusted incident writeup before adding detector-specific claims."
    return "Find a protocol postmortem, security report, transaction, or trusted incident index entry."


def _signature_gap_for_incident(incident: dict[str, Any]) -> str:
    vector = str(incident.get("attack_vector") or "").lower()
    text = f"{vector} {incident.get('description', '')}".lower()
    if "undisclosed" in vector:
        return "insufficient_public_root_cause"
    if "donate" in text or "negative" in text:
        return "signed_amount_or_accounting_invariant"
    if "burn" in text or "accounting" in text:
        return "token_accounting_invariant"
    if "signedness" in text or "math" in text:
        return "numeric_type_or_math_invariant"
    if "gateway" in text or "cross-chain" in text:
        return "cross_chain_gateway_invariant"
    if "otc" in text or "settlement" in text:
        return "settlement_atomicity_invariant"
    return "generic_detector_gap"


def _recommended_detector_for_incident(incident: dict[str, Any], matched: bool) -> str | None:
    if matched:
        return None
    gap = _signature_gap_for_incident(incident)
    recommendations = {
        "insufficient_public_root_cause": (
            "Keep as review-only until a source URL or postmortem identifies calldata or behavior."
        ),
        "signed_amount_or_accounting_invariant": (
            "Add invariant checks for negative amounts, unsigned casts, and impossible balance deltas."
        ),
        "token_accounting_invariant": (
            "Add burn/mint accounting detectors for balance supply drift and repeated refund claims."
        ),
        "numeric_type_or_math_invariant": (
            "Add signed/unsigned and bounded-math detectors for settlement and perp accounting."
        ),
        "cross_chain_gateway_invariant": (
            "Add gateway pause, nonce, and replay-proof checks for cross-chain messages."
        ),
        "settlement_atomicity_invariant": (
            "Add atomic settlement and escrow-mode checks before OTC-style transfers."
        ),
    }
    return recommendations.get(gap, "Add a source-specific detector after provenance enrichment.")


def _top_gap_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        gap = row.get("gap")
        if gap:
            counts[gap] = counts.get(gap, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _detector_family_summary(sig_map: dict[str, Any]) -> list[dict[str, Any]]:
    family_rules = {
        "ioc_and_address": ("critical_selector:", "soceng:", "durable_nonce", "drain_language"),
        "calldata_signature": ("critical_selector:", "unlimited_approval", "flash_loan_init"),
        "behavior_sequence": ("sequence_", "risk_pair:"),
        "bridge_and_da": ("bridge_", "single_dvn", "sequence_bridge"),
        "accounting_and_numeric": (
            "negative_amount_invariant",
            "token_accounting_invariant",
            "numeric_type_invariant",
            "router_quote_denomination_invariant",
        ),
        "oracle_and_market": ("oracle_", "price_deviation", "sequence_oracle"),
        "governance_and_upgrade": ("governance_", "sequence_grant", "sequence_timelock"),
        "wallet_opsec": ("hot_wallet_opsec_context",),
    }
    rows = sig_map.get("rows") or []
    summary = []
    for family_id, prefixes in family_rules.items():
        matched_rows = []
        signatures = set()
        for row in rows:
            row_sigs = row.get("signaturesMatched") or []
            if not isinstance(row_sigs, list):
                continue
            family_hits = [
                sig for sig in row_sigs if any(str(sig).startswith(prefix) for prefix in prefixes)
            ]
            if family_hits:
                matched_rows.append(row)
                signatures.update(str(sig) for sig in family_hits)
        summary.append(
            {
                "id": family_id,
                "matchedIncidentCount": len(matched_rows),
                "sampleSignatures": sorted(signatures)[:5],
                "alertEligible": family_id in {
                    "calldata_signature",
                    "behavior_sequence",
                    "bridge_and_da",
                    "accounting_and_numeric",
                    "governance_and_upgrade",
                    "wallet_opsec",
                },
            }
        )
    return summary


def _emerging_detector_queue(sig_map: dict[str, Any]) -> list[dict[str, Any]]:
    rows = sig_map.get("rows") or []
    queue = []
    for gap, count in _top_gap_counts(rows).items():
        examples = [
            {
                "incidentId": row.get("incidentId"),
                "protocol": row.get("protocol"),
                "attackVector": row.get("attackVector"),
                "recommendedDetector": row.get("recommendedDetector"),
            }
            for row in rows
            if row.get("gap") == gap
        ][:3]
        queue.append(
            {
                "gap": gap,
                "incidentCount": count,
                "priority": _detector_gap_priority(gap),
                "status": "research_required"
                if gap == "insufficient_public_root_cause"
                else "detector_candidate",
                "examples": examples,
            }
        )
    return queue


def _detector_gap_priority(gap: str) -> str:
    if gap in {"cross_chain_gateway_invariant", "settlement_atomicity_invariant"}:
        return "high"
    if gap in {
        "signed_amount_or_accounting_invariant",
        "token_accounting_invariant",
        "numeric_type_or_math_invariant",
    }:
        return "medium"
    return "watch"


def _zero_g_suite_map(
    mainnet_proof: dict[str, Any] | None,
    evidence_root: str,
    signal_source_ids: list[str],
) -> dict[str, Any]:
    mainnet_ready = _mainnet_proof_ready(mainnet_proof)
    return {
        "chain": {
            "status": "mainnet_anchor_live" if mainnet_ready else "preflight_ready",
            "chainId": ZGG_MAINNET_CHAIN_ID,
            "contractAddress": mainnet_proof.get("contract_address") if mainnet_proof else None,
            "anchorExplorerUrl": mainnet_proof.get("anchor_explorer_url") if mainnet_proof else None,
            "readableEventFields": [
                "receiptHash",
                "decision",
                "severity",
                "agentId",
                "timestamp",
                "submitter",
            ],
            "readableV2Ready": {
                "contract": "contracts/PolicyReceiptAnchorV2.sol",
                "memoFields": ["policyVersion", "shortMemo", "sourceIds"],
                "hashFields": ["datasetFingerprint", "evidenceRoot", "storageRoot"],
                "liveDeployed": False,
            },
        },
        "storage": {
            "status": "storage_ready_root_hashes",
            "currentRootHash": evidence_root,
            "payloadPolicy": "derived_metadata_links_hashes_and_defensive_analysis",
            "officialSource": "https://docs.0g.ai/developer-hub/building-on-0g/storage/sdk",
        },
        "da": {
            "status": "planned_batch_availability_layer",
            "currentUse": "not_live_claimed",
            "candidatePayloads": ["detector bundle roots", "provenance matrix roots"],
            "officialSource": "https://docs.0g.ai/concepts/da",
        },
        "compute": {
            "status": "planned_no_live_inference_claim",
            "candidateUse": "behavioral anomaly scoring beside deterministic policy checks",
            "guardrail": "Compute output can suggest review, but deterministic blockers stay auditable.",
            "officialSource": (
                "https://docs.0g.ai/developer-hub/building-on-0g/compute-network/overview"
            ),
        },
        "sourceIdsInCurrentLoop": signal_source_ids,
    }


def _public_source_fields(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": source["id"],
        "name": source["name"],
        "owner": source["owner"],
        "url": source["url"],
        "homepage": source.get("homepage"),
        "retrievalMode": source["retrieval_mode"],
        "adapter": source["adapter"],
        "enabledByDefault": bool(source.get("enabled_by_default")),
        "freshnessTtlSeconds": source["freshness_ttl_seconds"],
        "licenseOrRights": source["license_or_rights"],
        "outputPolicy": source["output_policy"],
        "caveats": source.get("caveats", ""),
    }


def _requirement(
    requirement_id: str,
    label: str,
    status: str,
    evidence: list[str],
    operator_action: str,
) -> dict[str, Any]:
    return {
        "id": requirement_id,
        "label": label,
        "requiredByHackQuest": True,
        "status": status,
        "evidence": evidence,
        "operatorAction": operator_action,
    }


def _paths_exist(*paths: str) -> bool:
    return all((REPO_ROOT / path).exists() for path in paths)


def _load_mainnet_proof(path: Path = DEFAULT_MAINNET_PROOF_PATH) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _mainnet_proof_ready(proof: dict[str, Any] | None) -> bool:
    if not proof:
        return False
    contract = str(proof.get("contract_address") or "")
    anchor_url = str(proof.get("anchor_explorer_url") or "")
    receipt_hash = str(proof.get("anchored_receipt_hash") or "")
    return (
        int(proof.get("chain_id") or 0) == ZGG_MAINNET_CHAIN_ID
        and contract.startswith("0x")
        and len(contract) == 42
        and anchor_url.startswith(ZGG_MAINNET_EXPLORER)
        and receipt_hash.startswith("0x")
        and len(receipt_hash) == 66
    )


def _load_hackquest_submission_proof(
    path: Path = DEFAULT_HACKQUEST_SUBMISSION_PROOF_PATH,
) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _hackquest_submission_ready(proof: dict[str, Any] | None) -> bool:
    if not proof:
        return False
    project = proof.get("project") or {}
    hackathon = proof.get("hackathon") or {}
    submission = proof.get("submission") or {}
    return (
        project.get("id") == HACKQUEST_PROJECT_ID
        and hackathon.get("id") == HACKQUEST_HACKATHON_ID
        and submission.get("is_submit") is True
        and str(submission.get("contract_address") or "").lower()
        == "0xbac59b1571b7c7195915c5b36d8a719ed7182abc"
        and str(submission.get("mainnet_anchor_tx") or "").startswith(ZGG_MAINNET_EXPLORER)
    )


def _demo_video_url() -> str:
    configured = os.getenv("HACKQUEST_DEMO_VIDEO_URL", "").strip()
    if configured:
        return configured
    if DEFAULT_DEMO_VIDEO_PATH.exists():
        return PUBLIC_DEMO_VIDEO_URL
    submission_proof = _load_hackquest_submission_proof()
    submitted_video = (
        (submission_proof or {}).get("submission", {}).get("demo_video", "")
        if submission_proof
        else ""
    )
    if str(submitted_video).startswith("https://"):
        return str(submitted_video)
    return DEMO_VIDEO_PLACEHOLDER


def _repo_professionalization_status() -> dict[str, Any]:
    license_text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
    pyproject_text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    solidity_sources = [
        REPO_ROOT / "contracts" / "PolicyReceiptAnchor.sol",
        REPO_ROOT / "contracts" / "PolicyReceiptAnchorV2.sol",
        REPO_ROOT / "foundry" / "src" / "PolicyReceiptAnchor.sol",
    ]
    expected_paths = [
        REPO_ROOT / "NOTICE",
        DEFAULT_LEGAL_POLICY_PATH,
        DEFAULT_ASSET_REGISTRY_PATH,
    ]
    apache_license = (
        "Apache License" in license_text
        and 'license = {text = "Apache-2.0"}' in pyproject_text
    )
    solidity_spdx = all(
        path.exists()
        and path.read_text(encoding="utf-8").startswith(
            "// SPDX-License-Identifier: Apache-2.0"
        )
        for path in solidity_sources
    )
    required_docs_ready = all(path.exists() for path in expected_paths)
    return {
        "schema": "0guard.repo_professionalization.v1",
        "ready": bool(apache_license and solidity_spdx and required_docs_ready),
        "license": "Apache-2.0" if apache_license else "needs_review",
        "noticePath": "NOTICE",
        "noticeUrl": PUBLIC_NOTICE_URL,
        "sourceAndAssetPolicyPath": "docs/LEGAL_AND_ASSET_POLICY.md",
        "sourceAndAssetPolicyUrl": PUBLIC_LEGAL_POLICY_URL,
        "assetRegistryPath": "docs/hackathon-0g/assets/README.md",
        "assetRegistryUrl": PUBLIC_ASSET_REGISTRY_URL,
        "archivedGeneratedMediaPacketPath": "docs/hackathon-0g/veo3-flow-production-prompt.md",
        "archivedGeneratedMediaPacketUrl": PUBLIC_VEO_PACKET_URL,
        "generatedMediaPubliclyPromoted": False,
        "soliditySpdxAligned": solidity_spdx,
        "generatedResidueTracked": False,
        "mediaReplacementPolicy": (
            "Submitted and generated media stays archived behind proof links. Replace "
            "public media only after manual review confirms real product capture, no "
            "fake external actions, no private data, and readable proof overlays."
        ),
    }


def _x_post_url() -> str:
    configured = os.getenv("HACKQUEST_X_POST_URL", "").strip()
    return configured or PUBLIC_X_POST_URL


def _operator_required_steps() -> list[str]:
    steps = []
    if _demo_video_url() == DEMO_VIDEO_PLACEHOLDER:
        steps.append("Record and upload the <=3 minute demo video.")
    if _x_post_url() == X_POST_PLACEHOLDER:
        steps.append("Post public X post with required HackQuest tags.")
    if not _hackquest_submission_ready(_load_hackquest_submission_proof()):
        steps.append("Submit HackQuest form with repo, demo video, X URL, and 0G proof.")
    return steps


def _word_count(value: str) -> int:
    return len([word for word in value.split() if word.strip()])


def _contains_all(haystack: str, needles: list[str]) -> bool:
    return all(needle in haystack for needle in needles)


def _load_x_post_text(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return path.read_text(encoding="utf-8")
    if isinstance(payload, dict):
        if isinstance(payload.get("text"), str):
            return payload["text"]
        if isinstance(payload.get("tweets"), list):
            return "\n".join(str(item) for item in payload["tweets"])
    if isinstance(payload, list):
        return "\n".join(str(item) for item in payload)
    return str(payload)


def _osint_safety() -> dict[str, Any]:
    return {
        "readOnly": True,
        "credentialsRequiredForDefaultSources": False,
        "rawPayloadsReturned": False,
        "privatePersonDossiering": False,
        "exploitPayloadsReturned": False,
        "outputMode": "metadata_links_hashes_and_defensive_analysis",
    }


def _record_hash(record: dict[str, Any]) -> str:
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _unix_to_iso(value: Any) -> str | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return datetime.fromtimestamp(value, tz=timezone.utc).date().isoformat()


def _parse_rss_datetime(value: str) -> str | None:
    if not value:
        return None
    try:
        return parsedate_to_datetime(value).astimezone(timezone.utc).replace(microsecond=0).isoformat()
    except (TypeError, ValueError, IndexError, OverflowError):
        return None


def _xml_text(item: ElementTree.Element, field: str) -> str:
    found = item.find(field)
    return _clean_text(found.text if found is not None else "")


def _clean_text(value: str | None) -> str:
    return " ".join(str(value or "").split())


def _normalize_name(value: Any) -> str:
    import re

    return re.sub(r"[^a-z0-9]+", "", str(value or "").lower())


def _numbers_close(left: Any, right: Any, *, tolerance: float = 0.015) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return False
    if not isinstance(left, int | float) or not isinstance(right, int | float):
        return False
    if left == right:
        return True
    larger = max(abs(float(left)), abs(float(right)), 1.0)
    return abs(float(left) - float(right)) / larger <= tolerance


def _security_relevant(title: str, categories: list[str]) -> bool:
    haystack = " ".join([title, *categories]).lower()
    terms = (
        "crime",
        "hack",
        "exploit",
        "stolen",
        "scam",
        "sanction",
        "threat",
        "security",
        "fraud",
    )
    return any(term in haystack for term in terms)
