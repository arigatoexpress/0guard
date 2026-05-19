"""Reviewed live connector workers for reputation feeds.

Workers fetch only explicitly reviewed public sources, then immediately reduce
the payload into derived evidence, hashes, counts, and source metadata. Public
responses never return raw feed rows.
"""

from __future__ import annotations

import hashlib
import csv
import io
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

REPUTATION_CONNECTOR_SNAPSHOT_SCHEMA = "0guard.reputation_connector_snapshot.v1"
PHISHDESTROY_SOURCE_ID = "phishdestroy_destroylist"
PHISHDESTROY_ACTIVE_DOMAINS_URL = (
    "https://raw.githubusercontent.com/phishdestroy/destroylist/main/dns/active_domains.json"
)
PHISHDESTROY_PUBLIC_SOURCE_URL = "https://phishdestroy.io/dataset"
CISA_KEV_SOURCE_ID = "cisa_kev"
CISA_KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_PUBLIC_SOURCE_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
NVD_CVE_SOURCE_ID = "nvd_cve"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CVE_PUBLIC_SOURCE_URL = "https://nvd.nist.gov/developers/vulnerabilities"
OFAC_SANCTIONS_SOURCE_ID = "ofac_sanctions"
OFAC_SANCTIONS_FEED_URL = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV"
OFAC_SANCTIONS_PUBLIC_SOURCE_URL = "https://ofac.treasury.gov/sanctions-list-service"
USER_AGENT = "0guard-osint/0.1 (+https://github.com/arigatoexpress/0guard)"
MAX_PHISHDESTROY_BYTES = 5_000_000
MAX_CISA_KEV_BYTES = 8_000_000
MAX_NVD_CVE_BYTES = 8_000_000
MAX_OFAC_SANCTIONS_BYTES = 24_000_000
EVM_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")


def phishdestroy_active_domains_snapshot(
    *,
    live: bool = False,
    limit: int = 5,
    subject_url: str = "",
    timeout_seconds: float = 6.0,
) -> dict[str, Any]:
    """Fetch and reduce the PhishDestroy active-domain feed."""
    from guard0.reputation_adapters import normalize_reputation_adapter_payload

    if limit < 1 or limit > 50:
        raise ValueError("limit must be between 1 and 50")

    subject_domain = _domain_from_url(subject_url)
    if not live:
        return _not_fetched_snapshot(limit=limit, subject_domain=subject_domain)

    fetched = _fetch_url(
        PHISHDESTROY_ACTIVE_DOMAINS_URL,
        timeout_seconds=timeout_seconds,
        max_bytes=MAX_PHISHDESTROY_BYTES,
    )
    if not fetched["ok"]:
        return _degraded_snapshot(fetched, limit=limit, subject_domain=subject_domain)

    domains = _decode_domain_list(fetched["body"])
    unique_domains = sorted({domain for domain in domains if domain})
    matched = subject_domain in set(unique_domains) if subject_domain else None
    sample_domains = (
        [subject_domain]
        if matched is True
        else unique_domains[:limit]
    )
    adapter_payload = {
        "sourceId": PHISHDESTROY_SOURCE_ID,
        "subject": {"url": subject_url} if subject_url else {},
        "payload": {
            "active_domains": [
                {
                    "domain": domain,
                    "site_status": "active",
                    "source": PHISHDESTROY_PUBLIC_SOURCE_URL,
                }
                for domain in sample_domains
            ]
        },
    }
    normalized = normalize_reputation_adapter_payload(adapter_payload)
    body_hash = _hash_bytes(fetched["body"])
    snapshot_hash = _hash_json(
        {
            "sourceId": PHISHDESTROY_SOURCE_ID,
            "bodyHash": body_hash,
            "domainCount": len(unique_domains),
            "sampleHashes": [item["evidenceHash"] for item in normalized["derivedEvidence"]],
            "subjectDomainHash": _hash_text(subject_domain) if subject_domain else "",
            "subjectMatched": matched,
        }
    )

    return {
        "schema": REPUTATION_CONNECTOR_SNAPSHOT_SCHEMA,
        "generatedAt": _now(),
        "mode": "live_fetch_derived_only",
        "sourceId": PHISHDESTROY_SOURCE_ID,
        "sourceName": "PhishDestroy active-domain feed",
        "sourceLink": PHISHDESTROY_PUBLIC_SOURCE_URL,
        "feedLink": PHISHDESTROY_ACTIVE_DOMAINS_URL,
        "live": True,
        "fetch": {
            "status": "ok",
            "httpStatus": fetched["statusCode"],
            "latencyMs": fetched["elapsedMs"],
            "contentType": fetched["contentType"],
            "contentLength": fetched["contentLength"],
            "etag": fetched["etag"],
            "lastModified": fetched["lastModified"],
            "feedHash": body_hash,
            "parsedDomainCount": len(unique_domains),
            "sampledEvidenceCount": len(normalized["derivedEvidence"]),
            "ttlSeconds": 21600,
        },
        "subject": _public_subject(subject_domain, matched),
        "derivedEvidence": normalized["derivedEvidence"],
        "reputationPreview": normalized["reputationPreview"],
        "snapshotReceipt": {
            "hash": snapshot_hash,
            "algorithm": "sha256_canonical_json",
            "zeroGChainReady": True,
            "zeroGStorageReady": True,
            "liveAnchorPerformed": False,
            "liveUploadPerformed": False,
        },
        "promotionUse": [
            "Use this as a live phishing-domain freshness proof.",
            "Use subjectMatched=true evidence in wallet/domain preflight before any signer prompt.",
            "Do not promote sampled feed rows into user alerts unless the user's target matches.",
        ],
        "rightsPolicy": _rights_policy(),
        "safety": _safety(live_connector_fetch=True),
    }


def reputation_connector_snapshot(
    *,
    source_id: str = PHISHDESTROY_SOURCE_ID,
    live: bool = False,
    limit: int = 5,
    subject_url: str = "",
    address: str = "",
    cve_ids: list[str] | tuple[str, ...] | str | None = None,
    days: int = 7,
    timeout_seconds: float = 6.0,
) -> dict[str, Any]:
    """Dispatch a reviewed connector worker by source id."""
    normalized_source_id = str(source_id or "").strip()
    if normalized_source_id == PHISHDESTROY_SOURCE_ID:
        return phishdestroy_active_domains_snapshot(
            live=live,
            limit=limit,
            subject_url=subject_url,
            timeout_seconds=timeout_seconds,
        )
    if normalized_source_id == CISA_KEV_SOURCE_ID:
        return cisa_kev_snapshot(
            live=live,
            limit=limit,
            cve_ids=cve_ids,
            timeout_seconds=timeout_seconds,
        )
    if normalized_source_id == NVD_CVE_SOURCE_ID:
        return nvd_cve_snapshot(
            live=live,
            limit=limit,
            cve_ids=cve_ids,
            days=days,
            timeout_seconds=timeout_seconds,
        )
    if normalized_source_id in {OFAC_SANCTIONS_SOURCE_ID, "ofac_sanctions_sls"}:
        return ofac_sanctions_snapshot(
            live=live,
            limit=limit,
            address=address,
            timeout_seconds=timeout_seconds,
        )
    raise ValueError(f"unsupported live connector sourceId: {source_id}")


def cisa_kev_snapshot(
    *,
    live: bool = False,
    limit: int = 5,
    cve_ids: list[str] | tuple[str, ...] | str | None = None,
    timeout_seconds: float = 6.0,
) -> dict[str, Any]:
    """Fetch and reduce the CISA Known Exploited Vulnerabilities catalog."""
    from guard0.reputation_adapters import normalize_reputation_adapter_payload

    _validate_limit(limit)
    requested_cves = _normalize_cve_ids(cve_ids)
    subject = _public_threat_subject(cve_ids=requested_cves)
    if not live:
        return _not_fetched_source_snapshot(
            source_id=CISA_KEV_SOURCE_ID,
            source_name="CISA Known Exploited Vulnerabilities catalog",
            source_link=CISA_KEV_PUBLIC_SOURCE_URL,
            feed_link=CISA_KEV_FEED_URL,
            limit=limit,
            subject=subject,
        )

    fetched = _fetch_url(
        CISA_KEV_FEED_URL,
        timeout_seconds=timeout_seconds,
        max_bytes=MAX_CISA_KEV_BYTES,
    )
    if not fetched["ok"]:
        return _degraded_source_snapshot(
            fetched,
            source_id=CISA_KEV_SOURCE_ID,
            source_name="CISA Known Exploited Vulnerabilities catalog",
            source_link=CISA_KEV_PUBLIC_SOURCE_URL,
            feed_link=CISA_KEV_FEED_URL,
            limit=limit,
            subject=subject,
        )

    rows = _decode_cisa_kev(fetched["body"])
    cve_filter = set(requested_cves)
    filtered = [
        row
        for row in rows
        if not cve_filter or str(row.get("cveID") or "").upper() in cve_filter
    ]
    filtered.sort(key=lambda row: str(row.get("dateAdded") or ""), reverse=True)
    sample_rows = filtered[:limit]
    adapter_payload = {
        "sourceId": "software_advisory_cve",
        "payload": {"kev_items": [_kev_adapter_row(row) for row in sample_rows]},
    }
    normalized = normalize_reputation_adapter_payload(adapter_payload)
    body_hash = _hash_bytes(fetched["body"])
    snapshot_hash = _hash_json(
        {
            "sourceId": CISA_KEV_SOURCE_ID,
            "bodyHash": body_hash,
            "parsedCveCount": len(rows),
            "matchedCveCount": len(filtered),
            "sampleHashes": [item["evidenceHash"] for item in normalized["derivedEvidence"]],
            "requestedCveIds": requested_cves,
        }
    )
    return _source_snapshot(
        source_id=CISA_KEV_SOURCE_ID,
        source_name="CISA Known Exploited Vulnerabilities catalog",
        source_link=CISA_KEV_PUBLIC_SOURCE_URL,
        feed_link=CISA_KEV_FEED_URL,
        fetched=fetched,
        body_hash=body_hash,
        limit=limit,
        subject={**subject, "matchedInFeed": bool(sample_rows) if requested_cves else None},
        parsed_count_key="parsedCveCount",
        parsed_count=len(rows),
        extra_fetch={
            "matchedCveCount": len(filtered),
            "requestedCveCount": len(requested_cves),
            "sampledEvidenceCount": len(normalized["derivedEvidence"]),
            "ttlSeconds": 21600,
        },
        derived_evidence=normalized["derivedEvidence"],
        reputation_preview=normalized["reputationPreview"],
        snapshot_hash=snapshot_hash,
        promotion_use=[
            "Use as exploited-software context for agent dependencies, browser extensions, and dapp infrastructure checks.",
            "Treat CISA KEV membership as review-required context, not proof that a user's wallet is compromised.",
            "Pair CVE context with wallet/domain/runtime evidence before surfacing a denial.",
        ],
    )


def nvd_cve_snapshot(
    *,
    live: bool = False,
    limit: int = 5,
    cve_ids: list[str] | tuple[str, ...] | str | None = None,
    days: int = 7,
    timeout_seconds: float = 6.0,
) -> dict[str, Any]:
    """Fetch and reduce NVD CVE API rows into derived advisory evidence."""
    from guard0.reputation_adapters import normalize_reputation_adapter_payload

    _validate_limit(limit)
    requested_cves = _normalize_cve_ids(cve_ids)
    days = max(1, min(int(days or 7), 30))
    subject = _public_threat_subject(cve_ids=requested_cves)
    feed_link = _nvd_query_url(cve_ids=requested_cves, limit=limit, days=days)
    if not live:
        return _not_fetched_source_snapshot(
            source_id=NVD_CVE_SOURCE_ID,
            source_name="NVD CVE API",
            source_link=NVD_CVE_PUBLIC_SOURCE_URL,
            feed_link=feed_link,
            limit=limit,
            subject=subject,
        )

    fetched = _fetch_url(
        feed_link,
        timeout_seconds=timeout_seconds,
        max_bytes=MAX_NVD_CVE_BYTES,
    )
    if not fetched["ok"]:
        return _degraded_source_snapshot(
            fetched,
            source_id=NVD_CVE_SOURCE_ID,
            source_name="NVD CVE API",
            source_link=NVD_CVE_PUBLIC_SOURCE_URL,
            feed_link=feed_link,
            limit=limit,
            subject=subject,
        )

    rows = _decode_nvd_cves(fetched["body"])
    cve_filter = set(requested_cves)
    filtered = [
        row
        for row in rows
        if not cve_filter or str(row.get("id") or "").upper() in cve_filter
    ]
    sample_rows = filtered[:limit]
    adapter_payload = {
        "sourceId": "software_advisory_cve",
        "payload": {"cves": [_nvd_adapter_row(row) for row in sample_rows]},
    }
    normalized = normalize_reputation_adapter_payload(adapter_payload)
    body_hash = _hash_bytes(fetched["body"])
    snapshot_hash = _hash_json(
        {
            "sourceId": NVD_CVE_SOURCE_ID,
            "bodyHash": body_hash,
            "parsedCveCount": len(rows),
            "matchedCveCount": len(filtered),
            "sampleHashes": [item["evidenceHash"] for item in normalized["derivedEvidence"]],
            "requestedCveIds": requested_cves,
            "days": days,
        }
    )
    return _source_snapshot(
        source_id=NVD_CVE_SOURCE_ID,
        source_name="NVD CVE API",
        source_link=NVD_CVE_PUBLIC_SOURCE_URL,
        feed_link=feed_link,
        fetched=fetched,
        body_hash=body_hash,
        limit=limit,
        subject={**subject, "matchedInFeed": bool(sample_rows) if requested_cves else None},
        parsed_count_key="parsedCveCount",
        parsed_count=len(rows),
        extra_fetch={
            "matchedCveCount": len(filtered),
            "requestedCveCount": len(requested_cves),
            "queryWindowDays": days,
            "sampledEvidenceCount": len(normalized["derivedEvidence"]),
            "ttlSeconds": 21600,
        },
        derived_evidence=normalized["derivedEvidence"],
        reputation_preview=normalized["reputationPreview"],
        snapshot_hash=snapshot_hash,
        promotion_use=[
            "Use as fresh vulnerability context for Web2 dependencies around dapps, extensions, and hosted wallet flows.",
            "Do not ship exploit instructions, proof-of-concept payloads, or unbounded CVE descriptions to public clients.",
            "Combine CVE severity with known exploitation and actual exposure before raising user-facing severity.",
        ],
    )


def ofac_sanctions_snapshot(
    *,
    live: bool = False,
    limit: int = 5,
    address: str = "",
    timeout_seconds: float = 6.0,
) -> dict[str, Any]:
    """Fetch and reduce OFAC SLS rows for a target wallet address."""
    from guard0.reputation_adapters import normalize_reputation_adapter_payload

    _validate_limit(limit)
    target_address = _normalize_evm_address(address)
    subject = _public_threat_subject(address=target_address)
    if not live:
        return _not_fetched_source_snapshot(
            source_id=OFAC_SANCTIONS_SOURCE_ID,
            source_name="OFAC Sanctions List Service SDN export",
            source_link=OFAC_SANCTIONS_PUBLIC_SOURCE_URL,
            feed_link=OFAC_SANCTIONS_FEED_URL,
            limit=limit,
            subject=subject,
        )

    fetched = _fetch_url(
        OFAC_SANCTIONS_FEED_URL,
        timeout_seconds=timeout_seconds,
        max_bytes=MAX_OFAC_SANCTIONS_BYTES,
    )
    if not fetched["ok"]:
        return _degraded_source_snapshot(
            fetched,
            source_id=OFAC_SANCTIONS_SOURCE_ID,
            source_name="OFAC Sanctions List Service SDN export",
            source_link=OFAC_SANCTIONS_PUBLIC_SOURCE_URL,
            feed_link=OFAC_SANCTIONS_FEED_URL,
            limit=limit,
            subject=subject,
        )

    parsed = _decode_ofac_sdn_csv(fetched["body"], target_address=target_address, limit=limit)
    normalized = None
    derived: list[dict[str, Any]] = []
    reputation_preview = None
    if target_address:
        adapter_payload = {
            "sourceId": "ofac_sanctions_sls",
            "subject": {"address": target_address, "chain": "eip155:any"},
            "payload": {"matches": parsed["matches"]},
        }
        normalized = normalize_reputation_adapter_payload(adapter_payload)
        derived = normalized["derivedEvidence"]
        reputation_preview = normalized["reputationPreview"]
    body_hash = _hash_bytes(fetched["body"])
    snapshot_hash = _hash_json(
        {
            "sourceId": OFAC_SANCTIONS_SOURCE_ID,
            "bodyHash": body_hash,
            "parsedDigitalCurrencyAddressCount": parsed["digitalCurrencyAddressCount"],
            "matchCount": len(parsed["matches"]),
            "sampleAddressHashes": parsed["sampleAddressHashes"],
            "targetAddressHash": _hash_text(target_address) if target_address else "",
            "sampleHashes": [item["evidenceHash"] for item in derived],
        }
    )
    return _source_snapshot(
        source_id=OFAC_SANCTIONS_SOURCE_ID,
        source_name="OFAC Sanctions List Service SDN export",
        source_link=OFAC_SANCTIONS_PUBLIC_SOURCE_URL,
        feed_link=OFAC_SANCTIONS_FEED_URL,
        fetched=fetched,
        body_hash=body_hash,
        limit=limit,
        subject={**subject, "matchedInFeed": bool(parsed["matches"]) if target_address else None},
        parsed_count_key="parsedDigitalCurrencyAddressCount",
        parsed_count=parsed["digitalCurrencyAddressCount"],
        extra_fetch={
            "matchedAddressCount": len(parsed["matches"]),
            "targetAddressProvided": bool(target_address),
            "sampleAddressHashes": parsed["sampleAddressHashes"],
            "sampledEvidenceCount": len(derived),
            "ttlSeconds": 21600,
        },
        derived_evidence=derived,
        reputation_preview=reputation_preview,
        snapshot_hash=snapshot_hash,
        promotion_use=[
            "Use target-address matches as a compliance-review signal before wallet execution.",
            "Do not return the raw SDN CSV, full sanctions records, or full wallet lists from public APIs.",
            "Treat this as defensive screening context and not legal advice.",
        ],
    )


def phishdestroy_digest_signal(snapshot: dict[str, Any], source: dict[str, Any]) -> dict[str, Any] | None:
    """Convert a connector snapshot into an OSINT signal row."""
    fetch = snapshot.get("fetch") if isinstance(snapshot.get("fetch"), dict) else {}
    if fetch.get("status") != "ok":
        return None
    signal = {
        "schema": "0guard.osint_signal.v1",
        "sourceId": source["id"],
        "sourceOwner": source["owner"],
        "sourceUrl": source["url"],
        "retrievalMode": source["retrieval_mode"],
        "rightsEnvelope": source["license_or_rights"],
        "outputPolicy": source["output_policy"],
        "observedAt": snapshot.get("generatedAt"),
        "signalType": "reputation_feed_digest",
        "title": "PhishDestroy active-domain digest",
        "activeDomainCount": fetch.get("parsedDomainCount", 0),
        "sampledEvidenceCount": fetch.get("sampledEvidenceCount", 0),
        "ttlSeconds": fetch.get("ttlSeconds", 21600),
        "sourceLink": snapshot.get("sourceLink"),
        "feedHash": fetch.get("feedHash"),
        "snapshotHash": (snapshot.get("snapshotReceipt") or {}).get("hash"),
        "rawPayloadReturned": False,
    }
    signal["recordHash"] = _hash_json(signal)
    return signal


def cyber_connector_digest_signal(snapshot: dict[str, Any], source: dict[str, Any]) -> dict[str, Any] | None:
    """Convert a cyber/sanctions connector snapshot into a public OSINT signal."""
    fetch = snapshot.get("fetch") if isinstance(snapshot.get("fetch"), dict) else {}
    if fetch.get("status") != "ok":
        return None
    source_id = str(snapshot.get("sourceId") or source.get("id") or "")
    if source_id == CISA_KEV_SOURCE_ID:
        signal_type = "known_exploited_vulnerability_digest"
        title = "CISA KEV derived digest"
        count_key = "parsedCveCount"
    elif source_id == NVD_CVE_SOURCE_ID:
        signal_type = "software_vulnerability_digest"
        title = "NVD CVE derived digest"
        count_key = "parsedCveCount"
    elif source_id == OFAC_SANCTIONS_SOURCE_ID:
        signal_type = "sanctions_screening_digest"
        title = "OFAC sanctions-list derived digest"
        count_key = "parsedDigitalCurrencyAddressCount"
    else:
        return None
    signal = {
        "schema": "0guard.osint_signal.v1",
        "sourceId": source_id,
        "sourceOwner": source.get("owner", ""),
        "sourceUrl": source.get("url") or snapshot.get("sourceLink"),
        "retrievalMode": source.get("retrieval_mode", "public_api"),
        "rightsEnvelope": source.get("license_or_rights", "public source; derived features only"),
        "outputPolicy": source.get("output_policy", "hashes, counts, links, and derived labels only"),
        "observedAt": snapshot.get("generatedAt"),
        "signalType": signal_type,
        "title": title,
        "sourceRecordCount": fetch.get(count_key, 0),
        "matchedRecordCount": fetch.get("matchedCveCount", fetch.get("matchedAddressCount", 0)),
        "sampledEvidenceCount": fetch.get("sampledEvidenceCount", 0),
        "ttlSeconds": fetch.get("ttlSeconds", 21600),
        "sourceLink": snapshot.get("sourceLink"),
        "feedHash": fetch.get("feedHash"),
        "snapshotHash": (snapshot.get("snapshotReceipt") or {}).get("hash"),
        "rawPayloadReturned": False,
        "notLegalAdvice": source_id == OFAC_SANCTIONS_SOURCE_ID,
        "notAttribution": source_id in {CISA_KEV_SOURCE_ID, NVD_CVE_SOURCE_ID},
    }
    signal["recordHash"] = _hash_json(signal)
    return signal


def _validate_limit(limit: int) -> None:
    if limit < 1 or limit > 50:
        raise ValueError("limit must be between 1 and 50")


def _not_fetched_source_snapshot(
    *,
    source_id: str,
    source_name: str,
    source_link: str,
    feed_link: str,
    limit: int,
    subject: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": REPUTATION_CONNECTOR_SNAPSHOT_SCHEMA,
        "generatedAt": _now(),
        "mode": "live_fetch_disabled",
        "sourceId": source_id,
        "sourceName": source_name,
        "sourceLink": source_link,
        "feedLink": feed_link,
        "live": False,
        "fetch": {
            "status": "live_fetch_disabled",
            "sampleLimit": limit,
        },
        "subject": subject,
        "derivedEvidence": [],
        "snapshotReceipt": {
            "hash": "",
            "algorithm": "sha256_canonical_json",
            "zeroGChainReady": False,
            "zeroGStorageReady": False,
            "liveAnchorPerformed": False,
            "liveUploadPerformed": False,
        },
        "rightsPolicy": _rights_policy(),
        "safety": _safety(live_connector_fetch=False),
    }


def _degraded_source_snapshot(
    fetched: dict[str, Any],
    *,
    source_id: str,
    source_name: str,
    source_link: str,
    feed_link: str,
    limit: int,
    subject: dict[str, Any],
) -> dict[str, Any]:
    snapshot = _not_fetched_source_snapshot(
        source_id=source_id,
        source_name=source_name,
        source_link=source_link,
        feed_link=feed_link,
        limit=limit,
        subject=subject,
    )
    snapshot["live"] = True
    snapshot["mode"] = "live_fetch_degraded"
    snapshot["fetch"] = {
        "status": "degraded",
        "httpStatus": fetched["statusCode"],
        "latencyMs": fetched["elapsedMs"],
        "contentType": fetched["contentType"],
        "contentLength": fetched["contentLength"],
        "etag": fetched["etag"],
        "lastModified": fetched["lastModified"],
        "error": fetched["error"],
        "sampleLimit": limit,
    }
    snapshot["safety"] = _safety(live_connector_fetch=True)
    return snapshot


def _source_snapshot(
    *,
    source_id: str,
    source_name: str,
    source_link: str,
    feed_link: str,
    fetched: dict[str, Any],
    body_hash: str,
    limit: int,
    subject: dict[str, Any],
    parsed_count_key: str,
    parsed_count: int,
    extra_fetch: dict[str, Any],
    derived_evidence: list[dict[str, Any]],
    reputation_preview: dict[str, Any] | None,
    snapshot_hash: str,
    promotion_use: list[str],
) -> dict[str, Any]:
    return {
        "schema": REPUTATION_CONNECTOR_SNAPSHOT_SCHEMA,
        "generatedAt": _now(),
        "mode": "live_fetch_derived_only",
        "sourceId": source_id,
        "sourceName": source_name,
        "sourceLink": source_link,
        "feedLink": feed_link,
        "live": True,
        "fetch": {
            "status": "ok",
            "httpStatus": fetched["statusCode"],
            "latencyMs": fetched["elapsedMs"],
            "contentType": fetched["contentType"],
            "contentLength": fetched["contentLength"],
            "etag": fetched["etag"],
            "lastModified": fetched["lastModified"],
            "feedHash": body_hash,
            parsed_count_key: parsed_count,
            "sampleLimit": limit,
            **extra_fetch,
        },
        "subject": subject,
        "derivedEvidence": derived_evidence,
        "reputationPreview": reputation_preview,
        "snapshotReceipt": {
            "hash": snapshot_hash,
            "algorithm": "sha256_canonical_json",
            "zeroGChainReady": True,
            "zeroGStorageReady": True,
            "liveAnchorPerformed": False,
            "liveUploadPerformed": False,
        },
        "promotionUse": promotion_use,
        "rightsPolicy": _rights_policy(),
        "safety": _safety(live_connector_fetch=True),
    }


def _not_fetched_snapshot(*, limit: int, subject_domain: str) -> dict[str, Any]:
    return {
        "schema": REPUTATION_CONNECTOR_SNAPSHOT_SCHEMA,
        "generatedAt": _now(),
        "mode": "live_fetch_disabled",
        "sourceId": PHISHDESTROY_SOURCE_ID,
        "sourceName": "PhishDestroy active-domain feed",
        "sourceLink": PHISHDESTROY_PUBLIC_SOURCE_URL,
        "feedLink": PHISHDESTROY_ACTIVE_DOMAINS_URL,
        "live": False,
        "fetch": {
            "status": "live_fetch_disabled",
            "sampleLimit": limit,
        },
        "subject": _public_subject(subject_domain, None),
        "derivedEvidence": [],
        "snapshotReceipt": {
            "hash": "",
            "algorithm": "sha256_canonical_json",
            "zeroGChainReady": False,
            "zeroGStorageReady": False,
            "liveAnchorPerformed": False,
            "liveUploadPerformed": False,
        },
        "rightsPolicy": _rights_policy(),
        "safety": _safety(live_connector_fetch=False),
    }


def _degraded_snapshot(
    fetched: dict[str, Any],
    *,
    limit: int,
    subject_domain: str,
) -> dict[str, Any]:
    snapshot = _not_fetched_snapshot(limit=limit, subject_domain=subject_domain)
    snapshot["live"] = True
    snapshot["mode"] = "live_fetch_degraded"
    snapshot["fetch"] = {
        "status": "degraded",
        "httpStatus": fetched["statusCode"],
        "latencyMs": fetched["elapsedMs"],
        "contentType": fetched["contentType"],
        "contentLength": fetched["contentLength"],
        "etag": fetched["etag"],
        "lastModified": fetched["lastModified"],
        "error": fetched["error"],
        "sampleLimit": limit,
    }
    snapshot["safety"] = _safety(live_connector_fetch=True)
    return snapshot


def _fetch_url(url: str, *, timeout_seconds: float, max_bytes: int) -> dict[str, Any]:
    started = time.perf_counter()
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = response.read(max_bytes + 1)
            too_large = len(body) > max_bytes
            if too_large:
                body = body[:max_bytes]
            return {
                "ok": not too_large,
                "statusCode": getattr(response, "status", None),
                "contentType": response.headers.get("content-type", ""),
                "contentLength": _int(response.headers.get("content-length")),
                "etag": response.headers.get("etag"),
                "lastModified": response.headers.get("last-modified"),
                "elapsedMs": int((time.perf_counter() - started) * 1000),
                "body": body,
                "error": "response exceeded max bytes" if too_large else None,
            }
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return {
            "ok": False,
            "statusCode": None,
            "contentType": "",
            "contentLength": 0,
            "etag": None,
            "lastModified": None,
            "elapsedMs": int((time.perf_counter() - started) * 1000),
            "body": b"",
            "error": f"{type(exc).__name__}: {exc}",
        }


def _decode_domain_list(body: bytes) -> list[str]:
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if not isinstance(decoded, list):
        return []
    return [_normalize_domain(item) for item in decoded if isinstance(item, str)]


def _decode_cisa_kev(body: bytes) -> list[dict[str, Any]]:
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if isinstance(decoded, dict):
        rows = decoded.get("vulnerabilities") or decoded.get("data") or []
    elif isinstance(decoded, list):
        rows = decoded
    else:
        rows = []
    return [row for row in rows if isinstance(row, dict)]


def _decode_nvd_cves(body: bytes) -> list[dict[str, Any]]:
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return []
    if isinstance(decoded, dict):
        items = decoded.get("vulnerabilities") or decoded.get("data") or []
    elif isinstance(decoded, list):
        items = decoded
    else:
        items = []
    rows: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        cve = item.get("cve") if isinstance(item.get("cve"), dict) else item
        if isinstance(cve, dict):
            rows.append(cve)
    return rows


def _decode_ofac_sdn_csv(
    body: bytes,
    *,
    target_address: str,
    limit: int,
) -> dict[str, Any]:
    try:
        decoded = body.decode("utf-8-sig")
    except UnicodeDecodeError:
        decoded = body.decode("latin-1", errors="ignore")
    reader = csv.reader(io.StringIO(decoded))
    target = _normalize_evm_address(target_address)
    address_count = 0
    matches: list[dict[str, Any]] = []
    sample_hashes: list[str] = []
    seen_addresses: set[str] = set()
    for row_index, row in enumerate(reader):
        row_text = " ".join(str(field) for field in row)
        addresses = sorted({_normalize_evm_address(match.group(0)) for match in EVM_ADDRESS_RE.finditer(row_text)})
        if not addresses:
            continue
        for address in addresses:
            if address in seen_addresses:
                continue
            seen_addresses.add(address)
            address_count += 1
            if len(sample_hashes) < limit:
                sample_hashes.append(_hash_text(address))
        if target and target in addresses and len(matches) < limit:
            matches.append(
                {
                    "matched": True,
                    "address": target,
                    "program": _ofac_program_from_row(row),
                    "list": "SDN",
                    "sourceUrl": OFAC_SANCTIONS_PUBLIC_SOURCE_URL,
                    "rowIndex": row_index,
                    "rowHash": _hash_text(row_text),
                }
            )
    return {
        "digitalCurrencyAddressCount": address_count,
        "matches": matches,
        "sampleAddressHashes": sample_hashes,
    }


def _kev_adapter_row(row: dict[str, Any]) -> dict[str, Any]:
    cve = str(row.get("cveID") or row.get("cve") or "").upper()
    ransomware = str(row.get("knownRansomwareCampaignUse") or "").lower()
    return {
        "cveID": cve,
        "cve": cve,
        "vendorProject": row.get("vendorProject"),
        "product": row.get("product"),
        "vulnerabilityNameHash": _hash_text(str(row.get("vulnerabilityName") or "")),
        "dateAdded": row.get("dateAdded"),
        "dueDate": row.get("dueDate"),
        "severity": "high",
        "knownExploited": True,
        "kev": True,
        "knownRansomwareCampaignUse": ransomware in {"known", "yes", "true"},
        "sourceUrl": CISA_KEV_PUBLIC_SOURCE_URL,
    }


def _nvd_adapter_row(row: dict[str, Any]) -> dict[str, Any]:
    cve = str(row.get("id") or row.get("cveID") or row.get("cve") or "").upper()
    severity = _nvd_severity(row)
    return {
        "cve": cve,
        "id": cve,
        "severity": severity,
        "published": row.get("published"),
        "lastModified": row.get("lastModified"),
        "weaknesses": _nvd_weaknesses(row),
        "descriptionHash": _hash_text(_nvd_description(row)),
        "sourceUrl": f"https://nvd.nist.gov/vuln/detail/{urllib.parse.quote(cve)}" if cve else NVD_CVE_PUBLIC_SOURCE_URL,
    }


def _nvd_query_url(
    *,
    cve_ids: list[str],
    limit: int,
    days: int,
) -> str:
    params: dict[str, str] = {"resultsPerPage": str(min(limit, 20))}
    if len(cve_ids) == 1:
        params["cveIds"] = cve_ids[0]
    else:
        end = datetime.now(timezone.utc).replace(microsecond=0)
        start = end - timedelta(days=days)
        params["pubStartDate"] = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        params["pubEndDate"] = end.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return f"{NVD_CVE_API_URL}?{urllib.parse.urlencode(params)}"


def _normalize_cve_ids(value: list[str] | tuple[str, ...] | str | None) -> list[str]:
    if value is None:
        return []
    raw_items: list[Any]
    if isinstance(value, str):
        raw_items = value.replace(";", ",").split(",")
    else:
        raw_items = list(value)
    cves: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        cve = str(item or "").strip().upper()
        if not cve:
            continue
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            continue
        if cve not in seen:
            seen.add(cve)
            cves.append(cve)
    return cves[:25]


def _normalize_evm_address(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    match = EVM_ADDRESS_RE.fullmatch(raw)
    return match.group(0).lower() if match else ""


def _public_threat_subject(
    *,
    address: str = "",
    cve_ids: list[str] | None = None,
) -> dict[str, Any]:
    cves = cve_ids or []
    return {
        "addressRedacted": _redact_address(address),
        "addressHash": _hash_text(address) if address else "",
        "rawAddressReturned": False,
        "cveIds": cves,
        "cveIdHashes": [_hash_text(cve) for cve in cves],
        "rawPayloadReturned": False,
        "matchedInFeed": None,
    }


def _redact_address(address: str) -> str:
    normalized = _normalize_evm_address(address)
    if not normalized:
        return ""
    return f"{normalized[:6]}...{normalized[-4:]}"


def _ofac_program_from_row(row: list[str]) -> str:
    for value in row:
        text = str(value or "").strip()
        if not text:
            continue
        upper = text.upper()
        if upper in {"SDGT", "SDNTK", "DPRK", "CYBER2", "CYBER", "NPWMD", "ILLICIT-DRUGS-EO14059"}:
            return upper
    return "OFAC"


def _nvd_severity(row: dict[str, Any]) -> str:
    metrics = row.get("metrics") if isinstance(row.get("metrics"), dict) else {}
    severities: list[str] = []
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        value = metrics.get(key)
        if not isinstance(value, list):
            continue
        for metric in value:
            if not isinstance(metric, dict):
                continue
            cvss_data = metric.get("cvssData") if isinstance(metric.get("cvssData"), dict) else {}
            severity = str(metric.get("baseSeverity") or cvss_data.get("baseSeverity") or "").lower()
            if severity:
                severities.append(severity)
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return max(severities, key=lambda item: rank.get(item, 0), default="")


def _nvd_weaknesses(row: dict[str, Any]) -> list[str]:
    weaknesses = row.get("weaknesses") if isinstance(row.get("weaknesses"), list) else []
    values: list[str] = []
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        for desc in weakness.get("description") or []:
            if isinstance(desc, dict):
                value = str(desc.get("value") or "").strip()
                if value:
                    values.append(value)
    return values[:5]


def _nvd_description(row: dict[str, Any]) -> str:
    descriptions = row.get("descriptions") if isinstance(row.get("descriptions"), list) else []
    for desc in descriptions:
        if not isinstance(desc, dict):
            continue
        if desc.get("lang") == "en" and desc.get("value"):
            return str(desc.get("value"))
    return ""


def _domain_from_url(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urllib.parse.urlparse(raw)
    return _normalize_domain(parsed.hostname or parsed.path.split("/", 1)[0])


def _normalize_domain(value: str) -> str:
    return str(value or "").strip().lower().rstrip(".")


def _public_subject(subject_domain: str, matched: bool | None) -> dict[str, Any]:
    return {
        "domainHash": _hash_text(subject_domain) if subject_domain else "",
        "matchedInFeed": matched,
        "rawDomainReturned": False,
    }


def _rights_policy() -> dict[str, bool]:
    return {
        "rawPayloadsReturned": False,
        "rawPayloadResaleAllowed": False,
        "rawDomainsReturned": False,
        "sourceLinksOrHashesOnly": True,
        "derivedEvidenceOnly": True,
    }


def _safety(*, live_connector_fetch: bool) -> dict[str, bool]:
    return {
        "readOnly": True,
        "networkCalls": live_connector_fetch,
        "liveConnectorFetch": live_connector_fetch,
        "rawPayloadsReturned": False,
        "rawDomainsReturned": False,
        "privateKeyRequired": False,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "telegramSendsEnabled": False,
        "socialPostingEnabled": False,
        "paymentSettlementEnabled": False,
        "bridgingEnabled": False,
        "swappingEnabled": False,
    }


def _hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hash_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
