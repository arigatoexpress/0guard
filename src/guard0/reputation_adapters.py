"""No-network reputation adapter normalization for external feeds.

The adapter layer is intentionally not a fetcher. It accepts caller-provided
evidence that came from a reviewed connector worker and converts it into the
derived source-evidence shape consumed by /api/reputation/probe and
/api/threat-case-file. Raw upstream payloads are hashed, summarized, and
discarded from the public response.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from guard0.reputation import build_reputation_probe

REPUTATION_ADAPTER_CATALOG_SCHEMA = "0guard.reputation_adapter_catalog.v1"
REPUTATION_ADAPTER_PREVIEW_SCHEMA = "0guard.reputation_adapter_preview.v1"

_ADAPTERS: tuple[dict[str, Any], ...] = (
    {
        "id": "phishdestroy_destroylist",
        "name": "PhishDestroy DestroyList and Threat API",
        "stage": "open_source_first_connector",
        "officialDocs": [
            "https://phishdestroy.io/dataset",
            "https://phishdestroy.io/",
            "https://huggingface.co/datasets/phishdestroy/destroylist",
        ],
        "supportedPayloads": [
            "domain_rows",
            "active_domains",
            "blocklist",
            "threat_api_result",
        ],
        "derivedOutput": "active_domain_status_target_brand_drainer_type_confidence_hashes",
        "credentialRequiredForLiveFetch": False,
    },
    {
        "id": "cryptoscamdb",
        "name": "CryptoScamDB open dataset",
        "stage": "open_dataset_seed",
        "officialDocs": [
            "https://cryptoscamdb.org/",
            "https://github.com/CryptoScamDB/api.cryptoscamdb.org",
        ],
        "supportedPayloads": ["urls", "addresses", "entries", "reports"],
        "derivedOutput": "reported_url_or_address_categories_confidence_hashes",
        "credentialRequiredForLiveFetch": False,
    },
    {
        "id": "scamsniffer_blacklist",
        "name": "Scam Sniffer delayed scam database",
        "stage": "open_dataset_optional_copyleft_review",
        "officialDocs": [
            "https://github.com/scamsniffer/scam-database",
            "https://www.scamsniffer.io/",
        ],
        "supportedPayloads": ["domains", "addresses", "blacklist", "entries"],
        "derivedOutput": "phishing_or_drainer_blacklist_confidence_hashes_license_flags",
        "credentialRequiredForLiveFetch": False,
        "licenseCaveat": "GPL-3.0 raw feed; keep disabled by default for bundled product artifacts unless license posture is accepted.",
    },
    {
        "id": "ofac_sanctions_sls",
        "name": "OFAC Sanctions List Service",
        "stage": "public_compliance_seed_optional",
        "officialDocs": [
            "https://ofac.treasury.gov/sanctions-list-service",
            "https://sanctionslistservice.ofac.treas.gov/",
        ],
        "supportedPayloads": ["csv_rows", "sdn_rows", "digital_currency_addresses", "matches"],
        "derivedOutput": "sanctions_match_program_list_version_hashes_no_legal_advice",
        "credentialRequiredForLiveFetch": False,
    },
    {
        "id": "forta_labelled_datasets",
        "name": "Forta labelled datasets",
        "stage": "offline_label_seed",
        "officialDocs": [
            "https://github.com/forta-network/labelled-datasets",
            "https://docs.forta.network/en/latest/labels/",
        ],
        "supportedPayloads": ["labels", "entities", "rows"],
        "derivedOutput": "label_confidence_entity_type_source_hashes",
        "credentialRequiredForLiveFetch": False,
    },
    {
        "id": "goplus_security",
        "name": "GoPlus Security",
        "stage": "keyed_connector_candidate",
        "officialDocs": [
            "https://docs.gopluslabs.io/",
            "https://docs.gopluslabs.io/docs/goplus-sdk",
        ],
        "supportedPayloads": [
            "malicious_address",
            "token_security",
            "approval_security",
            "dapp_security",
            "signature_decode",
            "evm_transaction_simulation",
        ],
        "derivedOutput": "risk_flags_confidence_source_ids_hashes_and_links",
        "credentialRequiredForLiveFetch": True,
    },
    {
        "id": "chainabuse",
        "name": "Chainabuse reports",
        "stage": "keyed_connector_candidate",
        "officialDocs": [
            "https://docs.chainabuse.com/docs/welcome-to-chainabuse-api",
            "https://docs.chainabuse.com/reference/reports-1",
            "https://docs.chainabuse.com/docs/get-reports-parameters",
        ],
        "supportedPayloads": ["reports", "screening_result"],
        "derivedOutput": "reported_count_checked_confidence_categories_links_and_hashes",
        "credentialRequiredForLiveFetch": True,
    },
    {
        "id": "forta_graphql_api",
        "name": "Forta alerts and labels",
        "stage": "detector_stream_candidate",
        "officialDocs": [
            "https://docs.forta.network/en/latest/api-reference/",
            "https://docs.forta.network/en/latest/forta-api-reference/",
            "https://docs.forta.network/en/latest/labels/",
        ],
        "supportedPayloads": ["alerts", "labels"],
        "derivedOutput": "alert_or_label_counts_severity_confidence_bot_ids_and_hashes",
        "credentialRequiredForLiveFetch": True,
    },
    {
        "id": "defillama_hacks",
        "name": "DeFiLlama hacks incident API",
        "stage": "public_incident_backtest_enrichment",
        "officialDocs": [
            "https://api.llama.fi/hacks",
            "https://docs.llama.fi/faqs/frequently-asked-questions",
        ],
        "supportedPayloads": ["incidents", "hacks", "records"],
        "derivedOutput": "incident_context_loss_chain_classification_hashes",
        "credentialRequiredForLiveFetch": False,
    },
    {
        "id": "evm_event_index",
        "name": "EVM approval, permit, and transfer event index",
        "stage": "operator_reviewed_rpc_or_explorer_worker",
        "officialDocs": [
            "https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_getlogs",
            "https://docs.etherscan.io/introduction",
        ],
        "supportedPayloads": ["logs", "transactions", "token_transfers", "approvals"],
        "derivedOutput": "spender_method_event_topic_value_risk_hashes",
        "credentialRequiredForLiveFetch": False,
    },
    {
        "id": "software_advisory_cve",
        "name": "GitHub/NVD/CISA software advisory context",
        "stage": "public_dependency_context",
        "officialDocs": [
            "https://docs.github.com/en/rest/security-advisories/global-advisories",
            "https://nvd.nist.gov/developers/start-here",
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        ],
        "supportedPayloads": ["advisories", "cves", "kev_items"],
        "derivedOutput": "dependency_cve_severity_kev_context_hashes",
        "credentialRequiredForLiveFetch": False,
    },
)

_ADAPTER_ALIASES = {
    "cisa_kev": "software_advisory_cve",
    "nvd_cve": "software_advisory_cve",
    "ofac_sanctions": "ofac_sanctions_sls",
}


def reputation_adapter_catalog() -> dict[str, Any]:
    """Return the supported adapter contracts without making external calls."""
    return {
        "schema": REPUTATION_ADAPTER_CATALOG_SCHEMA,
        "generatedAt": _now(),
        "mode": "adapter_contracts_no_network_calls",
        "adapterCount": len(_ADAPTERS),
        "adapters": [dict(adapter) for adapter in _ADAPTERS],
        "activationOrder": [
            "phishdestroy_destroylist",
            "scamsniffer_blacklist",
            "cryptoscamdb",
            "forta_labelled_datasets",
            "ofac_sanctions_sls",
            "goplus_security",
            "chainabuse",
            "forta_graphql_api",
            "defillama_hacks",
            "evm_event_index",
            "software_advisory_cve",
        ],
        "integrationPattern": [
            "fetch externally only from an operator-reviewed worker with credentials and retention terms",
            "pass the upstream response to /api/reputation/adapters/normalize",
            "persist only derived evidence, source ids, confidence, hashes, links, and receipts",
            "route the normalized evidence through /api/reputation/probe or /api/threat-case-file",
        ],
        "safety": _safety(),
        "rightsPolicy": _rights_policy(),
    }


def normalize_reputation_adapter_payload(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Normalize caller-provided adapter evidence without echoing raw payloads."""
    body = payload or {}
    if not isinstance(body, dict):
        raise ValueError("payload must be an object")

    source_id = str(
        body.get("sourceId") or body.get("source_id") or body.get("source") or ""
    ).strip()
    if not source_id:
        raise ValueError("sourceId is required")
    input_source_id = source_id
    source_id = _canonical_source_id(source_id)
    if source_id not in {adapter["id"] for adapter in _ADAPTERS}:
        raise ValueError(f"unsupported sourceId: {input_source_id}")

    subject = _subject(body)
    upstream_payload = _upstream_payload(body)
    derived = _derive(source_id, upstream_payload)
    probe_payload = {
        "url": subject["url"],
        "address": subject["address"],
        "chain": subject["chain"],
        "surface": "reputation_adapter_normalizer",
        "sourceEvidence": derived,
    }
    reputation = build_reputation_probe(probe_payload)
    return {
        "schema": REPUTATION_ADAPTER_PREVIEW_SCHEMA,
        "generatedAt": _now(),
        "mode": "normalize_caller_supplied_payload_no_network_calls",
        "sourceId": source_id,
        "inputSourceId": input_source_id if input_source_id != source_id else source_id,
        "subject": _public_subject(subject),
        "rawPayloadReturned": False,
        "rawPayloadHash": _hash_json(upstream_payload),
        "derivedEvidenceCount": len(derived),
        "derivedEvidence": derived,
        "recommendedProbePayload": {
            "urlHash": _hash_text(subject["url"]) if subject["url"] else "",
            "addressRedacted": _redact(subject["address"]),
            "chain": subject["chain"],
            "sourceEvidence": derived,
        },
        "reputationPreview": {
            "schema": reputation["schema"],
            "decision": reputation["decision"],
            "signalCount": reputation["signalCount"],
            "receipt": reputation["receipt"],
            "rawPayloadsReturned": reputation["rawPayloadsReturned"],
        },
        "nextStep": _next_step(source_id, derived),
        "safety": _safety(),
        "rightsPolicy": _rights_policy(),
    }


def normalize_reputation_adapters_from_payload(payload: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Normalize zero or more adapter payloads embedded in a request body."""
    body = payload or {}
    if not isinstance(body, dict):
        raise ValueError("payload must be an object")

    candidates: list[dict[str, Any]] = []
    for key in ("reputationAdapter", "reputation_adapter", "adapterPayload", "adapter_payload"):
        value = body.get(key)
        if isinstance(value, dict):
            candidates.append(value)
    for key in ("reputationAdapters", "reputation_adapters", "adapterPayloads", "adapter_payloads"):
        value = body.get(key)
        if isinstance(value, list):
            candidates.extend(item for item in value if isinstance(item, dict))

    return [normalize_reputation_adapter_payload(candidate) for candidate in candidates]


def _derive(source_id: str, upstream_payload: dict[str, Any]) -> list[dict[str, Any]]:
    if source_id == "phishdestroy_destroylist":
        return _derive_phishdestroy(upstream_payload)
    if source_id == "scamsniffer_blacklist":
        return _derive_scamsniffer(upstream_payload)
    if source_id == "cryptoscamdb":
        return _derive_cryptoscamdb(upstream_payload)
    if source_id == "ofac_sanctions_sls":
        return _derive_ofac(upstream_payload)
    if source_id == "forta_labelled_datasets":
        return _derive_forta("forta_labelled_datasets", upstream_payload)
    if source_id == "goplus_security":
        return _derive_goplus(upstream_payload)
    if source_id == "chainabuse":
        return _derive_chainabuse(upstream_payload)
    if source_id == "forta_graphql_api":
        return _derive_forta("forta_graphql_api", upstream_payload)
    if source_id == "defillama_hacks":
        return _derive_defillama(upstream_payload)
    if source_id == "evm_event_index":
        return _derive_evm_event_index(upstream_payload)
    if source_id == "software_advisory_cve":
        return _derive_software_advisory(upstream_payload)
    return []


def _canonical_source_id(source_id: str) -> str:
    return _ADAPTER_ALIASES.get(str(source_id or "").strip(), str(source_id or "").strip())


def _derive_phishdestroy(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = _domain_rows(payload)
    signals: list[dict[str, Any]] = []
    for row in rows[:10]:
        status = str(
            row.get("site_status")
            or row.get("status")
            or row.get("state")
            or row.get("dns_status")
            or ""
        ).lower()
        active = bool(row.get("active") is True or status in {"alive", "active", "online", "resolving"})
        brand = str(row.get("target_brand") or row.get("brand") or row.get("target") or "").strip()
        drainer = str(row.get("drainer_type") or row.get("kit") or row.get("category") or "").strip()
        detections = _int(row.get("vt_detections") or row.get("detections") or row.get("score"))
        verdict = "malicious" if active or detections >= 3 else "suspicious"
        confidence = 0.88 if active else 0.68 if detections else 0.58
        categories = ["phishing_domain"]
        if active:
            categories.append("active")
        if brand:
            categories.append(f"brand:{brand}")
        if drainer:
            categories.append(f"drainer:{drainer}")
        signals.append(
            _evidence(
                source_id="phishdestroy_destroylist",
                verdict=verdict,
                confidence=confidence,
                label="PhishDestroy phishing-domain signal",
                categories=categories,
                reference=row.get("url") or row.get("domain") or row.get("source"),
                raw_fragment=row,
            )
        )
    if signals:
        return signals[:5]
    return [
        _evidence(
            source_id="phishdestroy_destroylist",
            verdict="unknown",
            confidence=0.35,
            label="No PhishDestroy domain rows were present in the caller payload.",
            categories=[],
            reference=None,
            raw_fragment=payload,
        )
    ]


def _derive_scamsniffer(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = _domain_rows(payload)
    rows.extend(_address_rows(payload))
    signals: list[dict[str, Any]] = []
    for row in rows[:10]:
        list_type = str(
            row.get("list_type")
            or row.get("type")
            or row.get("category")
            or row.get("source")
            or "blacklist"
        ).strip()
        delay_days = _int(row.get("delay_days") or row.get("open_data_delay_days") or 7)
        confidence = 0.82 if delay_days <= 7 else 0.68
        signals.append(
            _evidence(
                source_id="scamsniffer_blacklist",
                verdict="malicious",
                confidence=confidence,
                label=f"Scam Sniffer blacklist signal: {list_type}",
                categories=["phishing_or_drainer", list_type, f"open_data_delay_days:{delay_days}"],
                reference=row.get("url") or row.get("domain") or row.get("address") or row.get("sourceUrl"),
                raw_fragment=row,
            )
        )
    if signals:
        return signals[:5]
    return [
        _evidence(
            source_id="scamsniffer_blacklist",
            verdict="unknown",
            confidence=0.35,
            label="No Scam Sniffer blacklist rows were present in the caller payload.",
            categories=["copyleft_raw_feed_review_required"],
            reference=None,
            raw_fragment=payload,
        )
    ]


def _derive_cryptoscamdb(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for key in ("urls", "addresses", "entries", "reports", "data", "results"):
        value = payload.get(key)
        if isinstance(value, dict):
            rows.append(value)
        elif isinstance(value, list):
            rows.extend(item for item in value if isinstance(item, dict))
    if not rows and payload:
        rows = [payload]

    signals: list[dict[str, Any]] = []
    for row in rows[:10]:
        category = str(
            row.get("category")
            or row.get("type")
            or row.get("subcategory")
            or row.get("name")
            or "reported_crypto_scam"
        ).strip()
        timestamped = bool(
            row.get("updated")
            or row.get("created")
            or row.get("date")
            or row.get("timestamp")
            or row.get("reported_at")
        )
        verified = bool(row.get("verified") or row.get("checked"))
        verdict = "malicious" if timestamped or verified else "suspicious"
        confidence = 0.72 if verdict == "malicious" else 0.58
        categories = [category, "staleness_review" if not timestamped else "timestamped"]
        signals.append(
            _evidence(
                source_id="cryptoscamdb",
                verdict=verdict,
                confidence=confidence,
                label="CryptoScamDB reported scam seed",
                categories=categories,
                reference=row.get("url") or row.get("address") or row.get("source"),
                raw_fragment=row,
            )
        )
    if signals:
        return signals[:5]
    return [
        _evidence(
            source_id="cryptoscamdb",
            verdict="unknown",
            confidence=0.35,
            label="No CryptoScamDB rows were present in the caller payload.",
            categories=[],
            reference=None,
            raw_fragment=payload,
        )
    ]


def _derive_ofac(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for key in ("matches", "sdn_rows", "csv_rows", "digital_currency_addresses", "records", "data"):
        value = payload.get(key)
        if isinstance(value, dict):
            rows.append(value)
        elif isinstance(value, list):
            rows.extend(item for item in value if isinstance(item, dict))
    if not rows and payload:
        rows = [payload]

    signals: list[dict[str, Any]] = []
    for row in rows[:10]:
        program = str(row.get("program") or row.get("sanctions_program") or row.get("list") or "OFAC").strip()
        address = row.get("digital_currency_address") or row.get("address") or row.get("wallet")
        matched = bool(row.get("matched") is not False and (address or row.get("sdn_id") or row.get("uid")))
        verdict = "malicious" if matched else "suspicious"
        signals.append(
            _evidence(
                source_id="ofac_sanctions_sls",
                verdict=verdict,
                confidence=0.94 if matched else 0.62,
                label=f"OFAC sanctions-list signal: {program}",
                categories=["sanctions_context", program, "not_legal_advice"],
                reference=row.get("sourceUrl") or row.get("url") or row.get("list_url"),
                raw_fragment=row,
            )
        )
    if signals:
        return signals[:5]
    return [
        _evidence(
            source_id="ofac_sanctions_sls",
            verdict="unknown",
            confidence=0.35,
            label="No OFAC sanctions-list rows were present in the caller payload.",
            categories=["not_legal_advice"],
            reference=None,
            raw_fragment=payload,
        )
    ]


def _derive_goplus(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = _flatten_records(payload)
    risk_terms = {
        "blacklist",
        "phishing",
        "honeypot",
        "malicious",
        "scam",
        "risky",
        "fake",
        "proxy",
        "mintable",
        "cannot_sell",
    }
    signals: list[dict[str, Any]] = []
    for row in rows or [payload]:
        flags = []
        for key, value in row.items():
            key_l = str(key).lower()
            value_l = str(value).lower()
            if any(term in key_l for term in risk_terms) and value_l in {"1", "true", "yes"}:
                flags.append(str(key))
            elif key_l in {"risk_level", "security_level"} and value_l in {"high", "critical"}:
                flags.append(f"{key}:{value}")
        if flags:
            signals.append(
                _evidence(
                    source_id="goplus_security",
                    verdict="malicious",
                    confidence=0.86,
                    label="GoPlus risk flags: " + ", ".join(flags[:6]),
                    categories=flags[:8],
                    reference=row.get("url") or row.get("link") or row.get("reference"),
                    raw_fragment=row,
                )
            )
    if signals:
        return signals[:5]
    return [
        _evidence(
            source_id="goplus_security",
            verdict="unknown",
            confidence=0.35,
            label="No high-risk GoPlus-style flags were present in the caller payload.",
            categories=[],
            reference=None,
            raw_fragment=payload,
        )
    ]


def _derive_chainabuse(payload: dict[str, Any]) -> list[dict[str, Any]]:
    reports = payload.get("reports") or payload.get("data") or payload.get("results") or []
    if isinstance(reports, dict):
        reports = reports.get("reports") or reports.get("items") or [reports]
    if not isinstance(reports, list):
        reports = []

    signals = []
    for report in reports[:10]:
        if not isinstance(report, dict):
            continue
        confidence = _confidence(
            report.get("confidence")
            or report.get("confidenceScore")
            or report.get("confidence_score")
            or (0.82 if report.get("checked") else 0.62)
        )
        category = str(
            report.get("category")
            or report.get("scamCategory")
            or report.get("scam_category")
            or "reported_abuse"
        )
        checked = bool(report.get("checked") or report.get("verified"))
        verdict = "malicious" if checked or confidence >= 0.7 else "suspicious"
        signals.append(
            _evidence(
                source_id="chainabuse",
                verdict=verdict,
                confidence=confidence,
                label=f"Chainabuse report: {category}",
                categories=[category, "checked" if checked else "unchecked"],
                reference=report.get("url") or report.get("link") or report.get("reportUrl"),
                raw_fragment=report,
            )
        )
    report_count = payload.get("reported_count") or payload.get("reportCount") or len(signals)
    if signals:
        return signals[:5]
    if _int(report_count) > 0:
        return [
            _evidence(
                source_id="chainabuse",
                verdict="suspicious",
                confidence=0.66,
                label=f"Chainabuse reported count: {_int(report_count)}",
                categories=["reported_abuse"],
                reference=payload.get("url") or payload.get("link"),
                raw_fragment=payload,
            )
        ]
    return [
        _evidence(
            source_id="chainabuse",
            verdict="unknown",
            confidence=0.35,
            label="No Chainabuse reports were present in the caller payload.",
            categories=[],
            reference=None,
            raw_fragment=payload,
        )
    ]


def _derive_forta(source_id: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    alerts = payload.get("alerts") or []
    labels = payload.get("labels") or payload.get("entities") or payload.get("rows") or []
    signals = []
    for alert in alerts[:10] if isinstance(alerts, list) else []:
        if not isinstance(alert, dict):
            continue
        severity = str(alert.get("severity") or alert.get("metadata", {}).get("severity") or "").lower()
        verdict = "malicious" if severity in {"critical", "high"} else "suspicious"
        signals.append(
            _evidence(
                source_id=source_id,
                verdict=verdict,
                confidence=0.82 if verdict == "malicious" else 0.62,
                label=str(alert.get("name") or alert.get("alertId") or "Forta alert"),
                categories=[severity or "unknown_severity", str(alert.get("botId") or "")],
                reference=alert.get("sourceUrl") or alert.get("url"),
                raw_fragment=alert,
            )
        )
    for label in labels[:10] if isinstance(labels, list) else []:
        if not isinstance(label, dict):
            continue
        label_value = str(label.get("label") or label.get("entityType") or label.get("tag") or "Forta label")
        confidence = _confidence(label.get("confidence") or 0.58)
        verdict = "malicious" if any(
            term in label_value.lower() for term in ("attacker", "phish", "scam", "exploit")
        ) and confidence >= 0.55 else "suspicious"
        signals.append(
            _evidence(
                source_id=source_id,
                verdict=verdict,
                confidence=confidence,
                label=f"Forta label: {label_value}",
                categories=[label_value],
                reference=label.get("sourceUrl") or label.get("url"),
                raw_fragment=label,
            )
        )
    if signals:
        return signals[:5]
    return [
        _evidence(
            source_id=source_id,
            verdict="unknown",
            confidence=0.35,
            label="No Forta alerts or labels were present in the caller payload.",
            categories=[],
            reference=None,
            raw_fragment=payload,
        )
    ]


def _derive_defillama(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for key in ("incidents", "hacks", "records", "data", "results"):
        value = payload.get(key)
        if isinstance(value, dict):
            rows.append(value)
        elif isinstance(value, list):
            rows.extend(item for item in value if isinstance(item, dict))
    if not rows and payload:
        rows = [payload]

    signals: list[dict[str, Any]] = []
    for row in rows[:10]:
        amount = _float(row.get("amount") or row.get("amountUsd") or row.get("loss_usd"))
        bridge_hack = bool(row.get("bridgeHack") or row.get("bridge_hack"))
        technique = str(row.get("technique") or row.get("classification") or "crypto_incident").strip()
        categories = ["incident_context", technique]
        if bridge_hack:
            categories.append("bridge_related")
        verdict = "suspicious" if amount >= 1_000_000 or bridge_hack else "unknown"
        confidence = 0.72 if verdict == "suspicious" else 0.42
        signals.append(
            _evidence(
                source_id="defillama_hacks",
                verdict=verdict,
                confidence=confidence,
                label=f"DeFiLlama incident context: {row.get('name') or technique}",
                categories=categories,
                reference=row.get("source") or row.get("url") or row.get("link"),
                raw_fragment=row,
            )
        )
    if signals:
        return signals[:5]
    return [
        _evidence(
            source_id="defillama_hacks",
            verdict="unknown",
            confidence=0.35,
            label="No DeFiLlama incident rows were present in the caller payload.",
            categories=["incident_context_only"],
            reference=None,
            raw_fragment=payload,
        )
    ]


def _derive_evm_event_index(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for key in ("logs", "transactions", "token_transfers", "approvals", "events", "data"):
        value = payload.get(key)
        if isinstance(value, dict):
            rows.append(value)
        elif isinstance(value, list):
            rows.extend(item for item in value if isinstance(item, dict))
    if not rows and payload:
        rows = [payload]

    signals: list[dict[str, Any]] = []
    unlimited_markers = {
        "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "unlimited",
        "max",
    }
    for row in rows[:10]:
        method = str(row.get("method") or row.get("methodId") or row.get("functionName") or "").lower()
        topic0 = str(row.get("topic0") or row.get("eventTopic") or row.get("event") or "").lower()
        value = str(row.get("value") or row.get("amount") or row.get("allowance") or "").lower()
        spender = str(row.get("spender") or row.get("operator") or row.get("to") or "").strip()
        approval_like = any(token in f"{method} {topic0}" for token in ("approve", "approval", "permit"))
        unlimited = any(marker in value for marker in unlimited_markers)
        if approval_like and unlimited:
            verdict = "malicious"
            confidence = 0.84
            categories = ["approval", "unlimited_allowance"]
        elif approval_like or spender:
            verdict = "suspicious"
            confidence = 0.62
            categories = ["event_context", "approval_like" if approval_like else "spender_context"]
        else:
            verdict = "unknown"
            confidence = 0.35
            categories = ["event_context"]
        signals.append(
            _evidence(
                source_id="evm_event_index",
                verdict=verdict,
                confidence=confidence,
                label=f"EVM event context: {method or topic0 or 'unknown'}",
                categories=categories,
                reference=row.get("txHash") or row.get("hash") or row.get("url"),
                raw_fragment=row,
            )
        )
    return signals[:5] if signals else [
        _evidence(
            source_id="evm_event_index",
            verdict="unknown",
            confidence=0.35,
            label="No EVM event rows were present in the caller payload.",
            categories=["event_context"],
            reference=None,
            raw_fragment=payload,
        )
    ]


def _derive_software_advisory(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for key in ("advisories", "cves", "kev_items", "vulnerabilities", "data", "results"):
        value = payload.get(key)
        if isinstance(value, dict):
            rows.append(value)
        elif isinstance(value, list):
            rows.extend(item for item in value if isinstance(item, dict))
    if not rows and payload:
        rows = [payload]

    signals: list[dict[str, Any]] = []
    for row in rows[:10]:
        severity = str(row.get("severity") or row.get("cvssSeverity") or row.get("baseSeverity") or "").lower()
        cve = str(row.get("cve") or row.get("cveID") or row.get("id") or row.get("ghsaId") or "").strip()
        kev = bool(row.get("knownRansomwareCampaignUse") or row.get("knownExploited") or row.get("kev"))
        if kev or severity in {"critical", "high"}:
            verdict = "suspicious"
            confidence = 0.74 if kev else 0.64
        else:
            verdict = "unknown"
            confidence = 0.42
        categories = ["software_supply_chain", severity or "unknown_severity"]
        if kev:
            categories.append("known_exploited")
        signals.append(
            _evidence(
                source_id="software_advisory_cve",
                verdict=verdict,
                confidence=confidence,
                label=f"Software advisory context: {cve or row.get('packageName') or 'unknown'}",
                categories=categories,
                reference=row.get("url") or row.get("references") or row.get("sourceUrl"),
                raw_fragment=row,
            )
        )
    return signals[:5] if signals else [
        _evidence(
            source_id="software_advisory_cve",
            verdict="unknown",
            confidence=0.35,
            label="No software advisory rows were present in the caller payload.",
            categories=["software_supply_chain"],
            reference=None,
            raw_fragment=payload,
        )
    ]


def _evidence(
    *,
    source_id: str,
    verdict: str,
    confidence: float,
    label: str,
    categories: list[str],
    reference: Any,
    raw_fragment: dict[str, Any],
) -> dict[str, Any]:
    return {
        "sourceId": source_id,
        "verdict": verdict,
        "confidence": round(confidence, 4),
        "label": label[:180],
        "categories": [str(item) for item in categories if str(item).strip()][:8],
        "referenceUrlHash": _hash_text(str(reference)) if reference else "",
        "evidenceHash": _hash_json(raw_fragment),
    }


def _subject(body: dict[str, Any]) -> dict[str, str]:
    subject = body.get("subject") if isinstance(body.get("subject"), dict) else {}
    return {
        "url": str(subject.get("url") or body.get("url") or body.get("domain") or ""),
        "address": str(subject.get("address") or body.get("address") or body.get("target") or ""),
        "chain": str(subject.get("chain") or body.get("chain") or ""),
    }


def _public_subject(subject: dict[str, str]) -> dict[str, str]:
    return {
        "urlHash": _hash_text(subject["url"]) if subject["url"] else "",
        "addressRedacted": _redact(subject["address"]),
        "chain": subject["chain"],
    }


def _upstream_payload(body: dict[str, Any]) -> dict[str, Any]:
    payload = body.get("payload")
    if isinstance(payload, dict):
        return payload
    return {
        key: value
        for key, value in body.items()
        if key not in {"sourceId", "source_id", "subject", "url", "domain", "address", "target", "chain"}
    }


def _flatten_records(payload: dict[str, Any]) -> list[dict[str, Any]]:
    result = payload.get("result") or payload.get("data") or payload.get("results") or payload
    if isinstance(result, list):
        return [row for row in result if isinstance(row, dict)]
    if isinstance(result, dict):
        if any(isinstance(value, dict) for value in result.values()):
            return [value for value in result.values() if isinstance(value, dict)]
        return [result]
    return []


def _domain_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in (
        "domain_rows",
        "active_domains",
        "domains",
        "blocklist",
        "list",
        "results",
        "data",
        "threats",
    ):
        value = payload.get(key)
        if isinstance(value, dict):
            nested = _domain_rows(value)
            rows.extend(nested or [value])
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    if key == "active_domains" and "active" not in item:
                        rows.append({**item, "active": True})
                    else:
                        rows.append(item)
                elif isinstance(item, str):
                    if key == "active_domains":
                        rows.append({"domain": item, "active": True})
                    else:
                        rows.append({"domain": item})
    if not rows and any(key in payload for key in ("domain", "url", "target_brand", "site_status")):
        rows.append(payload)
    return rows


def _address_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key in ("addresses", "wallets", "blacklist", "entries", "results", "data"):
        value = payload.get(key)
        if isinstance(value, dict):
            if any(field in value for field in ("address", "wallet", "chain")):
                rows.append(value)
            else:
                rows.extend(item for item in value.values() if isinstance(item, dict))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    rows.append(item)
                elif isinstance(item, str) and item.startswith("0x"):
                    rows.append({"address": item})
    if not rows and any(key in payload for key in ("address", "wallet", "chain")):
        rows.append(payload)
    return rows


def _next_step(source_id: str, derived: list[dict[str, Any]]) -> str:
    if any(item["verdict"] in {"malicious", "suspicious"} for item in derived):
        return "Pass derivedEvidence into /api/reputation/probe or /api/threat-case-file before any signer surface."
    return f"Keep {source_id} in shadow mode until live payloads prove material alert-quality lift."


def _confidence(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.5
    if number > 1:
        number = number / 100
    return max(0.0, min(1.0, number))


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _float(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _safety() -> dict[str, bool]:
    return {
        "readOnly": True,
        "networkCalls": False,
        "liveConnectorFetch": False,
        "telegramSendsEnabled": False,
        "socialPostingEnabled": False,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "paymentSettlementEnabled": False,
        "exchangeOrdersEnabled": False,
        "bridgingEnabled": False,
        "moneyMovementEnabled": False,
        "rawPayloadsReturned": False,
    }


def _rights_policy() -> dict[str, bool]:
    return {
        "rawPayloadsReturned": False,
        "rawPayloadResaleAllowed": False,
        "sourceLinksOrHashesOnly": True,
        "paymentIsNotPermission": True,
        "callerPayloadTreatedAsUntrusted": True,
    }


def _redact(value: str) -> str:
    value = str(value or "")
    if len(value) <= 16:
        return "***" if value else ""
    return f"{value[:6]}...{value[-6:]}"


def _hash_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
