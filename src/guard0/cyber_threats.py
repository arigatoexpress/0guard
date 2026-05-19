"""Web2/Web3 cyber-threat repository for wallet protection.

The repository composes existing rights-aware OSINT, reputation, and incident
features into a single defensive view. Live fetches are opt-in, derived-only,
and scoped to public official feeds or exact-address screening.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from guard0.incident_data import detection_coverage, incident_summary
from guard0.osint import load_source_registry
from guard0.reputation_connector_worker import (
    CISA_KEV_SOURCE_ID,
    NVD_CVE_SOURCE_ID,
    OFAC_SANCTIONS_SOURCE_ID,
    cisa_kev_snapshot,
    nvd_cve_snapshot,
    ofac_sanctions_snapshot,
)

CYBER_THREAT_REPOSITORY_SCHEMA = "0guard.cyber_threat_repository.v1"


def build_cyber_threat_repository(
    *,
    live: bool = False,
    limit: int = 5,
    address: str = "",
    cve_ids: list[str] | tuple[str, ...] | str | None = None,
    include_ofac: bool = False,
) -> dict[str, Any]:
    """Return a source-cited Web2/Web3 threat repository snapshot."""
    if limit < 1 or limit > 25:
        raise ValueError("limit must be between 1 and 25")

    registry_by_id = {
        str(source.get("id")): source
        for source in load_source_registry().get("sources", [])
        if isinstance(source, dict)
    }
    cves = _normalize_cve_ids(cve_ids)
    connectors = [
        cisa_kev_snapshot(live=live, limit=limit, cve_ids=cves),
        nvd_cve_snapshot(live=live, limit=limit, cve_ids=cves),
    ]
    ofac_live = bool(live and (include_ofac or address))
    connectors.append(
        ofac_sanctions_snapshot(live=ofac_live, limit=limit, address=address)
    )
    mitre_context = _mitre_context(registry_by_id)
    incident = incident_summary()
    coverage = detection_coverage()
    derived_evidence = [
        evidence
        for snapshot in connectors
        for evidence in snapshot.get("derivedEvidence", [])
        if isinstance(evidence, dict)
    ]
    repository = {
        "schema": CYBER_THREAT_REPOSITORY_SCHEMA,
        "generatedAt": _now(),
        "mode": "live_fetch_derived_only" if live else "catalog_and_local_features",
        "live": live,
        "scope": {
            "web2": [
                "software vulnerabilities",
                "known exploited CVEs",
                "browser and extension attack surface",
                "supply-chain malware",
                "credential theft",
            ],
            "web3": [
                "wallet approvals",
                "permit and EIP-712 replay",
                "drainer domains",
                "bridge and oracle exploits",
                "sanctions and AML review signals",
            ],
            "walletProtectionDefault": "review_before_signing_or_broadcast",
        },
        "sourcePosture": _source_posture(registry_by_id),
        "officialConnectorSnapshots": connectors,
        "mitreTtpContext": mitre_context,
        "historicalCryptoExploitCoverage": {
            "incidentCount": incident.get("incidentCount"),
            "totalLossUsd": incident.get("totalLossUsd"),
            "coverageRatio": coverage.get("coverageRatio"),
            "matchedCount": coverage.get("matchedCount"),
            "attackVectorCounts": incident.get("attackVectorCounts"),
        },
        "attackPatternTaxonomy": _attack_pattern_taxonomy(),
        "detectorPromotionCandidates": _detector_candidates(derived_evidence, mitre_context),
        "requestedCveIds": cves,
        "subject": {
            "addressRedacted": _redact_address(address),
            "addressHash": _hash_text(address.lower()) if _is_evm_address(address) else "",
            "rawAddressReturned": False,
        },
        "repositoryReceipt": {
            "hash": _hash_json(
                {
                    "live": live,
                    "connectors": [
                        (snapshot.get("snapshotReceipt") or {}).get("hash", "")
                        for snapshot in connectors
                    ],
                    "mitre": [item["id"] for item in mitre_context],
                    "coverageRatio": coverage.get("coverageRatio"),
                    "addressHash": _hash_text(address.lower()) if _is_evm_address(address) else "",
                    "cves": cves,
                }
            ),
            "algorithm": "sha256_canonical_json",
            "zeroGChainReady": True,
            "zeroGStorageReady": True,
            "liveAnchorPerformed": False,
            "liveUploadPerformed": False,
        },
        "nextBuildOrder": [
            "Promote exact-address OFAC and Chainalysis/TRM vendor checks only after terms, key custody, and retention policy are approved.",
            "Backfill advisory-derived features into the historical feature store without copying raw CVE or sanctions payloads.",
            "Correlate Web2 CVE exposure with actual dapp/extension/browser dependency inventories before blocking a wallet action.",
            "Use MITRE ATT&CK TTPs to guide detector hypotheses, not to attribute a wallet or project by themselves.",
        ],
        "rightsPolicy": _rights_policy(),
        "safety": _safety(live=live, ofac_live=ofac_live),
    }
    repository["rawPayloadsReturned"] = False
    return repository


def _source_posture(registry_by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for source_id in (
        CISA_KEV_SOURCE_ID,
        NVD_CVE_SOURCE_ID,
        "mitre_attack_lazarus_g0032",
        "mitre_attack_shai_hulud_s9008",
        OFAC_SANCTIONS_SOURCE_ID,
        "chainalysis_sanctions_oracle",
        "chainalysis_sanctions_api",
        "trm_wallet_screening",
        "urlhaus",
        "threatfox_iocs",
        "google_web_risk",
    ):
        source = registry_by_id.get(source_id, {})
        rows.append(
            {
                "sourceId": source_id,
                "name": source.get("name") or source_id,
                "owner": source.get("owner", ""),
                "url": source.get("homepage") or source.get("url", ""),
                "retrievalMode": source.get("retrieval_mode", "catalog_or_planned"),
                "enabledByDefault": bool(source.get("enabled_by_default")),
                "outputPolicy": source.get("output_policy", "derived features only"),
                "caveats": source.get("caveats", ""),
            }
        )
    return rows


def _mitre_context(registry_by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    lazarus = registry_by_id.get("mitre_attack_lazarus_g0032", {})
    shai_hulud = registry_by_id.get("mitre_attack_shai_hulud_s9008", {})
    return [
        {
            "id": "mitre_attack_lazarus_g0032",
            "sourceName": lazarus.get("name") or "MITRE ATT&CK Lazarus Group G0032",
            "referenceUrl": lazarus.get("url") or "https://attack.mitre.org/groups/G0032/",
            "contextType": "adversary_ttp_context",
            "defensiveUse": "Map phishing, supply-chain, credential theft, and infrastructure-compromise hypotheses.",
            "walletVerdictPolicy": "context_only_not_wallet_attribution",
            "notAttribution": True,
            "mappedPatterns": [
                "social_engineering",
                "credential_theft",
                "supply_chain_compromise",
                "infrastructure_compromise",
            ],
        },
        {
            "id": "mitre_attack_shai_hulud_s9008",
            "sourceName": shai_hulud.get("name") or "MITRE ATT&CK Shai-Hulud S9008",
            "referenceUrl": shai_hulud.get("url") or "https://attack.mitre.org/software/S9008/",
            "contextType": "software_supply_chain_malware_context",
            "defensiveUse": "Track package-manager and credential-harvesting patterns that can compromise dapp frontends and developer wallets.",
            "walletVerdictPolicy": "context_only_requires_direct_wallet_or_dependency_evidence",
            "notAttribution": True,
            "mappedPatterns": [
                "npm_supply_chain",
                "credential_harvesting",
                "ci_cd_secret_exposure",
                "developer_workstation_compromise",
            ],
        },
    ]


def _attack_pattern_taxonomy() -> list[dict[str, Any]]:
    return [
        {
            "id": "wallet_approval_drainer",
            "plainEnglish": "A fake site asks for a signature or approval that lets an attacker move tokens later.",
            "technicalSignals": ["approve", "permit", "setApprovalForAll", "unlimited_allowance"],
            "defaultAction": "deny_or_review_before_wallet_prompt",
        },
        {
            "id": "frontend_or_extension_compromise",
            "plainEnglish": "The page or wallet-extension path is changed before the user sees the transaction.",
            "technicalSignals": ["unexpected_origin", "dependency_cve", "script_supply_chain", "provider_injection"],
            "defaultAction": "review_with_origin_and_dependency_context",
        },
        {
            "id": "sanctioned_counterparty_exposure",
            "plainEnglish": "The target wallet may be linked to a sanctioned entity or sanctioned infrastructure.",
            "technicalSignals": ["ofac_exact_address_match", "vendor_screening_match", "chainalysis_oracle_match"],
            "defaultAction": "block_or_escalate_to_operator_review_not_legal_advice",
        },
        {
            "id": "bridge_message_or_oracle_abuse",
            "plainEnglish": "A cross-chain or price-feed dependency can be forged, delayed, or manipulated.",
            "technicalSignals": ["bridge_forgery", "oracle_manipulation", "message_replay", "dvn_config_risk"],
            "defaultAction": "deny_high_risk_transaction_until_state_is_verified",
        },
        {
            "id": "web2_known_exploited_vulnerability",
            "plainEnglish": "The software around the wallet or dapp has a known exploited vulnerability.",
            "technicalSignals": ["cisa_kev", "nvd_high_or_critical", "dependency_inventory_match"],
            "defaultAction": "review_if_exposed_dependency_matches_runtime",
        },
    ]


def _detector_candidates(
    evidence: list[dict[str, Any]],
    mitre_context: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for item in evidence[:10]:
        categories = item.get("categories") if isinstance(item.get("categories"), list) else []
        candidates.append(
            {
                "sourceId": item.get("sourceId"),
                "verdict": item.get("verdict"),
                "confidence": item.get("confidence"),
                "evidenceHash": item.get("evidenceHash"),
                "candidateRule": "review_action_when_source_evidence_matches_subject",
                "categories": categories,
                "promotionAutomatic": False,
            }
        )
    for item in mitre_context:
        candidates.append(
            {
                "sourceId": item["id"],
                "verdict": "context",
                "confidence": 0.45,
                "evidenceHash": _hash_json(item),
                "candidateRule": "use_ttp_as_detector_hypothesis_only",
                "categories": item["mappedPatterns"],
                "promotionAutomatic": False,
            }
        )
    return candidates[:12]


def _normalize_cve_ids(value: list[str] | tuple[str, ...] | str | None) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items = value.replace(";", ",").split(",")
    else:
        items = list(value)
    cves: list[str] = []
    seen: set[str] = set()
    for item in items:
        cve = str(item or "").strip().upper()
        if cve.startswith("CVE-") and cve not in seen:
            seen.add(cve)
            cves.append(cve)
    return cves[:25]


def _rights_policy() -> dict[str, bool]:
    return {
        "rawPayloadsReturned": False,
        "rawPayloadResaleAllowed": False,
        "rawSanctionsListReturned": False,
        "rawExploitPayloadsReturned": False,
        "sourceLinksOrHashesOnly": True,
        "derivedEvidenceOnly": True,
        "paidAccessMayUnlockDerivedArtifactsOnly": True,
    }


def _safety(*, live: bool, ofac_live: bool) -> dict[str, bool]:
    return {
        "readOnly": True,
        "networkCalls": live,
        "liveOfacFetch": ofac_live,
        "rawPayloadsReturned": False,
        "rawAddressesReturned": False,
        "notLegalAdvice": True,
        "notAttribution": True,
        "privateKeyRequired": False,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "telegramSendsEnabled": False,
        "socialPostingEnabled": False,
        "paymentSettlementEnabled": False,
        "bridgingEnabled": False,
        "swappingEnabled": False,
    }


def _is_evm_address(value: str) -> bool:
    raw = str(value or "").strip()
    return len(raw) == 42 and raw.startswith("0x") and all(ch in "0123456789abcdefABCDEF" for ch in raw[2:])


def _redact_address(value: str) -> str:
    raw = str(value or "").strip()
    if not _is_evm_address(raw):
        return ""
    normalized = raw.lower()
    return f"{normalized[:6]}...{normalized[-4:]}"


def _hash_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
