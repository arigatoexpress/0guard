"""Rights-aware counterparty and domain reputation probes for 0guard."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from guard0.crypto_hack_guard import KNOWN_MALICIOUS_ADDRESSES
from guard0.osint import load_source_registry
from guard0.policy import evaluate_intent

REPUTATION_PROBE_SCHEMA = "0guard.reputation_probe.v1"
REPUTATION_CONNECTORS_SCHEMA = "0guard.reputation_connectors.v1"

REPUTATION_CONNECTOR_CANDIDATES = (
    {
        "sourceId": "phishdestroy_destroylist",
        "priority": 1,
        "stage": "open_source_first_connector",
        "surfaces": ("domain", "url"),
        "useCases": (
            "active phishing-domain detection",
            "crypto-drainer and impersonated-brand context",
            "Telegram link and dApp domain preflight checks",
        ),
    },
    {
        "sourceId": "cryptoscamdb",
        "priority": 1,
        "stage": "open_dataset_seed",
        "surfaces": ("evm_address", "domain"),
        "useCases": (
            "open phishing-domain and address seeds",
            "regression fixtures for reputation detector tests",
        ),
    },
    {
        "sourceId": "forta_labelled_datasets",
        "priority": 1,
        "stage": "offline_label_seed",
        "surfaces": ("evm_address", "contract", "domain"),
        "useCases": (
            "labelled malicious-address and contract seeds",
            "offline regression data for behavior and signature detectors",
        ),
    },
    {
        "sourceId": "goplus_security",
        "priority": 2,
        "stage": "keyed_connector_candidate",
        "surfaces": ("evm_address", "evm_token", "domain"),
        "useCases": (
            "address and token risk enrichment",
            "approval and dApp preflight context",
            "phishing and malicious-site corroboration",
        ),
    },
    {
        "sourceId": "chainabuse",
        "priority": 2,
        "stage": "keyed_connector_candidate",
        "surfaces": ("evm_address", "domain"),
        "useCases": (
            "reported scam and abuse corroboration",
            "human-readable source links for wallet review",
        ),
    },
    {
        "sourceId": "forta_graphql_api",
        "priority": 2,
        "stage": "detector_stream",
        "surfaces": ("evm_address", "contract", "chain_activity"),
        "useCases": (
            "exploit-stage alerts and labels",
            "direct wallet relevance checks before alert promotion",
        ),
    },
    {
        "sourceId": "scam_sniffer_database",
        "priority": 2,
        "stage": "delayed_phishing_database",
        "surfaces": ("domain", "url"),
        "useCases": (
            "delayed open scam-domain corroboration",
            "browser and Telegram link preflight context with explicit license gating",
        ),
    },
    {
        "sourceId": "chainalysis_sanctions_oracle",
        "priority": 3,
        "stage": "binary_sanctions_precheck",
        "surfaces": ("evm_address", "contract"),
        "useCases": (
            "binary sanctions-oracle precheck for EVM counterparties",
            "receipt-level compliance context without treating it as legal advice",
        ),
    },
    {
        "sourceId": "chainalysis_sanctions_api",
        "priority": 3,
        "stage": "backend_sanctions_api_precheck",
        "surfaces": ("evm_address", "contract"),
        "useCases": (
            "backend exact-address sanctions screening with higher-volume API limits",
            "derived sanctions category and source-link evidence for operator review",
        ),
    },
    {
        "sourceId": "trm_wallet_screening",
        "priority": 3,
        "stage": "commercial_wallet_risk_candidate",
        "surfaces": ("evm_address", "contract", "evm_transaction"),
        "useCases": (
            "pre-transaction wallet risk and attribution review",
            "sanctions, scam, fraud, and indirect-exposure corroboration when vendor access is approved",
        ),
    },
    {
        "sourceId": "trm_blockint_api",
        "priority": 4,
        "stage": "commercial_blockchain_intelligence_candidate",
        "surfaces": ("evm_address", "contract", "chain_activity"),
        "useCases": (
            "high-volume blockchain-intelligence enrichment",
            "entity, balance, activity-window, exposure, and transaction-history derived features",
        ),
    },
    {
        "sourceId": "urlhaus",
        "priority": 3,
        "stage": "malware_infrastructure_corroboration",
        "surfaces": ("domain", "url"),
        "useCases": (
            "malware URL and infrastructure corroboration",
            "second-order host reputation for malicious dApp and phishing links",
        ),
    },
    {
        "sourceId": "threatfox_iocs",
        "priority": 3,
        "stage": "ioc_digest_candidate",
        "surfaces": ("domain", "url", "ip", "file_hash"),
        "useCases": (
            "recent IOC and malware-family corroboration",
            "fresh infrastructure signals for phishing and wallet-drainer context",
        ),
    },
    {
        "sourceId": "google_web_risk",
        "priority": 4,
        "stage": "commercial_url_safety_lookup",
        "surfaces": ("domain", "url"),
        "useCases": (
            "commercial-safe malicious URL lookup",
            "browser and Telegram link safety when open phishing feeds are insufficient",
        ),
    },
    {
        "sourceId": "toncenter_v3",
        "priority": 3,
        "stage": "telegram_ton_passport",
        "surfaces": ("ton_account", "telegram_wallet"),
        "useCases": (
            "read-only TON account activity enrichment",
            "TON passport context inside Telegram Mini Apps",
        ),
    },
    {
        "sourceId": "tonapi_jettons",
        "priority": 3,
        "stage": "telegram_ton_passport",
        "surfaces": ("ton_account", "jetton", "telegram_wallet"),
        "useCases": (
            "Jetton and NFT exposure context",
            "Telegram wallet alert quality gates",
        ),
    },
    {
        "sourceId": "tenderly_simulation",
        "priority": 4,
        "stage": "simulation_adapter",
        "surfaces": ("evm_transaction", "contract_call"),
        "useCases": (
            "pre-signing state-delta summaries",
            "approval, swap, and contract-call simulation evidence",
        ),
    },
    {
        "sourceId": "blocksec_phalcon_simulation",
        "priority": 4,
        "stage": "simulation_adapter",
        "surfaces": ("evm_transaction", "contract_call"),
        "useCases": (
            "second-opinion simulation",
            "incident-context enrichment without raw trace resale",
        ),
    },
    {
        "sourceId": "layerzeroscan_api",
        "priority": 5,
        "stage": "cross_chain_observability",
        "surfaces": ("cross_chain_message", "layerzero"),
        "useCases": (
            "message-status and configuration posture",
            "stuck-message or unsafe-routing context",
        ),
    },
    {
        "sourceId": "wormholescan_api",
        "priority": 5,
        "stage": "cross_chain_observability",
        "surfaces": ("cross_chain_message", "wormhole"),
        "useCases": (
            "VAA and transfer-status context",
            "read-only Wormhole guardrail evidence",
        ),
    },
)

CURATED_DOMAIN_ALLOWLIST = (
    "0g.ai",
    "docs.0g.ai",
    "hackquest.io",
    "github.com",
)

_BAD_LABEL_TERMS = (
    "abuse",
    "attack",
    "compromised",
    "drain",
    "drainer",
    "exploit",
    "hack",
    "malicious",
    "phish",
    "scam",
    "spoof",
)
_GOOD_LABEL_TERMS = (
    "allow",
    "benign",
    "known_good",
    "trusted",
    "verified",
)
_EVM_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def build_reputation_probe(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a deterministic reputation verdict without raw-source resale."""
    body = payload or {}
    if not isinstance(body, dict):
        raise ValueError("payload must be an object")

    subject = _subject_from_payload(body)
    signals: list[dict[str, Any]] = []
    signals.extend(_domain_signals(subject["domain"], subject["urlHash"]))
    signals.extend(_address_signals(subject["address"]))
    signals.extend(_label_signals(body.get("labels") or body.get("tags") or []))
    signals.extend(_source_evidence_signals(body.get("sourceEvidence") or body.get("evidence") or []))
    signals.extend(_intent_signals(body.get("intent"), subject))

    decision = _rollup(signals)
    receipt_hash = _hash_json(
        {
            "schema": REPUTATION_PROBE_SCHEMA,
            "subject": subject,
            "decision": decision["decision"],
            "signals": signals,
        }
    )
    safety = _safety()
    return {
        "schema": REPUTATION_PROBE_SCHEMA,
        "generatedAt": _now(),
        "mode": "derived_reputation_no_raw_resale",
        "subject": subject,
        "decision": decision,
        "rawPayloadsReturned": False,
        "signalCount": len(signals),
        "signals": signals,
        "receipt": {
            "hash": receipt_hash,
            "algorithm": "sha256_canonical_json",
            "zeroGChainReady": True,
            "zeroGStorageReady": True,
            "liveAnchorPerformed": False,
            "liveUploadPerformed": False,
        },
        "rightsPolicy": {
            "rawPayloadsReturned": False,
            "rawPayloadResaleAllowed": False,
            "sourceLinksOrHashesOnly": True,
            "callerEvidenceTreatedAsUntrusted": True,
        },
        "recommendedNextStep": _next_step(decision["decision"]),
        "safety": safety,
    }


def reputation_connector_manifest(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the planned external reputation connectors without fetching them."""
    body = payload or {}
    if not isinstance(body, dict):
        raise ValueError("payload must be an object")

    subject = _subject_from_payload(body)
    registry = load_source_registry()
    sources_by_id = {source["id"]: source for source in registry.get("sources", [])}
    connectors = []
    for spec in REPUTATION_CONNECTOR_CANDIDATES:
        source = sources_by_id.get(spec["sourceId"])
        if not source:
            continue
        connectors.append(_connector_row(source, spec, subject))

    return {
        "schema": REPUTATION_CONNECTORS_SCHEMA,
        "generatedAt": _now(),
        "mode": "connector_manifest_no_network_calls",
        "subject": subject,
        "connectorCount": len(connectors),
        "recommendedActivationOrder": [
            row["id"] for row in sorted(connectors, key=lambda item: item["priority"])
        ],
        "connectors": connectors,
        "activationRules": [
            "keep every external connector disabled until credentials, terms, and retention are reviewed",
            "return derived verdicts, labels, confidence, source ids, links, hashes, and redacted addresses only",
            "never return paid/raw payloads through public APIs",
            "require direct wallet or source relevance before promoting a Telegram alert",
            "route every external signal through /api/reputation/probe or /api/native-preflight before any signer surface",
        ],
        "rightsPolicy": {
            "rawPayloadsReturned": False,
            "rawPayloadResaleAllowed": False,
            "sourceLinksOrHashesOnly": True,
            "paymentIsNotPermission": True,
        },
        "safety": _safety(),
    }


def domain_decision(url: str) -> dict[str, Any]:
    """Return the curated-domain allowlist posture used by the legacy domain route."""
    parsed = _parse_url_or_host(url)
    host = parsed.hostname
    for allowed in sorted(CURATED_DOMAIN_ALLOWLIST, key=len, reverse=True):
        allowed_host = allowed.lower()
        if host == allowed_host or host.endswith(f".{allowed_host}"):
            return {"host": host, "allowed": True, "matched": allowed_host}
    return {"host": host, "allowed": False, "matched": None}


def _subject_from_payload(body: dict[str, Any]) -> dict[str, Any]:
    raw_url = str(body.get("url") or body.get("domain") or body.get("website") or "").strip()
    parsed = _parse_url_or_host(raw_url) if raw_url else None
    address = str(
        body.get("address")
        or body.get("target")
        or body.get("to")
        or body.get("counterparty")
        or ""
    ).strip()
    chain = str(body.get("chain") or body.get("caip2") or "").strip()
    return {
        "domain": parsed.hostname if parsed else "",
        "urlHash": _hash_text(raw_url) if raw_url else "",
        "address": address,
        "addressRedacted": _redact_address(address),
        "chain": chain,
        "surface": str(body.get("surface") or body.get("sourceProject") or "").strip(),
    }


def _parse_url_or_host(value: str):
    parsed = urlparse(value if "://" in value else f"https://{value}")
    host = (parsed.hostname or "").lower().rstrip(".")
    return parsed._replace(netloc=host)


def _domain_signals(domain: str, url_hash: str) -> list[dict[str, Any]]:
    if not domain:
        return []
    decision = domain_decision(domain)
    if decision["allowed"]:
        return [
            _signal(
                "trusted_domain_allowlist",
                "allow",
                "low",
                f"Domain matches curated allowlist host {decision['matched']}.",
                evidence={"domain": domain, "urlHash": url_hash},
            )
        ]

    for allowed in CURATED_DOMAIN_ALLOWLIST:
        allowed_host = allowed.lower()
        if allowed_host in domain:
            return [
                _signal(
                    "allowlist_suffix_spoof",
                    "deny",
                    "high",
                    f"Untrusted domain embeds curated host {allowed_host}.",
                    evidence={"domain": domain, "matchedAllowlistText": allowed_host},
                )
            ]

    return [
        _signal(
            "domain_not_allowlisted",
            "review",
            "medium",
            "Domain is not in the curated allowlist.",
            evidence={"domain": domain, "urlHash": url_hash},
        )
    ]


def _address_signals(address: str) -> list[dict[str, Any]]:
    if not address:
        return []
    known = {item.lower(): item for item in KNOWN_MALICIOUS_ADDRESSES}
    if address.lower() in known:
        return [
            _signal(
                "known_malicious_counterparty",
                "deny",
                "critical",
                "Counterparty matches a known malicious or compromised address indicator.",
                evidence={"addressRedacted": _redact_address(address), "source": "0guard_ioc_set"},
            )
        ]
    if address.startswith("0x") and not _EVM_ADDRESS_RE.match(address):
        return [
            _signal(
                "malformed_evm_address",
                "review",
                "medium",
                "Counterparty looks like an EVM address but has invalid syntax.",
                evidence={"addressRedacted": _redact_address(address)},
            )
        ]
    if _EVM_ADDRESS_RE.match(address):
        return [
            _signal(
                "evm_address_syntax_valid",
                "allow",
                "low",
                "Counterparty has valid EVM address syntax and no local IOC match.",
                evidence={"addressRedacted": _redact_address(address)},
            )
        ]
    return [
        _signal(
            "non_evm_counterparty_unresolved",
            "review",
            "medium",
            "Counterparty is non-EVM or unresolved by the local reputation probe.",
            evidence={"addressRedacted": _redact_address(address)},
        )
    ]


def _label_signals(labels: Any) -> list[dict[str, Any]]:
    if isinstance(labels, str):
        labels = [labels]
    if not isinstance(labels, list):
        return []
    signals = []
    for label in [str(item).strip() for item in labels if str(item).strip()][:10]:
        norm = label.lower()
        if any(term in norm for term in _BAD_LABEL_TERMS):
            signals.append(
                _signal(
                    "caller_bad_reputation_label",
                    "deny",
                    "high",
                    "Caller-supplied label indicates malicious or spoofed behavior.",
                    evidence={"label": label},
                )
            )
        elif any(term in norm for term in _GOOD_LABEL_TERMS):
            signals.append(
                _signal(
                    "caller_good_reputation_label",
                    "allow",
                    "low",
                    "Caller-supplied label indicates a trusted or verified entity.",
                    evidence={"label": label},
                )
            )
    return signals


def _source_evidence_signals(evidence: Any) -> list[dict[str, Any]]:
    if not isinstance(evidence, list):
        return []
    signals = []
    for row in evidence[:10]:
        if not isinstance(row, dict):
            continue
        verdict = str(row.get("verdict") or row.get("decision") or row.get("label") or "").lower()
        confidence = _confidence(row.get("confidence"))
        source_id = str(row.get("sourceId") or row.get("source_id") or "caller_evidence").strip()
        label = str(row.get("label") or verdict or "unspecified").strip()
        evidence_hash = _hash_json(
            {
                "sourceId": source_id,
                "verdict": verdict,
                "confidence": confidence,
                "label": label,
                "url": row.get("url") or row.get("referenceUrl"),
            }
        )
        if any(term in verdict or term in label.lower() for term in _BAD_LABEL_TERMS):
            signals.append(
                _signal(
                    "source_negative_vote",
                    "deny" if confidence >= 0.8 else "review",
                    "high" if confidence >= 0.8 else "medium",
                    "Caller-provided source evidence reports negative reputation.",
                    evidence={
                        "sourceId": source_id,
                        "confidence": confidence,
                        "label": label,
                        "evidenceHash": evidence_hash,
                    },
                )
            )
        elif any(term in verdict or term in label.lower() for term in _GOOD_LABEL_TERMS):
            signals.append(
                _signal(
                    "source_positive_vote",
                    "allow",
                    "low",
                    "Caller-provided source evidence reports positive reputation.",
                    evidence={
                        "sourceId": source_id,
                        "confidence": confidence,
                        "label": label,
                        "evidenceHash": evidence_hash,
                    },
                )
            )
    return signals


def _intent_signals(intent: Any, subject: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(intent, dict) or not intent:
        return []
    enriched = {
        **intent,
        "target_contract": intent.get("target_contract") or subject.get("address"),
        "app": intent.get("app") or subject.get("domain") or subject.get("surface"),
    }
    decision = evaluate_intent(enriched).to_dict()
    if decision["decision"] == "allow":
        return [
            _signal(
                "intent_policy_allow",
                "allow",
                "low",
                "Intent policy check did not find blockers or warnings.",
                evidence={"receiptHash": decision["receipt_hash"]},
            )
        ]
    return [
        _signal(
            "intent_policy_reputation_context",
            decision["decision"],
            "critical" if decision["decision"] == "deny" else "medium",
            "Intent policy check found signer, calldata, secret, or exploit-pattern risk.",
            evidence={
                "receiptHash": decision["receipt_hash"],
                "blockerCount": len(decision.get("blockers") or []),
                "warningCount": len(decision.get("warnings") or []),
            },
        )
    ]


def _rollup(signals: list[dict[str, Any]]) -> dict[str, Any]:
    blockers = [signal for signal in signals if signal["decision"] == "deny"]
    reviews = [signal for signal in signals if signal["decision"] == "review"]
    if blockers:
        return {
            "decision": "deny",
            "severity": "critical" if any(s["severity"] == "critical" for s in blockers) else "high",
            "riskScore": 96 if any(s["severity"] == "critical" for s in blockers) else 88,
            "reasons": [signal["reason"] for signal in blockers[:5]],
        }
    if reviews:
        return {
            "decision": "review",
            "severity": "medium",
            "riskScore": 62,
            "reasons": [signal["reason"] for signal in reviews[:5]],
        }
    return {
        "decision": "allow",
        "severity": "low",
        "riskScore": 8 if signals else 15,
        "reasons": ["No negative local reputation signals matched."],
    }


def _connector_row(
    source: dict[str, Any],
    spec: dict[str, Any],
    subject: dict[str, Any],
) -> dict[str, Any]:
    retrieval_mode = str(source.get("retrieval_mode") or "")
    adapter = str(source.get("adapter") or "")
    enabled_by_default = bool(source.get("enabled_by_default"))
    return {
        "id": source["id"],
        "name": source.get("name"),
        "owner": source.get("owner"),
        "priority": spec["priority"],
        "stage": spec["stage"],
        "status": "catalog_enabled" if enabled_by_default else "planned_disabled",
        "adapter": source.get("adapter"),
        "retrievalMode": retrieval_mode,
        "credentialRequired": retrieval_mode in ("api_key_required", "auth_required")
        or "paid" in retrieval_mode
        or "commercial" in retrieval_mode
        or adapter == "auth_required",
        "enabledByDefault": enabled_by_default,
        "appliesToSubject": _connector_applies(spec["surfaces"], subject),
        "surfaces": list(spec["surfaces"]),
        "useCases": list(spec["useCases"]),
        "docsUrl": source.get("url"),
        "homepage": source.get("homepage"),
        "freshnessTtlSeconds": source.get("freshness_ttl_seconds"),
        "rightsBoundary": {
            "licenseOrRights": source.get("license_or_rights"),
            "outputPolicy": source.get("output_policy"),
            "caveats": source.get("caveats"),
            "rawPayloadsReturned": False,
        },
    }


def _connector_applies(surfaces: tuple[str, ...], subject: dict[str, Any]) -> bool:
    if not any((subject.get("domain"), subject.get("address"), subject.get("chain"), subject.get("surface"))):
        return False
    address = str(subject.get("address") or "")
    chain = str(subject.get("chain") or "").lower()
    surface = str(subject.get("surface") or "").lower()
    if subject.get("domain") and "domain" in surfaces:
        return True
    if _EVM_ADDRESS_RE.match(address) and any(
        item in surfaces for item in ("evm_address", "evm_transaction", "contract_call")
    ):
        return True
    if chain.startswith("ton") or "ton" in surface or "telegram" in surface:
        return any(item in surfaces for item in ("ton_account", "telegram_wallet", "jetton"))
    if any(term in chain or term in surface for term in ("layerzero", "wormhole", "cross")):
        return "cross_chain_message" in surfaces
    return False


def _signal(
    signal_id: str,
    decision: str,
    severity: str,
    reason: str,
    *,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": signal_id,
        "decision": decision,
        "severity": severity,
        "reason": reason,
        "evidence": evidence,
    }


def _confidence(value: Any) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return 0.5
    return max(0.0, min(1.0, parsed))


def _next_step(decision: str) -> str:
    if decision == "deny":
        return "Stop before signer access and attach the reputation receipt to the review path."
    if decision == "review":
        return "Show the reputation reasons, request stronger evidence, and keep the flow simulation-only."
    return "Reputation context is acceptable; live actions still need native preflight and operator policy."


def _redact_address(address: str) -> str:
    value = str(address or "").strip()
    if len(value) <= 12:
        return value
    return f"{value[:6]}...{value[-4:]}"


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _hash_json(payload: dict[str, Any]) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(blob).hexdigest()


def _safety() -> dict[str, bool]:
    return {
        "readOnly": True,
        "networkCalls": False,
        "rawPayloadsReturned": False,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "privateKeyImportEnabled": False,
        "walletCreationEnabled": False,
        "telegramSendsEnabled": False,
        "moneyMovementEnabled": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
