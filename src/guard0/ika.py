"""Read-only Ika, Encrypt, and Ikavery integration planning for 0guard.

The integration boundary is deliberately pre-signing. Ika, MPCKit, OdWS, and
Ikavery are signing/custody/recovery surfaces; 0guard should evaluate the intent
before any dWallet, quorum, hosted MPC API, or recovery flow is asked to sign.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from guard0.policy import evaluate_intent

IKA_INTEGRATION_SCHEMA = "0guard.ika_integration_manifest.v1"
IKA_PREFLIGHT_SCHEMA = "0guard.ika_signing_preflight.v1"


@dataclass(frozen=True)
class IkaFinding:
    id: str
    severity: str
    decision: str
    message: str
    evidence: dict[str, Any]

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity,
            "decision": self.decision,
            "message": self.message,
            "evidence": self.evidence,
        }


def ika_integration_manifest() -> dict[str, Any]:
    """Return source-cited integration posture for Ika/Encrypt/Ikavery."""
    repositories = [
        {
            "id": "ikavery",
            "name": "Ikavery",
            "owner": "Iamknownasfesal",
            "url": "https://github.com/Iamknownasfesal/ikavery",
            "role": "quorum-gated key import and recovery UX for Sui testnet and Solana devnet",
            "license": "not_declared_in_repo_metadata",
            "reusePolicy": "reference_architecture_only_until_license_or_written_permission",
            "status": "pre_alpha_devnet_testnet_only",
        },
        {
            "id": "mpckit",
            "name": "MPCKit",
            "owner": "Iamknownasfesal",
            "url": "https://github.com/Iamknownasfesal/mpckit",
            "role": "hosted/self-hostable dWallet API and presign pool",
            "license": "BSD-3-Clause",
            "reusePolicy": "sdk_or_http_adapter_candidate_after_api_key_and_terms_review",
            "status": "live_testnet_and_mainnet_api",
        },
        {
            "id": "odws",
            "name": "Open dWallet Standard",
            "owner": "Iamknownasfesal",
            "url": "https://github.com/Iamknownasfesal/odws",
            "role": "multi-chain dWallet SDK with local and on-chain policy engines",
            "license": "BSD-3-Clause-Clear",
            "reusePolicy": "policy_contract_reference_and_future_sdk_adapter_candidate",
            "status": "beta_unaudited",
        },
        {
            "id": "clear_msig_ika",
            "name": "clear-msig-ika",
            "owner": "Iamknownasfesal",
            "url": "https://github.com/Iamknownasfesal/clear-msig-ika",
            "role": "human-readable multisig intents that execute through Ika dWallets",
            "license": "not_declared_in_repo_metadata",
            "reusePolicy": "concept_reference_only_until_license_or_written_permission",
            "status": "devnet_pre_alpha_pattern",
        },
        {
            "id": "ika",
            "name": "Ika",
            "owner": "dwallet-labs",
            "url": "https://github.com/dwallet-labs/ika",
            "role": "zero-trust 2PC-MPC dWallet network coordinated through Sui",
            "license": "other_plus_docs_license",
            "reusePolicy": "use official SDK/docs; avoid vendoring core code",
            "status": "mainnet_network_and_sdk_reference",
        },
        {
            "id": "encrypt_pre_alpha",
            "name": "Encrypt Pre-Alpha SDK",
            "owner": "dwallet-labs",
            "url": "https://github.com/dwallet-labs/encrypt-pre-alpha",
            "role": "Solana devnet FHE developer SDK and mock executor",
            "license": "other",
            "reusePolicy": "documentation_and_devnet_experiment_only",
            "status": "pre_alpha_plaintext_warning",
        },
    ]
    return {
        "schema": IKA_INTEGRATION_SCHEMA,
        "generatedAt": _now(),
        "mode": "pre_signing_firewall_and_receipt_layer",
        "positioning": {
            "coreThesis": (
                "Ika/Ikavery can enforce quorum or dWallet custody, while 0guard explains "
                "and blocks unsafe intent before a signing surface is reached."
            ),
            "nonBridgeFit": (
                "Ika signs native transactions on each chain, so it matches 0guard's "
                "no-bridge roadmap better than asset-wrapping integrations."
            ),
            "firstProductSlice": (
                "A dWallet signing preflight that returns allow/review/deny, source findings, "
                "and a 0G-ready receipt hash before MPCKit, OdWS, or Ikavery sees the request."
            ),
        },
        "repositories": repositories,
        "integrationContracts": [
            {
                "id": "ika_signing_preflight",
                "route": "/api/integrations/ika/evaluate",
                "input": "chain, operation, messageHex, target, value, environment, sourceProject",
                "output": "0guard verdict plus Ika-specific findings and receipt hash",
                "sideEffects": False,
            },
            {
                "id": "mpckit_http_policy_gate",
                "plannedAdapter": "MPCKit SDK/API wrapper that calls 0guard before /v1/sign",
                "sideEffects": "operator_only_after_preflight",
            },
            {
                "id": "odws_policy_function",
                "plannedAdapter": "OdWS local PolicyFunction that delegates to 0guard",
                "sideEffects": "no 0guard side effects; OdWS remains responsible for signing",
            },
            {
                "id": "ikavery_recovery_guard",
                "plannedAdapter": "Ikavery sweep/recovery preview panel with 0guard receipt",
                "sideEffects": "devnet/testnet only until audited and explicitly approved",
            },
            {
                "id": "encrypt_private_risk_proofs",
                "plannedAdapter": (
                    "future encrypted risk computation only after Encrypt leaves pre-alpha "
                    "and provides real encryption guarantees"
                ),
                "sideEffects": False,
            },
        ],
        "recommendedNextBuild": [
            "Keep external repos in a research cache; do not vendor unlicensed source.",
            "Add a TS example later: MPCKit/OdWS calls 0guard before sign.",
            "Promote Ikavery as a recovery UX reference, not a production custody claim.",
            "Use Encrypt only for devnet experiments until its own README no longer says plaintext.",
        ],
        "officialSources": [
            "https://docs.ika.xyz/",
            "https://docs.ika.xyz/docs/core-concepts/multi-chain-vs-cross-chain",
            "https://docs.ika.xyz/docs/move-integration/protocols/key-importing",
            "https://github.com/Iamknownasfesal/ikavery",
            "https://github.com/Iamknownasfesal/mpckit",
            "https://github.com/Iamknownasfesal/odws",
            "https://github.com/dwallet-labs/encrypt-pre-alpha",
        ],
        "safety": _safety(),
    }


def evaluate_ika_signing_request(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Evaluate a proposed dWallet/Ikavery signing request without side effects."""
    body = payload or {}
    if not isinstance(body, dict):
        raise ValueError("payload must be an object")

    chain = _norm(body.get("chain") or body.get("caip2") or "eip155:1")
    operation = _norm_id(body.get("operation") or body.get("action") or "sign_transaction")
    source_project = _norm_id(body.get("sourceProject") or body.get("source_project") or "ika")
    environment = _norm(body.get("environment") or "preview")
    message_hex = str(body.get("messageHex") or body.get("message_hex") or "").strip()
    target = str(body.get("target") or body.get("to") or "").strip()
    value = body.get("value") or body.get("valueEth") or body.get("value_eth") or 0
    intent_text = str(body.get("intentText") or body.get("intent_text") or "")
    live_signing = _truthy(body.get("liveSigning") or body.get("live_signing"))

    intent = {
        "action": _policy_action_for_operation(operation),
        "mode": "live_transaction" if live_signing else environment,
        "requires_signature": _requires_signature(operation),
        "target_contract": target,
        "to": target,
        "chain_id": _chain_id(chain),
        "value_eth": _float_value(value),
        "calldata": message_hex,
        "prompt_text": intent_text,
        "app": f"ika:{source_project}",
    }
    policy = evaluate_intent(intent).to_dict()
    findings = _ika_findings(
        chain=chain,
        operation=operation,
        source_project=source_project,
        environment=environment,
        live_signing=live_signing,
        sensitive_data=_truthy(body.get("sensitiveData") or body.get("sensitive_data")),
        has_message_hex=bool(message_hex),
    )
    decision = _rollup(policy, findings)
    receipt_payload = {
        "schema": IKA_PREFLIGHT_SCHEMA,
        "decision": decision,
        "chain": chain,
        "operation": operation,
        "sourceProject": source_project,
        "policyReceipt": policy.get("receipt_hash"),
        "findingIds": [finding.id for finding in findings],
    }
    return {
        "schema": IKA_PREFLIGHT_SCHEMA,
        "generatedAt": _now(),
        "mode": "read_only_pre_signing",
        "decision": decision,
        "chain": chain,
        "operation": operation,
        "sourceProject": source_project,
        "environment": environment,
        "policy": policy,
        "findingCount": len(findings),
        "findings": [finding.public() for finding in findings],
        "receipt": {
            "hash": _hash_json(receipt_payload),
            "algorithm": "sha256_canonical_json",
            "zeroGStorageReady": True,
            "liveUploadPerformed": False,
        },
        "recommendedNextStep": _recommended_next_step(decision),
        "safety": _safety(),
    }


def _ika_findings(
    *,
    chain: str,
    operation: str,
    source_project: str,
    environment: str,
    live_signing: bool,
    sensitive_data: bool,
    has_message_hex: bool,
) -> list[IkaFinding]:
    findings: list[IkaFinding] = []
    if live_signing or operation in {
        "sign_transaction",
        "sign_message",
        "execute",
        "sweep",
        "import_key",
        "create_wallet",
        "create_dwallet",
    }:
        findings.append(
            _finding(
                "ika_signing_surface_operator_only",
                "critical" if live_signing else "medium",
                "deny" if live_signing else "review",
                (
                    "0guard can preflight Ika/dWallet signing requests, but it must not "
                    "sign, import keys, sweep assets, or submit transactions."
                ),
                {"operation": operation, "liveSigning": live_signing},
            )
        )
    if source_project in {"ikavery", "clear_msig_ika"}:
        findings.append(
            _finding(
                "ikavery_pre_alpha_devnet_boundary",
                "high",
                "review",
                "Ikavery-style recovery is testnet/devnet and unaudited; never import real-fund keys.",
                {"sourceProject": source_project, "environment": environment},
            )
        )
    if source_project in {"encrypt", "encrypt_pre_alpha"} or "encrypt" in operation:
        findings.append(
            _finding(
                "encrypt_pre_alpha_plaintext_boundary",
                "critical" if sensitive_data else "medium",
                "deny" if sensitive_data else "review",
                (
                    "Encrypt pre-alpha states that data is public/plaintext today; sensitive "
                    "risk data cannot be treated as confidential."
                ),
                {"sensitiveData": sensitive_data},
            )
        )
    if source_project in {"odws", "mpckit"}:
        findings.append(
            _finding(
                "hosted_or_sdk_signing_requires_policy_gate",
                "medium",
                "review",
                "Use 0guard as the pre-signing policy gate before OdWS/MPCKit signing APIs.",
                {"sourceProject": source_project},
            )
        )
    if not has_message_hex and operation.startswith("sign"):
        findings.append(
            _finding(
                "ika_message_payload_missing",
                "medium",
                "review",
                "Signing preflight lacks messageHex, so calldata/message-specific checks are incomplete.",
                {"chain": chain},
            )
        )
    if chain.startswith(("eip155", "solana", "sui", "ton", "bip122")):
        findings.append(
            _finding(
                "native_chain_signing_not_bridge",
                "low",
                "allow",
                "Ika-style native signatures match the no-bridge integration model.",
                {"chain": chain},
            )
        )
    return findings or [
        _finding(
            "ika_read_only_context_ok",
            "low",
            "allow",
            "Read-only Ika/Ikavery context can be cataloged without touching keys or signers.",
            {"sourceProject": source_project},
        )
    ]


def _rollup(policy: dict[str, Any], findings: list[IkaFinding]) -> str:
    decisions = {finding.decision for finding in findings}
    if policy.get("decision") == "deny" or "deny" in decisions:
        return "deny"
    if policy.get("decision") == "review" or "review" in decisions:
        return "review"
    return "allow"


def _requires_signature(operation: str) -> bool:
    return any(
        term in operation
        for term in (
            "sign",
            "execute",
            "sweep",
            "import",
            "create_wallet",
            "create_dwallet",
            "approve",
        )
    )


def _policy_action_for_operation(operation: str) -> str:
    if operation.startswith(("read", "list", "get", "status", "network")):
        return "read_balance"
    if operation.startswith(("preview", "simulate", "dry_run")):
        return "preview"
    return operation


def _chain_id(chain: str) -> int:
    if chain.startswith("eip155:"):
        try:
            return int(chain.split(":", 1)[1])
        except ValueError:
            return 0
    return 0


def _float_value(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _finding(
    finding_id: str,
    severity: str,
    decision: str,
    message: str,
    evidence: dict[str, Any],
) -> IkaFinding:
    return IkaFinding(
        id=finding_id,
        severity=severity,
        decision=decision,
        message=message,
        evidence=evidence,
    )


def _recommended_next_step(decision: str) -> str:
    if decision == "deny":
        return "Do not send to Ika/MPCKit/OdWS/Ikavery. Keep this as a blocked receipt."
    if decision == "review":
        return "Keep this in preview. Require source review, testnet proof, and explicit operator approval."
    return "Safe as read-only context. Any signing path remains outside 0guard."


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _norm_id(value: Any) -> str:
    return _norm(value).replace("-", "_")


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}
    return bool(value)


def _safety() -> dict[str, bool]:
    return {
        "readOnly": True,
        "networkCalls": False,
        "privateKeyRequired": False,
        "privateKeyImportEnabled": False,
        "walletSignaturesRequested": False,
        "transactionSigningEnabled": False,
        "broadcastingEnabled": False,
        "sweepingEnabled": False,
        "bridgingEnabled": False,
        "moneyMovementEnabled": False,
        "rawPayloadsReturned": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
