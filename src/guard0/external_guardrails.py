"""Read-only external integration guardrail evaluator.

This module turns the cross-chain catalog into something more operational:
given a proposed external action/config, it returns a deterministic
allow/review/deny posture without signing, broadcasting, posting, settling, or
calling external APIs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


EXTERNAL_GUARDRAIL_CATALOG_SCHEMA = "0guard.external_guardrail_catalog.v1"
EXTERNAL_GUARDRAIL_EVALUATION_SCHEMA = "0guard.external_guardrail_evaluation.v1"


@dataclass(frozen=True)
class GuardrailFinding:
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


def external_guardrail_catalog() -> dict[str, Any]:
    """Return the active read-only guardrail checks by external surface."""
    return {
        "schema": EXTERNAL_GUARDRAIL_CATALOG_SCHEMA,
        "generatedAt": _now(),
        "mode": "read_only_policy_evaluator",
        "guardrails": [
            {
                "targetId": "arbitrum_l2",
                "role": "Arbitrum L2, Orbit, and Stylus pre-signer posture",
                "checks": [
                    "read-only RPC, receipt, gas, balance, code, and explorer context can pass",
                    "retryable tickets, L1 sends, proxy upgrades, role grants, Stylus deploys, and Orbit/DAC changes require review",
                    "signed blobs, eth_sendRawTransaction, bridge/deposit/withdrawal, and sequencer mutation are denied",
                ],
            },
            {
                "targetId": "metamask_wallet",
                "role": "MetaMask Connect, Snap insights, and smart-account delegation posture",
                "checks": [
                    "wallet reads and transaction/signature insights can pass as preview-only context",
                    "transactions, typed-data signatures, and permissions require a 0guard receipt before wallet prompt",
                    "unbounded delegation, missing expiry, private keys, and raw signed transactions are denied",
                ],
            },
            {
                "targetId": "x402",
                "role": "paid API rail posture",
                "checks": [
                    "payment requirement must bind route, network, token, amount, recipient, and content hash",
                    "live settlement remains disabled until facilitator, replay window, and pay-to address are reviewed",
                    "raw upstream OSINT payload resale is denied",
                ],
            },
            {
                "targetId": "virtuals_base",
                "role": "agent identity/distribution posture",
                "checks": [
                    "manifest-only agent preparation is allowed",
                    "live launch, tokenization, and marketplace publishing require operator approval",
                ],
            },
            {
                "targetId": "lighter_exchange",
                "role": "exchange/API intent posture",
                "checks": [
                    "read-only status or documentation checks can pass",
                    "orders, deposits, withdrawals, API-key creation, and exchange account actions are denied",
                ],
            },
            {
                "targetId": "chainlink_ccip",
                "role": "CCIP message/token-transfer posture",
                "checks": [
                    "destination chain must be allowlisted",
                    "router and token-pool ownership must be reviewed",
                    "rate limits must be enabled before any live token-transfer intent",
                ],
            },
            {
                "targetId": "layerzero_v2",
                "role": "omnichain message posture",
                "checks": [
                    "single-DVN or one-of-one verifier configurations are denied",
                    "send/receive config asymmetry requires review",
                    "nonce and replay protections must be present for live message intents",
                ],
            },
            {
                "targetId": "wormhole_ntt",
                "role": "VAA/native-token-transfer posture",
                "checks": [
                    "guardian threshold must meet the configured quorum expectation",
                    "transceiver registry changes require review",
                    "global-accountant or supply-invariant controls must be enabled for transfer intents",
                ],
            },
            {
                "targetId": "celestia_blobstream",
                "role": "DA proof comparator",
                "checks": [
                    "Blobstream is treated as proof/DA context, not an EVM settlement lane",
                    "0guard's implemented proof anchor remains 0G Chain/Storage-ready receipts",
                ],
            },
        ],
        "safety": _safety(),
    }


def evaluate_external_guardrail(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Evaluate a proposed external integration action without side effects."""
    body = payload or {}
    if not isinstance(body, dict):
        raise ValueError("payload must be an object")
    target_id = _norm(body.get("target_id") or body.get("targetId") or "layerzero_v2")
    action = _norm(body.get("action") or "review")
    config = body["config"] if "config" in body else {}
    if not isinstance(config, dict):
        raise ValueError("config must be an object")
    intent_text = str(body.get("intent_text") or body.get("intentText") or "")

    findings: list[GuardrailFinding] = []
    if target_id in {"x402", "x402_payment"}:
        findings.extend(_evaluate_x402(action=action, config=config, intent_text=intent_text))
    elif target_id in {"virtuals_base", "virtuals", "base_mainnet"}:
        findings.extend(_evaluate_virtuals(action=action, config=config, intent_text=intent_text))
    elif target_id in {"lighter_exchange", "lighter"}:
        findings.extend(_evaluate_lighter(action=action, config=config, intent_text=intent_text))
    elif target_id in {
        "arbitrum",
        "arbitrum_l2",
        "arbitrum_one",
        "arbitrum_nova",
        "arbitrum_sepolia",
        "arbitrum_orbit",
        "arbitrum_stylus",
        "arbitrum_bold",
    }:
        findings.extend(_evaluate_arbitrum(action=action, config=config, intent_text=intent_text))
    elif target_id in {
        "metamask",
        "metamask_wallet",
        "metamask_connect",
        "metamask_snap",
        "metamask_delegation",
        "metamask_smart_accounts",
    }:
        findings.extend(_evaluate_metamask(action=action, config=config, intent_text=intent_text))
    elif target_id in {"chainlink_ccip", "ccip"}:
        findings.extend(_evaluate_ccip(action=action, config=config, intent_text=intent_text))
    elif target_id in {"layerzero_v2", "layerzero"}:
        findings.extend(_evaluate_layerzero(action=action, config=config, intent_text=intent_text))
    elif target_id in {"wormhole_ntt", "wormhole"}:
        findings.extend(_evaluate_wormhole(action=action, config=config, intent_text=intent_text))
    elif target_id in {"celestia_blobstream", "celestia"}:
        findings.extend(_evaluate_celestia(action=action, config=config, intent_text=intent_text))
    else:
        findings.append(
            GuardrailFinding(
                id="unknown_external_target",
                severity="medium",
                decision="review",
                message="Unknown external target; require a source-cited guardrail profile before live use.",
                evidence={"targetId": target_id},
            )
        )

    decision = _rollup_decision(findings)
    return {
        "schema": EXTERNAL_GUARDRAIL_EVALUATION_SCHEMA,
        "generatedAt": _now(),
        "targetId": target_id,
        "action": action,
        "decision": decision,
        "findingCount": len(findings),
        "findings": [finding.public() for finding in findings],
        "recommendedOperatorAction": _operator_action(decision),
        "safety": _safety(),
    }


def _evaluate_x402(*, action: str, config: dict[str, Any], intent_text: str) -> list[GuardrailFinding]:
    findings: list[GuardrailFinding] = []
    raw_payload_resale = _truthy(config.get("rawPayloadResale") or config.get("raw_payload_resale"))
    live_settlement = _truthy(config.get("liveSettlement") or config.get("live_settlement"))
    if raw_payload_resale:
        findings.append(
            _finding(
                "x402_raw_payload_resale_denied",
                "critical",
                "deny",
                "Payment is not permission to resell raw upstream OSINT payloads.",
                {"rawPayloadResale": True},
            )
        )
    required = ("networkId", "token", "amount", "payTo", "contentHash", "nonce")
    missing = [field for field in required if not _present(config, field)]
    if live_settlement and missing:
        findings.append(
            _finding(
                "x402_live_settlement_missing_controls",
                "critical",
                "deny",
                "Live x402 settlement is missing required payment/replay/content binding controls.",
                {"missing": missing},
            )
        )
    elif not live_settlement:
        findings.append(
            _finding(
                "x402_prepared_not_live",
                "medium",
                "review",
                "x402 is prepared as a paid API posture only; live settlement is disabled.",
                {"liveSettlement": False, "intentText": intent_text[:160]},
            )
        )
    return findings or [
        _finding(
            "x402_ready_for_operator_review",
            "medium",
            "review",
            "x402 controls are present, but settlement still requires explicit operator enablement.",
            {"requiredControlsPresent": True},
        )
    ]


def _evaluate_virtuals(*, action: str, config: dict[str, Any], intent_text: str) -> list[GuardrailFinding]:
    launch_action = any(token in action for token in ("launch", "token", "publish", "marketplace"))
    launch_action = launch_action or any(token in intent_text.lower() for token in ("launch", "tokenize", "publish"))
    if launch_action:
        return [
            _finding(
                "virtuals_live_launch_operator_required",
                "high",
                "deny",
                "Virtuals/Base launch, tokenization, or marketplace publishing is an external side effect.",
                {"launchStatus": config.get("launchStatus", "not_enabled")},
            )
        ]
    return [
        _finding(
            "virtuals_manifest_only_ok",
            "low",
            "allow",
            "Manifest-only Virtuals/Base agent posture can be reviewed without live launch.",
            {"network": config.get("network", "Base")},
        )
    ]


def _evaluate_lighter(*, action: str, config: dict[str, Any], intent_text: str) -> list[GuardrailFinding]:
    text = f"{action} {intent_text}".lower()
    denied_terms = ("order", "deposit", "withdraw", "api key", "apikey", "stake", "buy lit", "fee credit", "trade")
    if any(term in text for term in denied_terms):
        return [
            _finding(
                "lighter_external_side_effect_denied",
                "critical",
                "deny",
                "Lighter orders, deposits, withdrawals, API-key creation, and exchange account actions are disabled.",
                {"matchedSurface": "exchange_or_lit_action", "readOnly": True},
            )
        ]
    return [
        _finding(
            "lighter_read_only_context_ok",
            "low",
            "allow",
            "Lighter status/docs/market-context review is allowed as a read-only exchange/API guardrail.",
            {"statusOnly": not _truthy(config.get("apiKeyConfigured"))},
        )
    ]


def _evaluate_arbitrum(*, action: str, config: dict[str, Any], intent_text: str) -> list[GuardrailFinding]:
    findings: list[GuardrailFinding] = []
    text = f"{action} {intent_text}".lower()
    method = _norm(config.get("method") or config.get("rpcMethod") or config.get("rpc_method"))
    read_methods = {
        "eth_chainid",
        "eth_blocknumber",
        "eth_call",
        "eth_estimategas",
        "eth_getcode",
        "eth_getbalance",
        "eth_gettransactionreceipt",
        "eth_getlogs",
    }
    denied_terms = (
        "private key",
        "mnemonic",
        "seed phrase",
        "eth_sendrawtransaction",
        "signed transaction",
        "bridge",
        "deposit",
        "withdraw",
        "sequencer",
    )
    review_terms = (
        "retryable",
        "sendtxtol1",
        "proxy",
        "upgrade",
        "grantrole",
        "owner",
        "admin",
        "stylus",
        "activate",
        "orbit",
        "dac",
        "chain owner",
    )
    if method == "eth_sendrawtransaction" or any(term in text for term in denied_terms):
        findings.append(
            _finding(
                "arbitrum_external_side_effect_denied",
                "critical",
                "deny",
                "Arbitrum signing, broadcasting, bridge/deposit/withdrawal, or sequencer-side effects are disabled.",
                {"method": method or None, "readOnly": True},
            )
        )
    if any(term in text for term in review_terms):
        findings.append(
            _finding(
                "arbitrum_l2_admin_review_required",
                "high",
                "review",
                "Arbitrum retryable, admin, proxy, Stylus, or Orbit/DAC changes require source/config readback before any wallet prompt.",
                {
                    "chain": config.get("chain"),
                    "nativePreflightReceiptPresent": _present(config, "nativePreflightReceipt"),
                },
            )
        )
    if _truthy(config.get("liveTransaction") or config.get("live_transaction")):
        findings.append(
            _finding(
                "arbitrum_live_transaction_operator_required",
                "critical",
                "deny",
                "0guard routes cannot execute live Arbitrum transactions; keep this as a pre-signer receipt.",
                {"liveTransaction": True},
            )
        )
    if not findings and (method in read_methods or action.startswith(("read", "get", "estimate", "simulate"))):
        findings.append(
            _finding(
                "arbitrum_read_only_context_ok",
                "low",
                "allow",
                "Arbitrum read-only RPC, gas, receipt, code, balance, and explorer summaries are allowed.",
                {"method": method or action},
            )
        )
    return findings or [
        _finding(
            "arbitrum_unknown_action_review",
            "medium",
            "review",
            "Arbitrum action is not recognized as read-only; require a native-preflight receipt before wallet prompt.",
            {"action": action},
        )
    ]


def _evaluate_metamask(*, action: str, config: dict[str, Any], intent_text: str) -> list[GuardrailFinding]:
    findings: list[GuardrailFinding] = []
    text = f"{action} {intent_text}".lower()
    method = _norm(config.get("method") or config.get("walletMethod") or config.get("wallet_method"))
    read_methods = {"eth_accounts", "eth_requestaccounts", "eth_chainid", "wallet_getpermissions"}
    gated_methods = {
        "eth_sendtransaction",
        "personal_sign",
        "eth_signtypeddata_v4",
        "wallet_requestpermissions",
        "requestexecutionpermissions",
        "sendtransactionwithdelegation",
        "senduseroperationwithdelegation",
    }
    if any(term in text for term in ("private key", "mnemonic", "seed phrase")):
        findings.append(
            _finding(
                "metamask_secret_request_denied",
                "critical",
                "deny",
                "0guard never asks MetaMask users for private keys, mnemonics, or seed phrases.",
                {"secretRequest": True},
            )
        )
    if method == "eth_sendrawtransaction" or "signed transaction" in text:
        findings.append(
            _finding(
                "metamask_signed_blob_denied",
                "critical",
                "deny",
                "Raw signed transaction blobs are denied; 0guard must run before signing.",
                {"method": method or None},
            )
        )
    is_delegation = method in {
        "requestexecutionpermissions",
        "sendtransactionwithdelegation",
        "senduseroperationwithdelegation",
    } or "delegation" in text or "permission" in text
    if is_delegation:
        missing = [
            field
            for field in ("expiry", "maxAmount", "nativePreflightReceipt")
            if not _present(config, field)
        ]
        if missing:
            findings.append(
                _finding(
                    "metamask_delegation_bounds_missing",
                    "critical",
                    "deny",
                    "MetaMask delegation or advanced-permission requests need expiry, max amount, and a 0guard receipt.",
                    {"missing": missing},
                )
            )
    if method in gated_methods and not _present(config, "nativePreflightReceipt"):
        findings.append(
            _finding(
                "metamask_preflight_receipt_missing",
                "high",
                "review",
                "MetaMask signing, transaction, typed-data, or permission prompts should be gated by a 0guard receipt.",
                {"method": method},
            )
        )
    if not findings and (method in read_methods or action.startswith(("read", "preview", "insight"))):
        findings.append(
            _finding(
                "metamask_preview_context_ok",
                "low",
                "allow",
                "MetaMask account, permission-read, and Snap insight preview context can be inspected without side effects.",
                {"method": method or action},
            )
        )
    return findings or [
        _finding(
            "metamask_wallet_action_review",
            "medium",
            "review",
            "MetaMask wallet action is not proven read-only; require a 0guard receipt before prompting the user.",
            {"action": action, "method": method or None},
        )
    ]


def _evaluate_ccip(*, action: str, config: dict[str, Any], intent_text: str) -> list[GuardrailFinding]:
    findings: list[GuardrailFinding] = []
    transfer_like = any(token in f"{action} {intent_text}".lower() for token in ("send", "transfer", "bridge"))
    if transfer_like and not _truthy(config.get("destinationChainAllowlisted")):
        findings.append(
            _finding(
                "ccip_destination_not_allowlisted",
                "critical",
                "deny",
                "CCIP transfer intent targets a destination chain that is not allowlisted.",
                {"destinationChainAllowlisted": False},
            )
        )
    if transfer_like and config.get("rateLimitEnabled") is False:
        findings.append(
            _finding(
                "ccip_rate_limit_disabled",
                "high",
                "deny",
                "CCIP token-transfer intent has rate limits disabled.",
                {"rateLimitEnabled": False},
            )
        )
    if not _present(config, "routerAddress") or not _present(config, "tokenPoolOwner"):
        findings.append(
            _finding(
                "ccip_router_pool_review_required",
                "medium",
                "review",
                "CCIP router address and token-pool owner should be reviewed before live use.",
                {
                    "routerAddressPresent": _present(config, "routerAddress"),
                    "tokenPoolOwnerPresent": _present(config, "tokenPoolOwner"),
                },
            )
        )
    return findings or [
        _finding(
            "ccip_policy_controls_present",
            "low",
            "allow",
            "CCIP guardrail controls are present for read-only review.",
            {"transferLike": transfer_like},
        )
    ]


def _evaluate_layerzero(*, action: str, config: dict[str, Any], intent_text: str) -> list[GuardrailFinding]:
    findings: list[GuardrailFinding] = []
    required_dvns = _int_or_none(config.get("requiredDVNCount") or config.get("required_dvn_count"))
    if required_dvns is not None and required_dvns <= 1:
        findings.append(
            _finding(
                "layerzero_single_dvn_denied",
                "critical",
                "deny",
                "LayerZero one-of-one or single-DVN verifier configurations are denied.",
                {"requiredDVNCount": required_dvns},
            )
        )
    elif required_dvns is None:
        findings.append(
            _finding(
                "layerzero_dvn_count_missing",
                "medium",
                "review",
                "LayerZero DVN threshold is missing; require source/config readback before live use.",
                {},
            )
        )
    if config.get("sendReceiveConfigSymmetric") is False:
        findings.append(
            _finding(
                "layerzero_send_receive_asymmetry",
                "high",
                "deny",
                "LayerZero send/receive configuration is asymmetric.",
                {"sendReceiveConfigSymmetric": False},
            )
        )
    if config.get("nonceReplayProtection") is False:
        findings.append(
            _finding(
                "layerzero_replay_protection_missing",
                "critical",
                "deny",
                "LayerZero live message intent is missing nonce/replay protection.",
                {"nonceReplayProtection": False},
            )
        )
    return findings or [
        _finding(
            "layerzero_policy_controls_present",
            "low",
            "allow",
            "LayerZero DVN, symmetry, and replay controls are present for read-only review.",
            {"requiredDVNCount": required_dvns},
        )
    ]


def _evaluate_wormhole(*, action: str, config: dict[str, Any], intent_text: str) -> list[GuardrailFinding]:
    findings: list[GuardrailFinding] = []
    threshold = _int_or_none(config.get("guardianThreshold"))
    expected = _int_or_none(config.get("expectedGuardianQuorum"))
    if threshold is not None and expected is not None and threshold < expected:
        findings.append(
            _finding(
                "wormhole_guardian_threshold_below_expected",
                "critical",
                "deny",
                "Wormhole guardian threshold is below the configured quorum expectation.",
                {"guardianThreshold": threshold, "expectedGuardianQuorum": expected},
            )
        )
    elif threshold is None or expected is None:
        findings.append(
            _finding(
                "wormhole_guardian_quorum_missing",
                "medium",
                "review",
                "Wormhole guardian threshold/quorum data is missing.",
                {"guardianThresholdPresent": threshold is not None, "expectedGuardianQuorumPresent": expected is not None},
            )
        )
    if config.get("globalAccountantEnabled") is False:
        findings.append(
            _finding(
                "wormhole_supply_invariant_disabled",
                "high",
                "deny",
                "Wormhole NTT transfer intent is missing global-accountant/supply-invariant protection.",
                {"globalAccountantEnabled": False},
            )
        )
    if config.get("transceiverRegistryChanged") is True:
        findings.append(
            _finding(
                "wormhole_transceiver_registry_changed",
                "medium",
                "review",
                "Wormhole transceiver registry changes require operator review before transfer use.",
                {"transceiverRegistryChanged": True},
            )
        )
    return findings or [
        _finding(
            "wormhole_policy_controls_present",
            "low",
            "allow",
            "Wormhole NTT guardrail controls are present for read-only review.",
            {"guardianThreshold": threshold, "expectedGuardianQuorum": expected},
        )
    ]


def _evaluate_celestia(*, action: str, config: dict[str, Any], intent_text: str) -> list[GuardrailFinding]:
    settlement_like = any(token in f"{action} {intent_text}".lower() for token in ("settle", "pay", "swap", "trade"))
    if settlement_like:
        return [
            _finding(
                "celestia_not_settlement_lane",
                "high",
                "deny",
                "Celestia/Blobstream is treated as DA proof context, not an EVM settlement or trading lane.",
                {"settlementLike": True},
            )
        ]
    return [
        _finding(
            "celestia_da_context_ok",
            "low",
            "allow",
            "Celestia/Blobstream can be compared as DA proof context while 0G remains the implemented anchor.",
            {"blobstreamContract": config.get("blobstreamContract")},
        )
    ]


def _finding(
    finding_id: str,
    severity: str,
    decision: str,
    message: str,
    evidence: dict[str, Any],
) -> GuardrailFinding:
    return GuardrailFinding(
        id=finding_id,
        severity=severity,
        decision=decision,
        message=message,
        evidence=evidence,
    )


def _rollup_decision(findings: list[GuardrailFinding]) -> str:
    decisions = {finding.decision for finding in findings}
    if "deny" in decisions:
        return "deny"
    if "review" in decisions:
        return "review"
    return "allow"


def _operator_action(decision: str) -> str:
    if decision == "deny":
        return "Do not sign or execute. Collect source/config evidence, then rerun the read-only guardrail evaluation."
    if decision == "review":
        return "Keep this as a preflight only. Operator must review source docs, config readbacks, and side-effect scope."
    return "Safe for read-only context. Live actions still require separate explicit operator approval."


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}
    return bool(value)


def _present(config: dict[str, Any], key: str) -> bool:
    value = config.get(key)
    return value is not None and str(value).strip() != ""


def _norm(value: Any) -> str:
    return str(value or "").strip().lower()


def _int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safety() -> dict[str, bool]:
    return {
        "readOnly": True,
        "rawPayloadsReturned": False,
        "privateKeyRequired": False,
        "transactionSigningEnabled": False,
        "broadcastingEnabled": False,
        "bridgingEnabled": False,
        "swappingEnabled": False,
        "moneyMovementEnabled": False,
        "externalAgentLaunchEnabled": False,
        "tradingEnabled": False,
        "exchangeApiKeysEnabled": False,
        "stakingEnabled": False,
        "postingEnabled": False,
        "deletionEnabled": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
