"""Dry-run x402 payment contract for ZeroGuard data products.

This module models the HTTP-402 shape for a paid route without verifying,
settling, forwarding, or storing payment headers. It gives the MetaMask/1Shot
hackathon path a real contract to build against while keeping live settlement
explicitly disabled.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

X402_WALLET_PREFLIGHT_DRY_RUN_SCHEMA = "0guard.x402_wallet_preflight_dry_run.v1"
X402_SETTLEMENT_POLICY_SCHEMA = "0guard.x402_settlement_policy.v1"
X402_SETTLEMENT_PROOF_SCHEMA = "0guard.x402_base_sepolia_settlement_proof.v1"
X402_SETTLEMENT_PROOF_VERIFICATION_SCHEMA = (
    "0guard.x402_base_sepolia_settlement_proof_verification.v1"
)
X402_BASE_SEPOLIA_BUYER_WALLET_STATUS_SCHEMA = (
    "0guard.x402_base_sepolia_buyer_wallet_status.v1"
)
X402_FIXTURE_PAYMENT_HEADER = "fixture-paid-zeroguard-wallet-preflight-v1"
X402_DOC_URL = "https://docs.cdp.coinbase.com/x402/welcome"
X402_NETWORK_SUPPORT_URL = "https://docs.cdp.coinbase.com/x402/network-support"
X402_ORG_URL = "https://www.x402.org/"
X402_TESTNET_FACILITATOR_URL = "https://x402.org/facilitator"
CDP_X402_FACILITATOR_URL = "https://api.cdp.coinbase.com/platform/v2/x402"
BASE_SEPOLIA_NETWORK = "base-sepolia"
BASE_SEPOLIA_CAIP2 = "eip155:84532"
BASE_SEPOLIA_RPC_URL = "https://sepolia.base.org"
BASE_SEPOLIA_USDC_CONTRACT = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_X402_SETTLEMENT_PROOF_PATH = (
    REPO_ROOT / "docs" / "hackathon-0g" / "x402-base-sepolia-settlement-proof.json"
)
HEX_32_RE = re.compile(r"^(0x)?[a-fA-F0-9]{64}$")
EVM_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


def build_x402_wallet_preflight_dry_run(
    *,
    payment_header: str = "",
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a no-settlement x402 contract response for wallet preflight."""

    request_body = body or {}
    header = str(payment_header or request_body.get("paymentFixture") or "").strip()
    if not header:
        status = "payment_required_dry_run"
        http_status = 402
        accepted = False
        problem = None
    elif header == X402_FIXTURE_PAYMENT_HEADER:
        status = "payment_fixture_accepted_no_settlement"
        http_status = 200
        accepted = True
        problem = None
    else:
        status = "malformed_payment_fixture"
        http_status = 400
        accepted = False
        problem = "Only the documented fixture header is accepted in dry-run mode."

    payload = {
        "schema": X402_WALLET_PREFLIGHT_DRY_RUN_SCHEMA,
        "generatedAt": _now(),
        "mode": "x402_dry_run_no_settlement",
        "status": status,
        "httpStatus": http_status,
        "resource": {
            "productId": "wallet_preflight_verdict",
            "route": "/x402/v1/wallet-preflight",
            "apiRoute": "/api/x402/dry-run/wallet-preflight",
            "method": "POST",
            "responseSchema": "0guard.wallet_preflight_verdict.v1",
        },
        "paymentRequirement": _payment_requirement(),
        "settlementPolicyRoute": "/api/x402/settlement-policy",
        "paymentReadback": {
            "paymentHeaderPresent": bool(header),
            "paymentHeaderAccepted": accepted,
            "paymentHeaderHash": _hash_text(header) if header else "",
            "paymentHeaderReturned": False,
            "facilitatorCalled": False,
            "settlementAttempted": False,
            "settlementEnabled": False,
            "problem": problem,
        },
        "dryRunFixture": {
            "headerName": "X-PAYMENT",
            "acceptedValue": X402_FIXTURE_PAYMENT_HEADER,
            "acceptedValueIsNotARealPayment": True,
        },
        "productResponse": _product_response(request_body) if accepted else None,
        "rightsPolicy": _rights_policy(),
        "operatorNext": [
            "Wire this exact contract to a testnet facilitator only after spend limits and refund wording are fixed.",
            "Keep paid responses to derived verdicts, source ids, hashes, and receipt metadata.",
            "Do not retain raw payment headers or treat payment as permission to expose upstream feeds.",
        ],
        "safety": _safety(),
    }
    payload["receipt"] = {
        "hash": _hash_json(
            {
                "schema": payload["schema"],
                "status": payload["status"],
                "resource": payload["resource"],
                "paymentRequirement": payload["paymentRequirement"],
                "paymentHeaderHash": payload["paymentReadback"]["paymentHeaderHash"],
                "rightsPolicy": payload["rightsPolicy"],
            }
        ),
        "algorithm": "sha256_canonical_json",
        "liveAnchorPerformed": False,
        "liveUploadPerformed": False,
    }
    return payload


def _payment_requirement() -> dict[str, Any]:
    policy = build_x402_settlement_policy()
    pay_to = (policy.get("paymentRequirement") or {}).get("payTo")
    payment = _payment_requirement_for_policy()
    return {
        **payment,
        "x402Version": 1,
        "displayPrice": "0.01 USDC",
        "payTo": pay_to or "operator_pay_to_required_before_live_settlement",
        "payToConfigured": bool(pay_to),
        "settlementMode": "dry_run_fixture_only",
        "facilitator": "not_configured",
        "capsRoute": "/api/x402/settlement-policy",
    }


def _payment_requirement_for_policy() -> dict[str, Any]:
    return {
        "route": "/x402/v1/wallet-preflight",
        "apiRoute": "/api/x402/dry-run/wallet-preflight",
        "network": "base-sepolia",
        "networkCaip2": "eip155:84532",
        "asset": "USDC",
        "assetCaip19": "eip155:84532/erc20:0x0000000000000000000000000000000000000000",
        "maxAmountRequired": "10000",
        "decimals": 6,
        "resource": "https://zeroguard.local/x402/v1/wallet-preflight",
        "description": "ZeroGuard wallet preflight verdict packet",
        "mimeType": "application/json",
    }


def build_x402_settlement_policy() -> dict[str, Any]:
    """Return the operator caps and terms for a future x402 settlement path."""

    pay_to = _public_pay_to_address()
    settlement_env_enabled = _truthy_env("ZG_X402_ENABLE_SETTLEMENT")
    testnet_only = not _truthy_env("ZG_X402_ALLOW_MAINNET")
    caps = _spend_caps()
    terms = _terms()
    payment_requirement = {
        "route": "/x402/v1/wallet-preflight",
        "apiRoute": "/api/x402/dry-run/wallet-preflight",
        "network": "base-sepolia",
        "networkCaip2": "eip155:84532",
        "asset": "USDC",
        "decimals": 6,
        "maxAmountRequired": "10000",
        "displayPrice": "0.01 USDC",
        "payTo": pay_to,
        "payToConfigured": bool(pay_to),
        "settlementMode": "testnet_first_when_enabled",
        "scheme": "exact",
    }
    settlement_proof = build_x402_settlement_proof_status()
    settlement_proof_verified = settlement_proof.get("verified") is True
    blockers = []
    if not pay_to:
        blockers.append("pay_to_address_missing")
    if not settlement_env_enabled:
        blockers.append("settlement_env_gate_disabled")
    if testnet_only:
        blockers.append("mainnet_settlement_disabled")
    if not settlement_proof_verified:
        blockers.append("base_sepolia_settlement_proof_missing")
    return {
        "schema": X402_SETTLEMENT_POLICY_SCHEMA,
        "generatedAt": _now(),
        "mode": "settlement_policy_no_facilitator_call",
        "status": (
            "testnet_settlement_proof_recorded"
            if settlement_proof_verified
            else "ready_for_testnet_review"
            if pay_to
            else "blocked_before_settlement"
        ),
        "blockers": blockers,
        "paymentRoute": payment_requirement["route"],
        "network": payment_requirement["network"],
        "networkCaip2": payment_requirement["networkCaip2"],
        "asset": payment_requirement["asset"],
        "amountAtomic": payment_requirement["maxAmountRequired"],
        "displayPrice": payment_requirement["displayPrice"],
        "payTo": pay_to,
        "payToConfigured": bool(pay_to),
        "settlementProofStatus": settlement_proof.get("status"),
        "settlementProofVerified": settlement_proof_verified,
        "settlementProofPresent": settlement_proof.get("proofPresent") is True,
        "paymentRequirement": payment_requirement,
        "spendCaps": caps,
        "terms": terms,
        "operatorProofPacket": _operator_proof_packet(
            payment_requirement=payment_requirement,
            caps=caps,
            terms=terms,
            settlement_proof=settlement_proof,
        ),
        "facilitators": [
            {
                "id": "x402_org_testnet",
                "endpoint": X402_TESTNET_FACILITATOR_URL,
                "network": "base-sepolia",
                "networkCaip2": "eip155:84532",
                "apiKeyRequired": False,
                "preferredFirstProof": True,
                "mainnet": False,
            },
            {
                "id": "cdp_mainnet",
                "endpoint": CDP_X402_FACILITATOR_URL,
                "networks": ["eip155:8453", "eip155:137", "eip155:42161"],
                "apiKeyRequired": True,
                "preferredFirstProof": False,
                "mainnet": True,
            },
        ],
        "acceptanceCriteria": [
            "Unpaid request returns HTTP 402 with this route's caps and terms referenced.",
            "Malformed payment headers are hashed but never echoed or stored.",
            "First real facilitator proof is Base Sepolia only and capped at 0.01 USDC per call.",
            "Paid response remains derived analysis only: verdict, source ids, hashes, and receipt metadata.",
            "Settlement receipt readback is stored without raw payment headers or signatures.",
        ],
        "requiredBeforeSettlement": [
            "Set a reviewed server-side pay-to address.",
            "Run one Base Sepolia facilitator proof with a throwaway buyer wallet.",
            "Pin response schema, refund wording, and rate limits in tests.",
            "Keep mainnet disabled until testnet receipt readback is committed.",
        ],
        "settlementProof": settlement_proof,
        "sources": [X402_DOC_URL, X402_NETWORK_SUPPORT_URL, X402_ORG_URL],
        "safety": {
            **_safety(),
            "settlementPolicyOnly": True,
            "settlementEnvGateEnabled": settlement_env_enabled,
            "mainnetSettlementAllowedByEnv": not testnet_only,
            "payToConfigured": bool(pay_to),
            "baseSepoliaSettlementProofVerified": settlement_proof_verified,
            "settlementPerformedExternally": (
                settlement_proof.get("settlementPerformedExternally") is True
            ),
            "settlementByZeroGuardEnabled": False,
        },
    }


def build_x402_settlement_proof_status(
    proof_path: str | Path | None = DEFAULT_X402_SETTLEMENT_PROOF_PATH,
) -> dict[str, Any]:
    """Return verification status for an externally produced x402 testnet proof."""

    return verify_x402_settlement_proof(
        _load_settlement_proof(proof_path) if proof_path else None,
        proof_path=proof_path,
    )


def build_x402_base_sepolia_buyer_wallet_status(
    *,
    address: str,
    eth_balance_wei: int | str | None = None,
    usdc_balance_atomic: int | str | None = None,
    rpc_url: str = BASE_SEPOLIA_RPC_URL,
    usdc_contract: str = BASE_SEPOLIA_USDC_CONTRACT,
    manifest_path: str | Path | None = None,
    keychain_service: str = "",
    network_calls: bool = False,
) -> dict[str, Any]:
    """Return public-safe funding readiness for the x402 throwaway buyer wallet.

    The live CLI reads balances and passes them here. The app itself never
    decrypts keystores, reads private keys, signs payment headers, calls a
    facilitator, or settles a payment.
    """

    caps = _spend_caps()
    required_usdc_atomic = int(caps["perRequestMaxAtomic"])
    parsed_eth_balance = _parse_nonnegative_int(eth_balance_wei)
    parsed_usdc_balance = _parse_nonnegative_int(usdc_balance_atomic)
    address_valid = _valid_evm_address(address)
    native_gas_ready = parsed_eth_balance is not None and parsed_eth_balance > 0
    usdc_ready = (
        parsed_usdc_balance is not None and parsed_usdc_balance >= required_usdc_atomic
    )
    blockers: list[str] = []
    if not address_valid:
        blockers.append("buyer_address_invalid")
    if parsed_eth_balance is None:
        blockers.append("base_sepolia_eth_balance_not_checked")
    elif not native_gas_ready:
        blockers.append("base_sepolia_eth_required_for_gas")
    if parsed_usdc_balance is None:
        blockers.append("base_sepolia_usdc_balance_not_checked")
    elif not usdc_ready:
        blockers.append("base_sepolia_usdc_below_0_01")
    status = "ready_for_external_x402_settlement_proof" if not blockers else "funding_required"
    return {
        "schema": X402_BASE_SEPOLIA_BUYER_WALLET_STATUS_SCHEMA,
        "generatedAt": _now(),
        "status": status,
        "blockers": blockers,
        "address": address if address_valid else "",
        "network": BASE_SEPOLIA_NETWORK,
        "networkCaip2": BASE_SEPOLIA_CAIP2,
        "rpcUrl": rpc_url,
        "usdcContract": usdc_contract,
        "manifestPath": str(manifest_path) if manifest_path else "",
        "keychainServiceConfigured": bool(keychain_service),
        "balances": {
            "baseSepoliaEthWei": (
                str(parsed_eth_balance) if parsed_eth_balance is not None else ""
            ),
            "baseSepoliaEthDisplay": _format_ether(parsed_eth_balance),
            "baseSepoliaUsdcAtomic": (
                str(parsed_usdc_balance) if parsed_usdc_balance is not None else ""
            ),
            "baseSepoliaUsdcDisplay": _format_usdc(parsed_usdc_balance),
        },
        "requiredForFirstProof": {
            "nativeGas": "any positive Base Sepolia ETH balance for gas",
            "usdcAtomic": str(required_usdc_atomic),
            "usdcDisplay": caps["perRequestMaxDisplay"],
            "facilitator": X402_TESTNET_FACILITATOR_URL,
        },
        "nextAction": (
            "Run the external x402 settlement proof and record only hashes."
            if not blockers
            else "Fund the throwaway buyer with Base Sepolia ETH and 0.01 USDC testnet."
        ),
        "sources": [
            X402_NETWORK_SUPPORT_URL,
            "https://docs.x402.org/core-concepts/network-and-token-support",
            "https://docs.base.org/tools/network-faucets",
        ],
        "safety": {
            **_safety(),
            "networkCalls": network_calls,
            "readOnlyRpcCalls": network_calls,
            "keystoreRead": False,
            "privateKeysReturned": False,
            "facilitatorCalled": False,
            "settlementByZeroGuardEnabled": False,
        },
    }


def verify_x402_settlement_proof(
    proof: dict[str, Any] | None,
    *,
    proof_path: str | Path | None = None,
) -> dict[str, Any]:
    """Validate public-safe receipt metadata from a Base Sepolia x402 proof.

    The proof must be produced outside this workbench by a signer-owned
    environment. This verifier accepts only receipt hashes, amount/caps metadata,
    and derived response hashes. It must never receive raw payment headers,
    signatures, keys, or private payloads.
    """

    if not isinstance(proof, dict):
        return _settlement_proof_status(
            "missing",
            "settlement_proof_file_missing",
            proof_path=proof_path,
        )

    payment = _payment_requirement_for_policy()
    caps = _spend_caps()
    max_atomic = int(str(caps["perRequestMaxAtomic"]))
    amount_atomic = _parse_positive_int(proof.get("amountAtomic"))
    checks = {
        "schema": proof.get("schema") == X402_SETTLEMENT_PROOF_SCHEMA,
        "network": proof.get("network") == "base-sepolia",
        "networkCaip2": proof.get("networkCaip2") == "eip155:84532",
        "asset": proof.get("asset") == "USDC",
        "decimals": proof.get("decimals") == 6,
        "amountAtomicWithinCap": amount_atomic is not None
        and 0 < amount_atomic <= max_atomic,
        "route": proof.get("route") == payment["route"],
        "transactionHash": _valid_hex_32(proof.get("transactionHash")),
        "facilitatorUrl": proof.get("facilitatorUrl") == X402_TESTNET_FACILITATOR_URL,
        "payer": _valid_evm_address(proof.get("payer")),
        "payTo": _valid_evm_address(proof.get("payTo")),
        "paymentHeaderHash": _valid_sha256(proof.get("paymentHeaderHash")),
        "responseHash": _valid_sha256(proof.get("responseHash")),
        "operatorReviewedCapsAndTerms": proof.get("operatorReviewedCapsAndTerms") is True,
        "settlementAttempted": proof.get("settlementAttempted") is True,
        "facilitatorCalled": proof.get("facilitatorCalled") is True,
        "settled": proof.get("settled") is True,
        "settlementPerformedExternally": proof.get("settlementPerformedExternally") is True,
        "rawPayloadResaleAllowed": proof.get("rawPayloadResaleAllowed") is False,
        "paymentHeaderStored": proof.get("paymentHeaderStored") is False,
        "paymentHeaderReturned": proof.get("paymentHeaderReturned") is False,
        "privateKeysReturned": proof.get("privateKeysReturned") is False,
        "transactionSigningByZeroGuard": proof.get("transactionSigningByZeroGuard") is False,
        "transactionBroadcastingByZeroGuard": proof.get("transactionBroadcastingByZeroGuard")
        is False,
        "moneyMovementByZeroGuard": proof.get("moneyMovementByZeroGuard") is False,
    }
    configured_pay_to = _public_pay_to_address()
    if configured_pay_to:
        checks["payToMatchesConfiguredAddress"] = (
            str(proof.get("payTo", "")).lower() == configured_pay_to.lower()
        )
    verified = all(checks.values())
    return {
        "schema": X402_SETTLEMENT_PROOF_VERIFICATION_SCHEMA,
        "generatedAt": _now(),
        "status": "verified" if verified else "review",
        "verified": verified,
        "proofPresent": True,
        "proofPath": str(proof_path) if proof_path else proof.get("proofPath"),
        "route": proof.get("route"),
        "network": proof.get("network"),
        "networkCaip2": proof.get("networkCaip2"),
        "asset": proof.get("asset"),
        "decimals": proof.get("decimals"),
        "amountAtomic": str(proof.get("amountAtomic") or ""),
        "perRequestMaxAtomic": caps["perRequestMaxAtomic"],
        "transactionHash": proof.get("transactionHash"),
        "facilitatorUrl": proof.get("facilitatorUrl"),
        "payer": proof.get("payer"),
        "payTo": proof.get("payTo"),
        "paymentHeaderHash": proof.get("paymentHeaderHash"),
        "responseHash": proof.get("responseHash"),
        "settlementAttempted": proof.get("settlementAttempted") is True,
        "facilitatorCalled": proof.get("facilitatorCalled") is True,
        "settled": proof.get("settled") is True,
        "settlementPerformedExternally": proof.get("settlementPerformedExternally") is True,
        "termsVersion": proof.get("termsVersion"),
        "checks": checks,
        "safety": {
            **_safety(),
            "settlementProofVerificationOnly": True,
            "facilitatorCalledByZeroGuard": False,
            "facilitatorCalledExternally": proof.get("facilitatorCalled") is True,
            "settlementPerformedExternally": proof.get("settlementPerformedExternally") is True,
            "settlementByZeroGuardEnabled": False,
            "paymentHeaderStored": False,
            "paymentHeaderReturned": False,
        },
    }


def _product_response(body: dict[str, Any]) -> dict[str, Any]:
    target = str(body.get("target") or body.get("address") or body.get("url") or "").strip()
    return {
        "schema": "0guard.wallet_preflight_verdict.v1",
        "mode": "fixture_paid_response_no_settlement",
        "targetProvided": bool(target),
        "targetHash": _hash_text(target) if target else "",
        "verdict": {
            "decision": "review",
            "severity": "medium",
            "reasons": [
                "Dry-run x402 fixture accepted.",
                "No live facilitator settlement was performed.",
                "Production verdicts must be generated by deterministic ZeroGuard checks.",
            ],
        },
        "sourceIds": ["zeroguard_dry_run_contract"],
        "rawPayloadResaleAllowed": False,
        "paymentIsNotPermission": True,
    }


def _rights_policy() -> dict[str, bool]:
    return {
        "rawPayloadsReturned": False,
        "rawPayloadResaleAllowed": False,
        "paymentHeadersStored": False,
        "paymentHeadersReturned": False,
        "derivedAnalysisOnly": True,
        "paymentIsNotPermission": True,
    }


def _safety() -> dict[str, bool]:
    return {
        "readOnly": True,
        "networkCalls": False,
        "facilitatorCalled": False,
        "x402SettlementEnabled": False,
        "paymentSettlementEnabled": False,
        "paymentHeaderStored": False,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "moneyMovementEnabled": False,
        "telegramSendsEnabled": False,
        "socialPostingEnabled": False,
    }


def _spend_caps() -> dict[str, Any]:
    return {
        "currency": "USDC",
        "perRequestMaxAtomic": "10000",
        "perRequestMaxDisplay": "0.01 USDC",
        "perWalletDailyMaxAtomic": "250000",
        "perWalletDailyMaxDisplay": "0.25 USDC",
        "serviceDailyMaxAtomic": "5000000",
        "serviceDailyMaxDisplay": "5.00 USDC",
        "maxRefundWindowHours": 24,
        "rateLimit": "10 paid requests per wallet per hour before manual review",
        "mainnetStartCap": "disabled_until_testnet_receipt_readback",
    }


def _terms() -> dict[str, Any]:
    return {
        "version": "zeroguard-x402-terms-2026-05-19",
        "plainEnglish": (
            "Payment buys one derived ZeroGuard defensive packet. It does not buy raw upstream "
            "feeds, legal advice, custody, transaction approval, or permission to bypass source terms."
        ),
        "refundPolicy": (
            "Refund or credit if the service returns a malformed packet, server error, duplicate "
            "charge, or unavailable route within the 24 hour review window."
        ),
        "noAdvice": "Outputs are defensive risk signals, not legal, sanctions, investment, or custody advice.",
        "dataRetention": "Store route id, schema id, receipt hash, amount, source ids, and response hash only.",
        "neverStore": [
            "raw payment headers",
            "payment signatures",
            "private keys",
            "mnemonics",
            "raw paid-feed payloads",
            "private customer chats",
        ],
        "rawPayloadResaleAllowed": False,
    }


def _public_pay_to_address() -> str:
    value = os.getenv("ZG_X402_PAY_TO_ADDRESS", "").strip()
    if len(value) == 42 and value.startswith("0x"):
        hex_part = value[2:]
        if all(char in "0123456789abcdefABCDEF" for char in hex_part):
            return value
    return ""


def _truthy_env(name: str) -> bool:
    value = os.getenv(name, "")
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _load_settlement_proof(path: str | Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _settlement_proof_status(
    status: str,
    reason: str,
    *,
    proof_path: str | Path | None = None,
) -> dict[str, Any]:
    return {
        "schema": X402_SETTLEMENT_PROOF_VERIFICATION_SCHEMA,
        "generatedAt": _now(),
        "status": status,
        "verified": False,
        "proofPresent": False,
        "proofPath": str(proof_path) if proof_path else "",
        "reason": reason,
        "recordProofCommandTemplate": _record_settlement_proof_command(
            pay_to=_public_pay_to_address(),
            amount_atomic=_payment_requirement_for_policy()["maxAmountRequired"],
        ),
        "safety": {
            **_safety(),
            "settlementProofVerificationOnly": True,
            "settlementByZeroGuardEnabled": False,
        },
    }


def _valid_hex_32(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX_32_RE.fullmatch(value.strip()))


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[a-fA-F0-9]{64}", value.strip()))


def _valid_evm_address(value: Any) -> bool:
    return isinstance(value, str) and bool(EVM_ADDRESS_RE.fullmatch(value.strip()))


def _parse_positive_int(value: Any) -> int | None:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _parse_nonnegative_int(value: Any) -> int | None:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _format_ether(wei: int | None) -> str:
    if wei is None:
        return ""
    return f"{wei / 10**18:.18f}".rstrip("0").rstrip(".") or "0"


def _format_usdc(atomic: int | None) -> str:
    if atomic is None:
        return ""
    return f"{atomic / 10**6:.6f}".rstrip("0").rstrip(".") or "0"


def _hash_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _operator_proof_packet(
    *,
    payment_requirement: dict[str, Any],
    caps: dict[str, Any],
    terms: dict[str, Any],
    settlement_proof: dict[str, Any],
) -> dict[str, Any]:
    pay_to = str(payment_requirement.get("payTo") or "")
    amount_atomic = str(payment_requirement.get("maxAmountRequired") or "")
    return {
        "schema": "0guard.x402_base_sepolia_operator_proof_packet.v1",
        "status": (
            "verified"
            if settlement_proof.get("verified") is True
            else "ready_for_external_base_sepolia_proof"
            if pay_to
            else "blocked_until_pay_to_configured"
        ),
        "proofPath": str(DEFAULT_X402_SETTLEMENT_PROOF_PATH.relative_to(REPO_ROOT)),
        "recordProofCommandTemplate": _record_settlement_proof_command(
            pay_to=pay_to,
            amount_atomic=amount_atomic,
        ),
        "paymentRequirementHash": _hash_json(payment_requirement),
        "spendCapsHash": _hash_json(caps),
        "termsHash": _hash_json(terms),
        "rawPaymentHeaderRequired": False,
        "rawPaymentHeaderStored": False,
        "paymentHeaderHashRequired": True,
        "responseHashRequired": True,
        "operatorReviewedCapsAndTermsRequired": True,
        "settlementPerformedExternallyRequired": True,
        "settlementProofVerified": settlement_proof.get("verified") is True,
        "settlementProofStatus": settlement_proof.get("status"),
    }


def _record_settlement_proof_command(*, pay_to: str, amount_atomic: str) -> str:
    reviewed_pay_to = pay_to or "<reviewed-pay-to-address>"
    reviewed_amount = amount_atomic or "10000"
    return (
        "PYTHONPATH=src .venv/bin/python "
        "scripts/record_x402_base_sepolia_settlement_proof.py "
        "--tx-hash <base-sepolia-settlement-tx-hash> "
        "--payer <throwaway-buyer-wallet-address> "
        f"--pay-to {reviewed_pay_to} "
        "--payment-header-hash <sha256-of-x-payment-header> "
        "--response-hash <sha256-of-derived-paid-response> "
        f"--amount-atomic {reviewed_amount} "
        "--operator-reviewed-caps-and-terms "
        "--settlement-performed-externally"
    )


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
