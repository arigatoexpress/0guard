"""EIP-1193 wallet-provider guard backed by native preflight.

This module turns "protect the wallet before the popup" into a concrete adapter
contract. It never talks to a wallet provider itself. Callers send a sanitized
provider request, 0guard returns an allow/review/deny verdict, and the caller's
own wrapper decides whether to forward the original request to the wallet.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from guard0.native_preflight import build_native_preflight

WALLET_PROVIDER_GUARD_SCHEMA = "0guard.wallet_provider_guard.v1"
WALLET_PROVIDER_EXTERNAL_PROOF_SCHEMA = "0guard.wallet_provider_external_proof.v1"
WALLET_PROVIDER_EXTERNAL_PROOF_VERIFICATION_SCHEMA = (
    "0guard.wallet_provider_external_proof_verification.v1"
)
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WALLET_PROVIDER_EXTERNAL_PROOF_PATH = (
    REPO_ROOT / "docs" / "hackathon-0g" / "wallet-provider-external-proof.json"
)
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

READ_ONLY_PROVIDER_METHODS = frozenset(
    {
        "eth_accounts",
        "eth_blockNumber",
        "eth_call",
        "eth_chainId",
        "eth_estimateGas",
        "eth_gasPrice",
        "eth_getBalance",
        "eth_getBlockByHash",
        "eth_getBlockByNumber",
        "eth_getCode",
        "eth_getLogs",
        "eth_getStorageAt",
        "eth_getTransactionCount",
        "eth_getTransactionReceipt",
        "net_version",
        "web3_clientVersion",
    }
)

SIGNING_OR_BROADCAST_METHODS = frozenset(
    {
        "eth_sendRawTransaction",
        "eth_sendTransaction",
        "eth_sign",
        "eth_signTransaction",
        "eth_signTypedData",
        "eth_signTypedData_v3",
        "eth_signTypedData_v4",
        "personal_sign",
        "wallet_grantPermissions",
        "wallet_requestPermissions",
        "wallet_sendCalls",
    }
)

REVIEW_PROVIDER_METHODS = frozenset(
    {
        "wallet_addEthereumChain",
        "wallet_switchEthereumChain",
        "wallet_watchAsset",
        "wallet_registerOnboarding",
        "wallet_requestSnaps",
        "wallet_invokeSnap",
    }
)

APPROVAL_SELECTOR = "0x095ea7b3"
TRANSFER_SELECTOR = "0xa9059cbb"


def build_wallet_provider_guard(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return a no-side-effect verdict for one wallet-provider request."""
    body = payload or {}
    if not isinstance(body, dict):
        raise ValueError("payload must be an object")

    method = str(body.get("method") or "").strip()
    if not method:
        raise ValueError("method is required")

    params = _params(body.get("params"))
    request = _summarize_request(
        method=method,
        params=params,
        origin=str(body.get("origin") or body.get("url") or body.get("domain") or ""),
        fallback_chain=str(body.get("chain") or body.get("chainId") or body.get("caip2") or ""),
    )
    intent = _intent_for_request(method=method, summary=request, intent_text=body.get("intentText"))
    live_signing = method in SIGNING_OR_BROADCAST_METHODS or bool(intent["requires_signature"])

    reputation_requested = bool(
        body.get("sourceEvidence") or body.get("evidence") or body.get("labels") or body.get("tags")
    )
    should_attach_origin_reputation = method not in READ_ONLY_PROVIDER_METHODS or reputation_requested
    native_payload = {
        "surface": str(body.get("surface") or "metamask_wallet"),
        "sourceProject": str(body.get("sourceProject") or "wallet_provider_guard"),
        "operation": _operation_for_method(method),
        "chain": request["chain"] or "eip155:1",
        "target": request.get("target") or "",
        "messageHex": request.get("calldata") or "",
        "intentText": intent["prompt_text"],
        "liveSigning": live_signing,
        "intent": intent,
        "url": request.get("originUrl") if should_attach_origin_reputation else "",
        "domain": request.get("originDomain") if should_attach_origin_reputation else "",
        "labels": (body.get("labels") or ["wallet_provider_request", method])
        if should_attach_origin_reputation
        else [],
        "sourceEvidence": body.get("sourceEvidence") or body.get("evidence") or [],
        "config": {
            "providerMethod": method,
            "paramCount": request["paramCount"],
            "selector": request.get("selector") or "",
            "originDomain": request.get("originDomain") or "",
        },
    }
    preflight = build_native_preflight(native_payload)
    decision = _decision_with_method_floor(method, preflight["decision"])
    enforcement = _enforcement(method=method, decision=decision)

    return {
        "schema": WALLET_PROVIDER_GUARD_SCHEMA,
        "generatedAt": _now(),
        "mode": "pre_wallet_provider_guard",
        "providerMethod": method,
        "origin": {
            "domain": request.get("originDomain") or "",
            "urlProvided": bool(request.get("originUrl")),
        },
        "request": _public_request_summary(request),
        "decision": decision,
        "enforcement": enforcement,
        "preflight": preflight,
        "receipt": preflight["receipt"],
        "recommendedNextStep": enforcement["message"],
        "safety": {
            "readOnly": True,
            "networkCalls": False,
            "walletSignaturesRequestedBy0guard": False,
            "providerForwardingPerformedBy0guard": False,
            "providerCallAllowed": enforcement["providerCallAllowed"],
            "transactionBroadcastingEnabled": False,
            "rawParamsReturned": False,
            "moneyMovementEnabled": False,
        },
    }


def build_wallet_provider_external_proof_status(
    proof_path: str | Path | None = DEFAULT_WALLET_PROVIDER_EXTERNAL_PROOF_PATH,
) -> dict[str, Any]:
    """Return verification status for a real extension/window.ethereum proof."""

    return verify_wallet_provider_external_proof(
        _load_external_proof(proof_path) if proof_path else None,
        proof_path=proof_path,
    )


def verify_wallet_provider_external_proof(
    proof: dict[str, Any] | None,
    *,
    proof_path: str | Path | None = None,
) -> dict[str, Any]:
    """Validate a public-safe proof from an externally run wallet extension flow."""

    if not isinstance(proof, dict):
        return _external_proof_status(
            "missing",
            "wallet_provider_external_proof_file_missing",
            proof_path=proof_path,
        )

    read_check = _scenario_check(
        proof.get("readOnlyRequest"),
        expected_method="eth_chainId",
        expected_decision="allow",
        expected_forwarded=True,
    )
    review_check = _scenario_check(
        proof.get("reviewRequest"),
        expected_method="wallet_switchEthereumChain",
        expected_decision="review",
        expected_forwarded=False,
    )
    deny_check = _scenario_check(
        proof.get("denyRequest"),
        expected_method="eth_sendTransaction",
        expected_decision="deny",
        expected_forwarded=False,
    )
    read_count = _provider_call_count(proof.get("readOnlyRequest"))
    review_count = _provider_call_count(proof.get("reviewRequest"))
    deny_count = _provider_call_count(proof.get("denyRequest"))
    checks = {
        "schema": proof.get("schema") == WALLET_PROVIDER_EXTERNAL_PROOF_SCHEMA,
        "proofMode": proof.get("proofMode") == "real_wallet_extension_window_ethereum",
        "externalDappOrigin": _valid_origin(proof.get("externalDappOrigin")),
        "guardBaseUrl": _valid_origin(proof.get("guardBaseUrl")),
        "windowEthereumPresent": proof.get("windowEthereumPresent") is True,
        "realWalletExtension": proof.get("realWalletExtension") is True,
        "mockProvider": proof.get("mockProvider") is False,
        "throwawayWallet": proof.get("throwawayWallet") is True,
        "walletWasEmpty": proof.get("walletWasEmpty") is True,
        "walletAddressHash": _valid_sha256(proof.get("walletAddressHash")),
        "readOnlyRequest": read_check["ok"],
        "reviewRequest": review_check["ok"],
        "denyRequest": deny_check["ok"],
        "reviewDidNotAddProviderCall": read_count is not None and review_count == read_count,
        "denyDidNotAddProviderCall": read_count is not None and deny_count == read_count,
        "operatorReviewed": proof.get("operatorReviewed") is True,
        "rawParamsReturned": proof.get("rawParamsReturned") is False,
        "providerCallLogRawParamsStored": proof.get("providerCallLogRawParamsStored") is False,
        "privateKeysReturned": proof.get("privateKeysReturned") is False,
        "mnemonicsReturned": proof.get("mnemonicsReturned") is False,
        "transactionSigningByZeroGuard": proof.get("transactionSigningByZeroGuard") is False,
        "transactionBroadcastingByZeroGuard": proof.get("transactionBroadcastingByZeroGuard")
        is False,
        "moneyMovementByZeroGuard": proof.get("moneyMovementByZeroGuard") is False,
    }
    verified = all(checks.values())
    blockers = _external_proof_check_blockers(checks)
    proof_path_str = str(proof_path) if proof_path else str(proof.get("proofPath") or "")
    operator_packet = _external_operator_proof_packet(proof_path_str)
    return {
        "schema": WALLET_PROVIDER_EXTERNAL_PROOF_VERIFICATION_SCHEMA,
        "generatedAt": _now(),
        "status": "verified" if verified else "review",
        "verified": verified,
        "proofPresent": True,
        "proofPath": proof_path_str,
        "operatorProofPath": operator_packet["proofPath"],
        "blockers": blockers,
        "proofBlockers": blockers,
        "suggestedExternalProofUrl": operator_packet["externalDappSuggestedUrl"],
        "externalDappSuggestedUrl": operator_packet["externalDappSuggestedUrl"],
        "requiredExternalDappOrigin": "https://arigatoexpress.github.io",
        "requiresRealWalletExtension": True,
        "requiresWindowEthereum": True,
        "requiresThrowawayEmptyWallet": True,
        "requiresOperatorReview": True,
        "proofMode": proof.get("proofMode"),
        "externalDappOrigin": proof.get("externalDappOrigin"),
        "guardBaseUrl": proof.get("guardBaseUrl"),
        "walletAddressHash": proof.get("walletAddressHash"),
        "windowEthereumPresent": proof.get("windowEthereumPresent") is True,
        "realWalletExtension": proof.get("realWalletExtension") is True,
        "mockProvider": proof.get("mockProvider") is True,
        "throwawayWallet": proof.get("throwawayWallet") is True,
        "walletWasEmpty": proof.get("walletWasEmpty") is True,
        "rawParamsReturned": proof.get("rawParamsReturned") is True,
        "privateKeysReturned": proof.get("privateKeysReturned") is True,
        "mnemonicsReturned": proof.get("mnemonicsReturned") is True,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "moneyMovementEnabled": False,
        "readOnlyRequest": read_check,
        "reviewRequest": review_check,
        "denyRequest": deny_check,
        "checks": checks,
        "safety": {
            "readOnly": True,
            "networkCalls": False,
            "proofVerificationOnly": True,
            "walletSignaturesRequestedBy0guard": False,
            "providerForwardingPerformedBy0guard": False,
            "rawParamsReturned": False,
            "providerCallLogRawParamsStored": False,
            "privateKeysReturned": False,
            "mnemonicsReturned": False,
            "transactionSigningEnabled": False,
            "transactionBroadcastingEnabled": False,
            "moneyMovementEnabled": False,
            "telegramSendsEnabled": False,
            "socialPostingEnabled": False,
        },
    }


def _params(raw: Any) -> list[Any]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, tuple):
        return list(raw)
    if isinstance(raw, dict):
        return [raw]
    raise ValueError("params must be an array or object")


def _summarize_request(
    *,
    method: str,
    params: list[Any],
    origin: str,
    fallback_chain: str,
) -> dict[str, Any]:
    tx = _first_dict(params)
    calldata = str(tx.get("data") or tx.get("input") or "").strip()
    target = str(tx.get("to") or tx.get("spender") or "").strip()
    chain = _chain_from_value(tx.get("chainId") or fallback_chain)
    if not chain and method == "wallet_switchEthereumChain":
        chain = _chain_from_value(tx.get("chainId") or _first_chain_id(params))
    if not chain:
        chain = "eip155:1"
    parsed = _parse_origin(origin)
    return {
        "method": method,
        "paramCount": len(params),
        "chain": chain,
        "target": target,
        "targetRedacted": _redact_address(target),
        "calldata": calldata,
        "selector": _selector(calldata),
        "valueEth": _eth_value(tx.get("value")),
        "originUrl": parsed["url"],
        "originDomain": parsed["domain"],
    }


def _intent_for_request(
    *,
    method: str,
    summary: dict[str, Any],
    intent_text: Any,
) -> dict[str, Any]:
    action = _action_for_method(method, summary.get("selector") or "")
    mode = "preview" if method in READ_ONLY_PROVIDER_METHODS else "live_transaction"
    requires_signature = method in SIGNING_OR_BROADCAST_METHODS
    prompt_text = str(intent_text or "").strip()
    if not prompt_text:
        origin = summary.get("originDomain") or "unknown origin"
        prompt_text = f"{origin} requested {method} before wallet provider access."
    return {
        "action": action,
        "method": _policy_method(method),
        "mode": mode,
        "requires_signature": requires_signature,
        "target_contract": summary.get("target") or "",
        "to": summary.get("target") or "",
        "chain_id": _chain_id(summary.get("chain") or ""),
        "value_eth": summary.get("valueEth") or 0,
        "calldata": summary.get("calldata") or "",
        "prompt_text": prompt_text,
        "app": "wallet-provider-guard",
    }


def _operation_for_method(method: str) -> str:
    if method in READ_ONLY_PROVIDER_METHODS:
        return "read_status"
    if method in REVIEW_PROVIDER_METHODS:
        return f"review_{method}"
    return method


def _action_for_method(method: str, selector: str) -> str:
    if method in READ_ONLY_PROVIDER_METHODS:
        return "read_balance"
    if method in {"eth_sendTransaction", "eth_signTransaction"}:
        if selector == APPROVAL_SELECTOR:
            return "token_approval"
        if selector == TRANSFER_SELECTOR:
            return "token_transfer"
        return "send_transaction"
    if method.startswith("eth_sign") or method == "personal_sign":
        return "sign_message"
    if method in {"wallet_requestPermissions", "wallet_grantPermissions"}:
        return "wallet_permission_request"
    if method == "wallet_switchEthereumChain":
        return "switch_chain"
    if method == "wallet_addEthereumChain":
        return "add_chain"
    return "wallet_provider_request"


def _policy_method(method: str) -> str:
    if method in {
        "eth_signTypedData_v3",
        "eth_signTypedData_v4",
    }:
        return "eth_signTypedData"
    return method


def _decision_with_method_floor(method: str, native_decision: str) -> str:
    if method in SIGNING_OR_BROADCAST_METHODS:
        return "deny"
    if method in REVIEW_PROVIDER_METHODS and native_decision == "allow":
        return "review"
    return native_decision


def _enforcement(*, method: str, decision: str) -> dict[str, Any]:
    if decision == "allow":
        return {
            "action": "forward_to_provider",
            "providerCallAllowed": True,
            "walletPromptBlocked": False,
            "message": "The wrapper may forward this read-only request to the wallet provider.",
        }
    if decision == "review":
        return {
            "action": "show_review_before_wallet_prompt",
            "providerCallAllowed": False,
            "walletPromptBlocked": True,
            "message": (
                f"Do not forward {method} yet; show the receipt and require manual review first."
            ),
        }
    return {
        "action": "block_before_wallet_prompt",
        "providerCallAllowed": False,
        "walletPromptBlocked": True,
        "message": f"Block {method} before any wallet prompt or provider forwarding.",
    }


def _public_request_summary(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "method": summary["method"],
        "chain": summary["chain"],
        "targetRedacted": summary["targetRedacted"],
        "selector": summary["selector"],
        "valueEth": summary["valueEth"],
        "paramCount": summary["paramCount"],
    }


def _first_dict(params: list[Any]) -> dict[str, Any]:
    for item in params:
        if isinstance(item, dict):
            return item
    return {}


def _first_chain_id(params: list[Any]) -> Any:
    for item in params:
        if isinstance(item, dict) and item.get("chainId"):
            return item["chainId"]
    return None


def _chain_from_value(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if raw.startswith("eip155:"):
        return raw
    if raw.startswith("0x"):
        try:
            return f"eip155:{int(raw, 16)}"
        except ValueError:
            return ""
    try:
        return f"eip155:{int(raw)}"
    except ValueError:
        return raw


def _chain_id(chain: str) -> int:
    if chain.startswith("eip155:"):
        try:
            return int(chain.split(":", 1)[1])
        except ValueError:
            return 0
    return 0


def _eth_value(value: Any) -> float:
    raw = str(value or "").strip()
    if not raw:
        return 0.0
    try:
        wei = int(raw, 16) if raw.startswith("0x") else int(raw)
        return wei / 1_000_000_000_000_000_000
    except ValueError:
        try:
            return float(raw)
        except ValueError:
            return 0.0


def _selector(calldata: str) -> str:
    if calldata.startswith("0x") and len(calldata) >= 10:
        return calldata[:10].lower()
    return ""


def _parse_origin(value: str) -> dict[str, str]:
    raw = value.strip()
    if not raw:
        return {"url": "", "domain": ""}
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    domain = (parsed.hostname or "").lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return {"url": raw, "domain": domain}


def _redact_address(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    if len(raw) <= 12:
        return raw
    return f"{raw[:6]}...{raw[-4:]}"


def _scenario_check(
    value: Any,
    *,
    expected_method: str,
    expected_decision: str,
    expected_forwarded: bool,
) -> dict[str, Any]:
    scenario = value if isinstance(value, dict) else {}
    receipt_hash = str(scenario.get("receiptHash") or "").strip()
    provider_count = _provider_call_count(scenario)
    ok = (
        scenario.get("method") == expected_method
        and scenario.get("decision") == expected_decision
        and scenario.get("forwardedToProvider") is expected_forwarded
        and scenario.get("walletPromptShown") is False
        and provider_count is not None
        and provider_count >= (1 if expected_forwarded else 0)
        and _valid_sha256(receipt_hash)
    )
    return {
        "ok": ok,
        "method": scenario.get("method"),
        "decision": scenario.get("decision"),
        "forwardedToProvider": scenario.get("forwardedToProvider"),
        "walletPromptShown": scenario.get("walletPromptShown"),
        "providerCallCount": provider_count,
        "receiptHash": receipt_hash,
    }


def _provider_call_count(value: Any) -> int | None:
    if not isinstance(value, dict):
        return None
    try:
        count = int(str(value.get("providerCallCount")))
    except (TypeError, ValueError):
        return None
    return count if count >= 0 else None


def _load_external_proof(path: str | Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _external_proof_status(
    status: str,
    reason: str,
    *,
    proof_path: str | Path | None = None,
) -> dict[str, Any]:
    proof_path_str = str(proof_path) if proof_path else ""
    operator_packet = _external_operator_proof_packet(proof_path_str)
    proof_blockers = _missing_external_proof_blockers(reason)
    return {
        "schema": WALLET_PROVIDER_EXTERNAL_PROOF_VERIFICATION_SCHEMA,
        "generatedAt": _now(),
        "status": status,
        "verified": False,
        "proofPresent": False,
        "proofPath": proof_path_str,
        "operatorProofPath": operator_packet["proofPath"],
        "blockers": proof_blockers,
        "proofBlockers": proof_blockers,
        "suggestedExternalProofUrl": operator_packet["externalDappSuggestedUrl"],
        "externalDappSuggestedUrl": operator_packet["externalDappSuggestedUrl"],
        "requiredExternalDappOrigin": "https://arigatoexpress.github.io",
        "requiresRealWalletExtension": True,
        "requiresWindowEthereum": True,
        "requiresThrowawayEmptyWallet": True,
        "requiresOperatorReview": True,
        "windowEthereumPresent": None,
        "realWalletExtension": None,
        "mockProvider": None,
        "throwawayWallet": None,
        "walletWasEmpty": None,
        "rawParamsReturned": False,
        "privateKeysReturned": False,
        "mnemonicsReturned": False,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "moneyMovementEnabled": False,
        "reason": reason,
        "recordProofCommandTemplate": operator_packet["recordProofCommandTemplate"],
        "proofDraftAssistant": operator_packet,
        "safety": {
            "readOnly": True,
            "networkCalls": False,
            "proofVerificationOnly": True,
            "walletSignaturesRequestedBy0guard": False,
            "providerForwardingPerformedBy0guard": False,
            "transactionSigningEnabled": False,
            "transactionBroadcastingEnabled": False,
            "moneyMovementEnabled": False,
            "privateKeysReturned": False,
        },
    }


def _missing_external_proof_blockers(reason: str) -> list[str]:
    return [
        reason,
        "real_wallet_extension_proof_missing",
        "window_ethereum_proof_missing",
        "throwaway_empty_wallet_proof_missing",
        "operator_review_proof_missing",
    ]


def _external_proof_check_blockers(checks: dict[str, bool]) -> list[str]:
    return [
        f"proof_check_failed:{name}"
        for name, passed in checks.items()
        if passed is not True
    ]


def _external_operator_proof_packet(proof_path: str) -> dict[str, Any]:
    proof_file = _operator_proof_path(proof_path)
    suggested_origin = "https://arigatoexpress.github.io"
    suggested_url = "https://arigatoexpress.github.io/0guard/wallet-provider-proof/"
    command = " ".join(
        [
            "PYTHONPATH=src .venv/bin/python",
            "scripts/record_wallet_provider_external_proof.py",
            f"--external-dapp-origin {suggested_origin}",
            "--guard-base-url <guard0-public-base-url>",
            "--wallet-address-hash <sha256-of-empty-throwaway-wallet-address>",
            "--read-receipt-hash <sha256-from-eth_chainId-verdict>",
            "--review-receipt-hash <sha256-from-switch-chain-verdict>",
            "--deny-receipt-hash <sha256-from-approval-deny-verdict>",
            f"--out {proof_file}",
            "--real-wallet-extension",
            "--window-ethereum-present",
            "--throwaway-empty-wallet",
            "--operator-reviewed",
        ]
    )
    return {
        "schema": "0guard.wallet_provider_external_operator_proof_packet.v1",
        "status": "ready_for_external_window_ethereum_proof",
        "proofPath": proof_file,
        "recordProofCommandTemplate": command,
        "externalDappSuggestedUrl": suggested_url,
        "externalDappOriginRequired": True,
        "guardBaseUrlRequired": True,
        "walletAddressHashRequired": True,
        "rawWalletAddressRequired": False,
        "receiptHashesRequired": [
            "read-receipt-hash",
            "review-receipt-hash",
            "deny-receipt-hash",
        ],
        "realWalletExtensionRequired": True,
        "windowEthereumRequired": True,
        "throwawayEmptyWalletRequired": True,
        "operatorReviewedRequired": True,
        "reviewAndDenyMustNotOpenWalletPrompt": True,
        "rawParamsStored": False,
        "privateKeysRequired": False,
        "signingByZeroGuardEnabled": False,
        "broadcastingByZeroGuardEnabled": False,
        "moneyMovementByZeroGuardEnabled": False,
    }


def _operator_proof_path(proof_path: str) -> str:
    if not proof_path:
        return "docs/hackathon-0g/wallet-provider-external-proof.json"
    try:
        path = Path(proof_path)
        if path.is_absolute():
            return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return proof_path
    return proof_path


def _valid_origin(value: Any) -> bool:
    raw = str(value or "").strip()
    parsed = urlparse(raw)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(SHA256_RE.fullmatch(value.strip()))


def wallet_address_hash(address: str) -> str:
    """Return a stable hash for a throwaway wallet address."""

    return hashlib.sha256(str(address or "").strip().lower().encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
