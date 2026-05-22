#!/usr/bin/env python3
"""Record a reviewed external dapp/window.ethereum proof.

The actual wallet-extension interaction must happen outside this script in a
wallet-enabled browser with a throwaway empty account. This recorder only writes
public-safe proof metadata and hashes. It does not connect to a wallet, read
keys, request signatures, broadcast transactions, or move funds.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guard0.wallet_provider_guard import (
    WALLET_PROVIDER_EXTERNAL_PROOF_SCHEMA,
    verify_wallet_provider_external_proof,
    wallet_address_hash,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Record a public-safe wallet-provider proof")
    parser.add_argument(
        "--draft-file",
        default="",
        help="Optional public-safe proof draft JSON emitted by the hosted capture page; use '-' for stdin",
    )
    parser.add_argument("--external-dapp-origin", default="")
    parser.add_argument("--guard-base-url", default="")
    parser.add_argument(
        "--wallet-address",
        default="",
        help="Optional throwaway address; hashed before storage and never written raw",
    )
    parser.add_argument("--wallet-address-hash", default="", help="sha256 of throwaway wallet address")
    parser.add_argument("--read-receipt-hash", default="")
    parser.add_argument("--review-receipt-hash", default="")
    parser.add_argument("--deny-receipt-hash", default="")
    parser.add_argument("--provider-call-count-after-read", type=int)
    parser.add_argument("--provider-call-count-after-review", type=int)
    parser.add_argument("--provider-call-count-after-deny", type=int)
    parser.add_argument(
        "--out",
        default="docs/hackathon-0g/wallet-provider-external-proof.json",
        help="Proof JSON output path",
    )
    parser.add_argument("--real-wallet-extension", action="store_true")
    parser.add_argument("--window-ethereum-present", action="store_true")
    parser.add_argument("--throwaway-empty-wallet", action="store_true")
    parser.add_argument("--operator-reviewed", action="store_true")
    args = parser.parse_args()

    if not args.real_wallet_extension:
        raise SystemExit("--real-wallet-extension is required")
    if not args.window_ethereum_present:
        raise SystemExit("--window-ethereum-present is required")
    if not args.throwaway_empty_wallet:
        raise SystemExit("--throwaway-empty-wallet is required")
    if not args.operator_reviewed:
        raise SystemExit("--operator-reviewed is required")

    draft = _load_draft(args.draft_file)
    if draft is not None:
        _validate_public_safe_draft(draft)

    address_hash = args.wallet_address_hash.strip()
    if args.wallet_address.strip():
        address_hash = wallet_address_hash(args.wallet_address)
    if not address_hash and draft is not None:
        address_hash = str(draft.get("walletAddressHash") or "").strip()
    if not address_hash:
        raise SystemExit("--wallet-address, --wallet-address-hash, or --draft-file is required")

    external_dapp_origin = args.external_dapp_origin.strip() or _draft_str(
        draft, "externalDappOrigin"
    )
    if not external_dapp_origin:
        raise SystemExit("--external-dapp-origin or --draft-file is required")
    guard_base_url = args.guard_base_url.strip() or _draft_str(draft, "guardBaseUrl")
    if not guard_base_url:
        raise SystemExit("--guard-base-url or --draft-file is required")

    read_receipt_hash = args.read_receipt_hash.strip() or _draft_receipt_hash(
        draft, "readOnlyRequest"
    )
    review_receipt_hash = args.review_receipt_hash.strip() or _draft_receipt_hash(
        draft, "reviewRequest"
    )
    deny_receipt_hash = args.deny_receipt_hash.strip() or _draft_receipt_hash(
        draft, "denyRequest"
    )
    if not read_receipt_hash:
        raise SystemExit("--read-receipt-hash or --draft-file is required")
    if not review_receipt_hash:
        raise SystemExit("--review-receipt-hash or --draft-file is required")
    if not deny_receipt_hash:
        raise SystemExit("--deny-receipt-hash or --draft-file is required")

    proof: dict[str, Any] = {
        "schema": WALLET_PROVIDER_EXTERNAL_PROOF_SCHEMA,
        "recordedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "proofMode": "real_wallet_extension_window_ethereum",
        "externalDappOrigin": external_dapp_origin,
        "guardBaseUrl": guard_base_url.rstrip("/"),
        "windowEthereumPresent": True,
        "realWalletExtension": True,
        "mockProvider": False,
        "throwawayWallet": True,
        "walletWasEmpty": True,
        "walletAddressHash": address_hash,
        "readOnlyRequest": {
            "method": "eth_chainId",
            "decision": "allow",
            "forwardedToProvider": True,
            "walletPromptShown": False,
            "providerCallCount": _provider_count(
                args.provider_call_count_after_read, draft, "readOnlyRequest"
            ),
            "receiptHash": read_receipt_hash,
        },
        "reviewRequest": {
            "method": "wallet_switchEthereumChain",
            "decision": "review",
            "forwardedToProvider": False,
            "walletPromptShown": False,
            "providerCallCount": _provider_count(
                args.provider_call_count_after_review, draft, "reviewRequest"
            ),
            "receiptHash": review_receipt_hash,
        },
        "denyRequest": {
            "method": "eth_sendTransaction",
            "decision": "deny",
            "forwardedToProvider": False,
            "walletPromptShown": False,
            "providerCallCount": _provider_count(
                args.provider_call_count_after_deny, draft, "denyRequest"
            ),
            "receiptHash": deny_receipt_hash,
        },
        "operatorReviewed": True,
        "rawParamsReturned": False,
        "providerCallLogRawParamsStored": False,
        "privateKeysReturned": False,
        "mnemonicsReturned": False,
        "transactionSigningByZeroGuard": False,
        "transactionBroadcastingByZeroGuard": False,
        "moneyMovementByZeroGuard": False,
        "safety": {
            "recorderNetworkCalls": False,
            "recorderConnectedWallet": False,
            "recorderReadPrivateKeys": False,
            "recorderRequestedSignatures": False,
            "recorderBroadcastTransactions": False,
            "recorderMovedFunds": False,
            "rawWalletAddressStored": False,
        },
    }
    out_path = Path(args.out)
    verification = verify_wallet_provider_external_proof(proof, proof_path=out_path)
    if verification.get("verified") is not True:
        print(json.dumps(verification, sort_keys=True), flush=True)
        raise SystemExit("wallet-provider proof metadata failed verification")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(f"{out_path.suffix}.tmp")
    tmp_path.write_text(json.dumps(proof, sort_keys=True, indent=2), encoding="utf-8")
    tmp_path.replace(out_path)
    print(
        json.dumps(
            {
                "schema": "0guard.wallet_provider_external_proof_record.v1",
                "out": str(out_path),
                "verification": verification,
            },
            sort_keys=True,
        )
    )
    return 0


def _load_draft(path: str) -> dict[str, Any] | None:
    if not path:
        return None
    try:
        if path == "-":
            payload = json.loads(sys.stdin.read())
        else:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"could not read proof draft: {type(exc).__name__}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit("proof draft must be a JSON object")
    return payload


def _validate_public_safe_draft(draft: dict[str, Any]) -> None:
    if draft.get("schema") != "0guard.wallet_provider_external_proof_draft.v1":
        raise SystemExit("proof draft schema mismatch")
    if draft.get("status") != "ready_for_operator_review":
        raise SystemExit("proof draft must be ready_for_operator_review")
    if draft.get("windowEthereumPresent") is not True:
        raise SystemExit("proof draft did not observe window.ethereum")
    if draft.get("rawWalletAddressStored") is not False:
        raise SystemExit("proof draft must not store a raw wallet address")
    if draft.get("rawParamsStored") is not False:
        raise SystemExit("proof draft must not store raw wallet params")


def _draft_str(draft: dict[str, Any] | None, key: str) -> str:
    if draft is None:
        return ""
    return str(draft.get(key) or "").strip()


def _draft_scenario(draft: dict[str, Any] | None, name: str) -> dict[str, Any]:
    if draft is None:
        return {}
    scenarios = draft.get("scenarioEvidence")
    if not isinstance(scenarios, dict):
        return {}
    scenario = scenarios.get(name)
    return scenario if isinstance(scenario, dict) else {}


def _draft_receipt_hash(draft: dict[str, Any] | None, name: str) -> str:
    return str(_draft_scenario(draft, name).get("receiptHash") or "").strip()


def _provider_count(
    explicit: int | None,
    draft: dict[str, Any] | None,
    name: str,
) -> int:
    if explicit is not None:
        return explicit
    value = _draft_scenario(draft, name).get("providerCallCount")
    try:
        return int(value)
    except (TypeError, ValueError):
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
