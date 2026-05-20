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
    parser.add_argument("--external-dapp-origin", required=True)
    parser.add_argument("--guard-base-url", required=True)
    parser.add_argument(
        "--wallet-address",
        default="",
        help="Optional throwaway address; hashed before storage and never written raw",
    )
    parser.add_argument("--wallet-address-hash", default="", help="sha256 of throwaway wallet address")
    parser.add_argument("--read-receipt-hash", required=True)
    parser.add_argument("--review-receipt-hash", required=True)
    parser.add_argument("--deny-receipt-hash", required=True)
    parser.add_argument("--provider-call-count-after-read", type=int, default=1)
    parser.add_argument("--provider-call-count-after-review", type=int, default=1)
    parser.add_argument("--provider-call-count-after-deny", type=int, default=1)
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

    address_hash = args.wallet_address_hash.strip()
    if args.wallet_address.strip():
        address_hash = wallet_address_hash(args.wallet_address)
    if not address_hash:
        raise SystemExit("--wallet-address or --wallet-address-hash is required")

    proof: dict[str, Any] = {
        "schema": WALLET_PROVIDER_EXTERNAL_PROOF_SCHEMA,
        "recordedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "proofMode": "real_wallet_extension_window_ethereum",
        "externalDappOrigin": args.external_dapp_origin,
        "guardBaseUrl": args.guard_base_url.rstrip("/"),
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
            "providerCallCount": args.provider_call_count_after_read,
            "receiptHash": args.read_receipt_hash,
        },
        "reviewRequest": {
            "method": "wallet_switchEthereumChain",
            "decision": "review",
            "forwardedToProvider": False,
            "walletPromptShown": False,
            "providerCallCount": args.provider_call_count_after_review,
            "receiptHash": args.review_receipt_hash,
        },
        "denyRequest": {
            "method": "eth_sendTransaction",
            "decision": "deny",
            "forwardedToProvider": False,
            "walletPromptShown": False,
            "providerCallCount": args.provider_call_count_after_deny,
            "receiptHash": args.deny_receipt_hash,
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


if __name__ == "__main__":
    raise SystemExit(main())
