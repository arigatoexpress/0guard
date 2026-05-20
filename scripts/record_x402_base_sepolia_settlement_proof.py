#!/usr/bin/env python3
"""Record a reviewed x402 Base Sepolia settlement proof.

The actual payment must happen outside this script in a signer-owned buyer
environment. This recorder only writes public-safe receipt metadata and hashes.
It does not call an x402 facilitator, store raw payment headers, sign,
broadcast, settle, or move funds.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guard0.x402_guard import (
    X402_SETTLEMENT_PROOF_SCHEMA,
    X402_TESTNET_FACILITATOR_URL,
    verify_x402_settlement_proof,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Record a public-safe x402 proof")
    parser.add_argument("--tx-hash", required=True, help="Base Sepolia settlement tx hash")
    parser.add_argument("--payer", required=True, help="Throwaway buyer wallet address")
    parser.add_argument("--pay-to", required=True, help="Reviewed server-side pay-to address")
    parser.add_argument(
        "--payment-header-hash",
        required=True,
        help="sha256 of the X-PAYMENT header; never pass the raw header",
    )
    parser.add_argument(
        "--response-hash",
        required=True,
        help="sha256 of the derived paid response packet",
    )
    parser.add_argument("--amount-atomic", default="10000", help="USDC atomic amount")
    parser.add_argument("--route", default="/x402/v1/wallet-preflight")
    parser.add_argument("--network", default="base-sepolia")
    parser.add_argument("--network-caip2", default="eip155:84532")
    parser.add_argument("--asset", default="USDC")
    parser.add_argument("--decimals", type=int, default=6)
    parser.add_argument("--facilitator-url", default=X402_TESTNET_FACILITATOR_URL)
    parser.add_argument(
        "--terms-version",
        default="zeroguard-x402-terms-2026-05-19",
        help="Terms version reviewed for this proof",
    )
    parser.add_argument(
        "--out",
        default="docs/hackathon-0g/x402-base-sepolia-settlement-proof.json",
        help="Proof JSON output path",
    )
    parser.add_argument(
        "--operator-reviewed-caps-and-terms",
        action="store_true",
        help="Required acknowledgement that caps and terms were reviewed",
    )
    parser.add_argument(
        "--settlement-performed-externally",
        action="store_true",
        help="Required acknowledgement that payment was performed outside ZeroGuard",
    )
    args = parser.parse_args()

    if not args.operator_reviewed_caps_and_terms:
        raise SystemExit("--operator-reviewed-caps-and-terms is required")
    if not args.settlement_performed_externally:
        raise SystemExit("--settlement-performed-externally is required")

    proof: dict[str, Any] = {
        "schema": X402_SETTLEMENT_PROOF_SCHEMA,
        "recordedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "route": args.route,
        "network": args.network,
        "networkCaip2": args.network_caip2,
        "asset": args.asset,
        "decimals": args.decimals,
        "amountAtomic": str(args.amount_atomic),
        "displayPrice": "0.01 USDC",
        "payer": args.payer,
        "payTo": args.pay_to,
        "transactionHash": args.tx_hash,
        "facilitatorUrl": args.facilitator_url,
        "paymentHeaderHash": args.payment_header_hash,
        "responseHash": args.response_hash,
        "termsVersion": args.terms_version,
        "operatorReviewedCapsAndTerms": True,
        "settlementAttempted": True,
        "facilitatorCalled": True,
        "settled": True,
        "settlementPerformedExternally": True,
        "rawPayloadResaleAllowed": False,
        "paymentHeaderStored": False,
        "paymentHeaderReturned": False,
        "privateKeysReturned": False,
        "transactionSigningByZeroGuard": False,
        "transactionBroadcastingByZeroGuard": False,
        "moneyMovementByZeroGuard": False,
        "safety": {
            "recorderNetworkCalls": False,
            "recorderReadPrivateKeys": False,
            "recorderStoredRawPaymentHeader": False,
            "recorderSignedTransactions": False,
            "recorderBroadcastTransactions": False,
            "recorderMovedFunds": False,
        },
    }
    out_path = Path(args.out)
    verification = verify_x402_settlement_proof(proof, proof_path=out_path)
    if verification.get("verified") is not True:
        print(json.dumps(verification, sort_keys=True), flush=True)
        raise SystemExit("x402 proof metadata failed verification")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(f"{out_path.suffix}.tmp")
    tmp_path.write_text(json.dumps(proof, sort_keys=True, indent=2), encoding="utf-8")
    tmp_path.replace(out_path)
    print(
        json.dumps(
            {
                "schema": "0guard.x402_base_sepolia_settlement_proof_record.v1",
                "out": str(out_path),
                "verification": verification,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
