#!/usr/bin/env python3
"""Run one capped Base Sepolia x402 paid-route smoke with a throwaway wallet.

The script decrypts the local encrypted throwaway keystore in memory, signs the
x402 payment authorization, calls the configured testnet route, and records only
public-safe hashes plus facilitator settlement metadata. It never prints the
private key or raw payment header.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from eth_account import Account
from x402 import x402ClientSync
from x402.http.clients import x402_requests
from x402.http.x402_http_client import x402HTTPClientSync
from x402.mechanisms.evm.exact import register_exact_evm_client

from guard0.x402_guard import (
    BASE_SEPOLIA_CAIP2,
    DEFAULT_X402_SETTLEMENT_PROOF_PATH,
    X402_TESTNET_FACILITATOR_URL,
    verify_x402_settlement_proof,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run a capped x402 Base Sepolia paid smoke")
    parser.add_argument("--keystore", required=True, help="Encrypted throwaway buyer keystore")
    parser.add_argument(
        "--keychain-service",
        default="",
        help="macOS Keychain service containing the keystore passphrase",
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Protected x402 route URL, usually a tagged no-traffic Cloud Run revision",
    )
    parser.add_argument(
        "--target",
        default="0x02228b0afcdbEdf8180D96Fc181Da3AF5DD1d1ab",
        help="Public target value to hash inside the derived response",
    )
    parser.add_argument(
        "--pay-to",
        required=True,
        help="Reviewed pay-to address expected in the settlement response",
    )
    parser.add_argument("--amount-atomic", default="10000")
    parser.add_argument(
        "--proof-path",
        default=str(DEFAULT_X402_SETTLEMENT_PROOF_PATH),
        help="Where to write public-safe proof metadata",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Check setup and print the intended route without signing or paying",
    )
    args = parser.parse_args()

    keystore_path = Path(args.keystore).expanduser()
    keystore = _read_keystore(keystore_path)
    keychain_service = args.keychain_service or str(keystore.get("x-0guard-keychain-service") or "")
    payer = "0x" + str(keystore.get("address") or "").removeprefix("0x")

    if args.dry_run:
        print(
            json.dumps(
                {
                    "schema": "0guard.x402_base_sepolia_paid_smoke_preview.v1",
                    "status": "dry_run_no_signing",
                    "url": args.url,
                    "payer": payer,
                    "payTo": args.pay_to,
                    "amountAtomic": args.amount_atomic,
                    "keychainServiceConfigured": bool(keychain_service),
                    "safety": _safety(signing=False, facilitator=False),
                },
                sort_keys=True,
            )
        )
        return 0

    passphrase = _read_keychain_passphrase(keychain_service)
    private_key = Account.decrypt(keystore, passphrase)
    account = Account.from_key(private_key)
    if account.address.lower() != payer.lower():
        raise SystemExit("decrypted key does not match keystore address")

    client = x402ClientSync()
    register_exact_evm_client(client, account, networks=BASE_SEPOLIA_CAIP2)
    http_client = x402HTTPClientSync(client)
    session = x402_requests(client)
    response = session.get(args.url, params={"target": args.target}, timeout=45)
    payment_header = (
        response.request.headers.get("PAYMENT-SIGNATURE")
        or response.request.headers.get("X-PAYMENT")
        or ""
    )
    if not payment_header:
        raise SystemExit("x402 client did not attach a payment header")
    response_hash = hashlib.sha256(response.content).hexdigest()
    payment_header_hash = hashlib.sha256(payment_header.encode("utf-8")).hexdigest()
    try:
        settlement = http_client.get_payment_settle_response(lambda name: response.headers.get(name))
    except Exception as exc:  # noqa: BLE001 - surfaced without raw payment data.
        raise SystemExit(f"missing or invalid payment response header: {exc}") from exc

    settlement_body = _model_dump(settlement)
    if response.status_code != 200:
        raise SystemExit(f"paid route returned HTTP {response.status_code}")
    if settlement_body.get("success") is not True:
        raise SystemExit(f"settlement did not succeed: {settlement_body}")

    proof = {
        "schema": "0guard.x402_base_sepolia_settlement_proof.v1",
        "route": "/x402/v1/wallet-preflight",
        "network": "base-sepolia",
        "networkCaip2": BASE_SEPOLIA_CAIP2,
        "asset": "USDC",
        "decimals": 6,
        "amountAtomic": args.amount_atomic,
        "payer": account.address,
        "payTo": args.pay_to,
        "transactionHash": settlement_body["transaction"],
        "facilitatorUrl": X402_TESTNET_FACILITATOR_URL,
        "paymentHeaderHash": payment_header_hash,
        "responseHash": response_hash,
        "termsVersion": "zeroguard-x402-terms-2026-05-19",
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
    }
    proof_path = Path(args.proof_path)
    verification = verify_x402_settlement_proof(proof, proof_path=proof_path)
    if not verification.get("verified"):
        raise SystemExit(f"proof metadata failed verification: {verification}")
    proof_path.parent.mkdir(parents=True, exist_ok=True)
    proof_path.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "schema": "0guard.x402_base_sepolia_paid_smoke_result.v1",
                "status": "settled",
                "httpStatus": response.status_code,
                "payer": account.address,
                "transactionHash": settlement_body["transaction"],
                "paymentHeaderHash": payment_header_hash,
                "responseHash": response_hash,
                "proofPath": str(proof_path),
                "proofVerified": True,
                "rawPaymentHeaderPrinted": False,
                "privateKeyPrinted": False,
                "safety": _safety(signing=True, facilitator=True),
            },
            sort_keys=True,
        )
    )
    return 0


def _read_keystore(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"could not read keystore metadata: {exc}") from exc


def _read_keychain_passphrase(service: str) -> str:
    if not service:
        raise SystemExit("--keychain-service is required")
    result = subprocess.run(
        ["security", "find-generic-password", "-w", "-s", service],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.rstrip("\n")


def _model_dump(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return value.model_dump(by_alias=True)
    if hasattr(value, "dict"):
        return value.dict(by_alias=True)
    return dict(value)


def _safety(*, signing: bool, facilitator: bool) -> dict[str, bool]:
    return {
        "baseSepoliaOnly": True,
        "privateKeyPrinted": False,
        "rawPaymentHeaderPrinted": False,
        "paymentHeaderStored": False,
        "telegramSendsEnabled": False,
        "socialPostingEnabled": False,
        "transactionSigningEnabled": signing,
        "facilitatorCalled": facilitator,
        "mainnetSettlementEnabled": False,
    }


if __name__ == "__main__":
    raise SystemExit(main())
