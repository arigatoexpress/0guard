#!/usr/bin/env python3
"""Read-only funding check for a throwaway x402 Base Sepolia buyer wallet.

This helper is deliberately not a settlement client. It never reads or decrypts
the encrypted keystore, never asks macOS Keychain for the passphrase, never
signs an x402 payment header, and never calls a facilitator. It only checks
public balances needed before the first externally performed 0.01 USDC proof.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from guard0.x402_guard import (
    BASE_SEPOLIA_RPC_URL,
    BASE_SEPOLIA_USDC_CONTRACT,
    build_x402_base_sepolia_buyer_wallet_status,
)

BALANCE_OF_SELECTOR = "0x70a08231"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check x402 Base Sepolia buyer wallet funding without secrets"
    )
    parser.add_argument("--address", default="", help="Throwaway buyer wallet address")
    parser.add_argument(
        "--manifest",
        default="",
        help="Optional public buyer-wallet manifest JSON; keystore is not read",
    )
    parser.add_argument("--rpc-url", default=BASE_SEPOLIA_RPC_URL)
    parser.add_argument("--usdc-contract", default=BASE_SEPOLIA_USDC_CONTRACT)
    parser.add_argument(
        "--update-manifest",
        action="store_true",
        help="Write the read-only balance snapshot back to the public manifest",
    )
    args = parser.parse_args()

    manifest_path = Path(args.manifest).expanduser() if args.manifest else None
    manifest = _load_manifest(manifest_path) if manifest_path else {}
    address = (args.address or manifest.get("address") or "").strip()
    if not address:
        raise SystemExit("--address or --manifest with address is required")

    eth_balance = _eth_balance(args.rpc_url, address)
    usdc_balance = _erc20_balance(args.rpc_url, args.usdc_contract, address)
    status = build_x402_base_sepolia_buyer_wallet_status(
        address=address,
        eth_balance_wei=eth_balance,
        usdc_balance_atomic=usdc_balance,
        rpc_url=args.rpc_url,
        usdc_contract=args.usdc_contract,
        manifest_path=manifest_path,
        keychain_service=str(manifest.get("keychainService") or ""),
        network_calls=True,
    )
    if args.update_manifest:
        if not manifest_path:
            raise SystemExit("--update-manifest requires --manifest")
        _update_manifest(manifest_path, manifest, status)
    print(json.dumps(status, sort_keys=True))
    return 0


def _load_manifest(path: Path | None) -> dict[str, Any]:
    if not path:
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"could not read public manifest {path}: {exc}") from exc


def _eth_balance(rpc_url: str, address: str) -> int:
    result = _rpc_call(
        rpc_url,
        {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, "latest"]},
    )
    return int(str(result), 16)


def _erc20_balance(rpc_url: str, contract: str, address: str) -> int:
    call_data = BALANCE_OF_SELECTOR + address.lower().removeprefix("0x").rjust(64, "0")
    result = _rpc_call(
        rpc_url,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [{"to": contract, "data": call_data}, "latest"],
        },
    )
    return int(str(result), 16)


def _rpc_call(rpc_url: str, payload: dict[str, Any]) -> Any:
    response = requests.post(rpc_url, json=payload, timeout=15)
    response.raise_for_status()
    body = response.json()
    if body.get("error"):
        raise SystemExit(f"rpc error: {body['error']}")
    return body.get("result")


def _update_manifest(path: Path, manifest: dict[str, Any], status: dict[str, Any]) -> None:
    updated = {
        **manifest,
        "readOnlyBalanceCheck": {
            "checkedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "baseSepoliaEth": status["balances"]["baseSepoliaEthDisplay"],
            "baseSepoliaUsdc": status["balances"]["baseSepoliaUsdcDisplay"],
        },
        "networkCaip2": status["networkCaip2"],
        "recommendedFunding": {
            **dict(manifest.get("recommendedFunding") or {}),
            "usdcContract": status["usdcContract"],
            "perRequestCap": status["requiredForFirstProof"]["usdcDisplay"],
        },
    }
    tmp_path = path.with_suffix(f"{path.suffix}.tmp")
    tmp_path.write_text(json.dumps(updated, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp_path.replace(path)


if __name__ == "__main__":
    raise SystemExit(main())
