#!/usr/bin/env python3
"""Record a reviewed 0G Storage live upload/readback proof.

The actual upload/download must happen outside this script in a signer-owned
environment. This recorder only hashes the uploaded bundle and downloaded
readback file, verifies byte equality, and writes public-safe receipt metadata.
It does not call 0G Storage, sign, broadcast, move funds, or read keys.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guard0.storage_upload_manifest import STORAGE_LIVE_PROOF_SCHEMA

HEX_32_RE = re.compile(r"^(0x)?[a-fA-F0-9]{64}$")


def main() -> int:
    parser = argparse.ArgumentParser(description="Record a public-safe 0G Storage proof")
    parser.add_argument("--bundle-file", required=True, help="Bundle file that was uploaded")
    parser.add_argument("--downloaded-file", required=True, help="File downloaded back from 0G Storage")
    parser.add_argument("--root-hash", required=True, help="0G Storage root hash")
    parser.add_argument("--tx-hash", required=True, help="Upload transaction hash")
    parser.add_argument("--indexer-url", required=True, help="0G Storage indexer URL used for proof")
    parser.add_argument("--gateway-url", default="", help="Gateway/download URL used for readback")
    parser.add_argument(
        "--out",
        default="docs/hackathon-0g/0g-storage-live-proof.json",
        help="Proof JSON output path",
    )
    parser.add_argument(
        "--operator-approved-public-safe",
        action="store_true",
        help="Required acknowledgement that the bundle is public-safe and reviewed",
    )
    args = parser.parse_args()

    if not args.operator_approved_public_safe:
        raise SystemExit("--operator-approved-public-safe is required")
    if not HEX_32_RE.fullmatch(args.root_hash.strip()):
        raise SystemExit("--root-hash must be a 32-byte hex value")
    if not HEX_32_RE.fullmatch(args.tx_hash.strip()):
        raise SystemExit("--tx-hash must be a 32-byte hex value")

    bundle_path = Path(args.bundle_file)
    downloaded_path = Path(args.downloaded_file)
    bundle_bytes = bundle_path.read_bytes()
    downloaded_bytes = downloaded_path.read_bytes()
    bundle_sha = hashlib.sha256(bundle_bytes).hexdigest()
    downloaded_sha = hashlib.sha256(downloaded_bytes).hexdigest()
    if bundle_sha != downloaded_sha:
        raise SystemExit("downloaded file hash does not match uploaded bundle hash")

    bundle_root = _bundle_root(bundle_bytes)
    proof: dict[str, Any] = {
        "schema": STORAGE_LIVE_PROOF_SCHEMA,
        "recordedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "bundleRoot": bundle_root,
        "bundleArtifactSha256": bundle_sha,
        "gatewayReadbackSha256": downloaded_sha,
        "rootHash": args.root_hash.strip(),
        "transactionHash": args.tx_hash.strip(),
        "indexerUrl": args.indexer_url,
        "gatewayUrl": args.gateway_url,
        "operatorApprovedPublicSafe": True,
        "rawPayloadsReturned": False,
        "privateKeysReturned": False,
        "paymentHeadersStored": False,
        "liveUploadPerformedExternally": True,
        "gatewayReadbackPerformedExternally": True,
        "safety": {
            "recorderNetworkCalls": False,
            "recorderReadPrivateKeys": False,
            "recorderSignedTransactions": False,
            "recorderBroadcastTransactions": False,
            "recorderMovedFunds": False,
        },
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(f"{out_path.suffix}.tmp")
    tmp_path.write_text(json.dumps(proof, sort_keys=True, indent=2), encoding="utf-8")
    tmp_path.replace(out_path)
    print(json.dumps({"schema": "0guard.0g_storage_live_proof_record.v1", "out": str(out_path), **proof}, sort_keys=True))
    return 0


def _bundle_root(bundle_bytes: bytes) -> str:
    try:
        payload = json.loads(bundle_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"bundle file is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict) or not payload.get("bundleRoot"):
        raise SystemExit("bundle file is missing bundleRoot")
    return str(payload["bundleRoot"])


if __name__ == "__main__":
    raise SystemExit(main())
