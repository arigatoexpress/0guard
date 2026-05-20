#!/usr/bin/env python3
"""Build the public-safe 0G Storage bundle artifact.

This script is offline and deterministic. It does not upload, sign, broadcast,
read keys, or call a gateway. The output is the exact file an operator can
upload with the 0G Storage SDK from a reviewed signer environment.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from guard0.storage_upload_manifest import (
    build_storage_upload_manifest,
    storage_bundle_bytes,
    storage_bundle_sha256,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a public-safe 0G Storage bundle")
    parser.add_argument(
        "--out",
        default="dist/0g-storage/zeroguard-public-safe-derived-bundle.json",
        help="Path for the deterministic upload bundle",
    )
    parser.add_argument(
        "--manifest-out",
        default="dist/0g-storage/zeroguard-public-safe-derived-bundle.manifest.json",
        help="Path for the companion manifest/readback summary",
    )
    args = parser.parse_args()

    out_path = Path(args.out)
    manifest_path = Path(args.manifest_out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    bundle_bytes = storage_bundle_bytes()
    out_path.write_bytes(bundle_bytes)
    manifest = build_storage_upload_manifest(live_proof_path=None)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2), encoding="utf-8")

    summary: dict[str, Any] = {
        "schema": "0guard.0g_storage_bundle_build.v1",
        "bundlePath": str(out_path),
        "manifestPath": str(manifest_path),
        "bundleRoot": manifest["bundle"]["bundleRoot"],
        "bundleArtifactSha256": storage_bundle_sha256(),
        "bundleFileCount": manifest["bundle"]["fileCount"],
        "rawPayloadResaleAllowed": False,
        "liveUploadPerformed": False,
        "safety": {
            "readOnly": True,
            "networkCalls": False,
            "privateKeysRead": False,
            "transactionSigningEnabled": False,
            "transactionBroadcastingEnabled": False,
            "moneyMovementEnabled": False,
        },
    }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
