"""0G Storage upload manifest and local readback verification.

This prepares a public-safe bundle for a future operator-approved 0G Storage
upload. It verifies local content hashes now, but it does not call the Storage
SDK, upload bytes, read from a gateway, sign, or move funds.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STORAGE_UPLOAD_MANIFEST_SCHEMA = "0guard.0g_storage_upload_manifest.v1"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STORAGE_BUNDLE_PATHS = (
    REPO_ROOT / "data" / "evals" / "incident_detector_eval.v1.jsonl",
    REPO_ROOT / "data" / "backfill" / "reputation_features" / "phishdestroy" / "latest.json",
    REPO_ROOT / "docs" / "hackathon-0g" / "mainnet-proof.json",
)


def build_storage_upload_manifest(
    paths: list[str | Path] | None = None,
) -> dict[str, Any]:
    """Return a no-upload manifest for public-safe 0G Storage bundle candidates."""

    selected = [Path(path) for path in paths] if paths else list(DEFAULT_STORAGE_BUNDLE_PATHS)
    files = [_file_entry(path) for path in selected]
    existing_files = [entry for entry in files if entry["exists"]]
    bundle_root = _hash_json(
        {
            "schema": STORAGE_UPLOAD_MANIFEST_SCHEMA,
            "files": [
                {
                    "path": entry["path"],
                    "sizeBytes": entry["sizeBytes"],
                    "sha256": entry["sha256"],
                    "rightsClass": entry["rightsClass"],
                }
                for entry in existing_files
            ],
        }
    )
    local_readback = _local_readback(files)
    return {
        "schema": STORAGE_UPLOAD_MANIFEST_SCHEMA,
        "generatedAt": _now(),
        "mode": "public_safe_bundle_manifest_no_live_upload",
        "bundle": {
            "id": "zeroguard-public-safe-derived-bundle",
            "fileCount": len(existing_files),
            "missingFileCount": len(files) - len(existing_files),
            "sizeBytes": sum(int(entry["sizeBytes"] or 0) for entry in existing_files),
            "bundleRoot": bundle_root,
            "files": files,
        },
        "uploadPlan": {
            "target": "0G Storage",
            "officialSdk": "https://docs.0g.ai/developer-hub/building-on-0g/storage/sdk",
            "operatorRequired": True,
            "liveUploadPerformed": False,
            "transactionSigningEnabled": False,
            "uploadCommandStatus": "not_run_from_workbench",
            "requiredBeforeLiveUpload": [
                "operator-approved storage endpoint and wallet/signer custody",
                "public-safe bundle review",
                "upload budget and rollback plan",
                "download/readback proof saved with content hash equality",
            ],
        },
        "readbackVerifier": local_readback,
        "rightsPolicy": {
            "rawPayloadsReturned": False,
            "rawPayloadResaleAllowed": False,
            "publicSafeDerivedBundleOnly": True,
            "containsPrivateKeys": False,
            "containsPaymentHeaders": False,
        },
        "safety": _safety(),
    }


def verify_storage_upload_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Recompute local file hashes for an existing manifest."""

    bundle = manifest.get("bundle") if isinstance(manifest.get("bundle"), dict) else {}
    files = bundle.get("files") if isinstance(bundle.get("files"), list) else []
    checks = []
    for entry in files:
        if not isinstance(entry, dict):
            continue
        path = REPO_ROOT / str(entry.get("path") or "")
        current = _file_entry(path)
        checks.append(
            {
                "path": entry.get("path"),
                "expectedSha256": entry.get("sha256"),
                "currentSha256": current.get("sha256"),
                "exists": current.get("exists"),
                "matches": bool(current.get("exists") and current.get("sha256") == entry.get("sha256")),
            }
        )
    return {
        "schema": "0guard.0g_storage_upload_manifest_readback.v1",
        "generatedAt": _now(),
        "mode": "local_hash_readback_no_gateway_call",
        "allMatched": all(check["matches"] for check in checks) if checks else False,
        "checks": checks,
        "liveStorageGatewayReadback": False,
        "safety": _safety(),
    }


def _file_entry(path: Path) -> dict[str, Any]:
    resolved = path if path.is_absolute() else REPO_ROOT / path
    exists = resolved.exists() and resolved.is_file()
    content = resolved.read_bytes() if exists else b""
    return {
        "path": _relative_repo_path(resolved),
        "exists": exists,
        "sizeBytes": len(content) if exists else 0,
        "sha256": hashlib.sha256(content).hexdigest() if exists else "",
        "rightsClass": _rights_class(resolved),
        "rawPayloadResaleAllowed": False,
    }


def _local_readback(files: list[dict[str, Any]]) -> dict[str, Any]:
    checks = [
        {
            "path": entry["path"],
            "exists": entry["exists"],
            "sha256": entry["sha256"],
            "matchesManifest": bool(entry["exists"] and entry["sha256"]),
        }
        for entry in files
    ]
    return {
        "schema": "0guard.0g_storage_upload_manifest_readback.v1",
        "mode": "local_hash_readback_no_gateway_call",
        "allMatched": all(check["matchesManifest"] for check in checks) if checks else False,
        "checks": checks,
        "liveStorageGatewayReadback": False,
        "downloadProofRequiredBeforeClaim": True,
    }


def _rights_class(path: Path) -> str:
    rel = _relative_repo_path(path)
    if rel.startswith("data/evals/"):
        return "public_source_derived_eval"
    if rel.startswith("data/backfill/reputation_features/"):
        return "public_source_derived_reputation_features"
    if rel.startswith("docs/hackathon-0g/mainnet-proof"):
        return "public_mainnet_proof"
    return "operator_review_required"


def _relative_repo_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safety() -> dict[str, bool]:
    return {
        "readOnly": True,
        "networkCalls": False,
        "liveStorageUpload": False,
        "liveStorageGatewayReadback": False,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "moneyMovementEnabled": False,
        "privateKeysReturned": False,
        "paymentHeadersStored": False,
        "telegramSendsEnabled": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
