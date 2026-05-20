"""0G Storage upload manifest and local/readback verification.

This prepares a public-safe bundle for a future operator-approved 0G Storage
upload. It verifies local content hashes now, and it can verify an externally
recorded live upload/readback proof. It does not call the Storage SDK, upload
bytes, read from a gateway, sign, or move funds.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STORAGE_UPLOAD_MANIFEST_SCHEMA = "0guard.0g_storage_upload_manifest.v1"
STORAGE_BUNDLE_ARTIFACT_SCHEMA = "0guard.0g_storage_public_bundle.v1"
STORAGE_LIVE_PROOF_SCHEMA = "0guard.0g_storage_live_upload_proof.v1"
STORAGE_LIVE_PROOF_VERIFICATION_SCHEMA = "0guard.0g_storage_live_upload_proof_verification.v1"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STORAGE_BUNDLE_PATHS = (
    REPO_ROOT / "data" / "evals" / "incident_detector_eval.v1.jsonl",
    REPO_ROOT / "data" / "backfill" / "reputation_features" / "phishdestroy" / "latest.json",
    REPO_ROOT / "data" / "backfill" / "historical_feature_store" / "seed.v1.jsonl",
    REPO_ROOT / "docs" / "hackathon-0g" / "mainnet-proof.json",
)
DEFAULT_STORAGE_LIVE_PROOF_PATH = REPO_ROOT / "docs" / "hackathon-0g" / "0g-storage-live-proof.json"
HEX_32_RE = re.compile(r"^(0x)?[a-fA-F0-9]{64}$")


def build_storage_upload_manifest(
    paths: list[str | Path] | None = None,
    *,
    live_proof_path: str | Path | None = DEFAULT_STORAGE_LIVE_PROOF_PATH,
) -> dict[str, Any]:
    """Return a no-upload manifest for public-safe 0G Storage bundle candidates."""

    files, existing_files, bundle_root = _bundle_components(paths)
    local_readback = _local_readback(files)
    live_proof = verify_storage_live_upload_proof(
        _load_live_proof(live_proof_path) if live_proof_path else None,
        expected_bundle_root=bundle_root,
    )
    live_verified = live_proof["verified"] is True
    local_readback["liveStorageGatewayReadback"] = live_verified
    artifact_sha = storage_bundle_sha256(paths)
    return {
        "schema": STORAGE_UPLOAD_MANIFEST_SCHEMA,
        "generatedAt": _now(),
        "mode": (
            "public_safe_bundle_manifest_with_verified_live_readback"
            if live_verified
            else "public_safe_bundle_manifest_no_live_upload"
        ),
        "status": "verified_live_readback" if live_verified else "pending_live_upload_readback",
        "verified": live_verified,
        "proofPresent": live_proof.get("proofPresent") is True,
        "reason": live_proof.get("reason", ""),
        "bundleFileCount": len(existing_files),
        "bundleRoot": bundle_root,
        "bundleArtifactSha256": artifact_sha,
        "liveProofStatus": live_proof.get("status"),
        "liveProofVerified": live_verified,
        "liveUploadPerformed": live_verified,
        "liveStorageGatewayReadback": live_verified,
        "bundle": {
            "id": "zeroguard-public-safe-derived-bundle",
            "fileCount": len(existing_files),
            "missingFileCount": len(files) - len(existing_files),
            "sizeBytes": sum(int(entry["sizeBytes"] or 0) for entry in existing_files),
            "bundleRoot": bundle_root,
            "files": files,
        },
        "bundleArtifact": {
            "schema": STORAGE_BUNDLE_ARTIFACT_SCHEMA,
            "format": "canonical_json_with_base64_file_contents",
            "buildCommand": (
                "PYTHONPATH=src .venv/bin/python scripts/build_0g_storage_bundle.py "
                "--out dist/0g-storage/zeroguard-public-safe-derived-bundle.json"
            ),
            "defaultOutputPath": "dist/0g-storage/zeroguard-public-safe-derived-bundle.json",
            "artifactSha256": artifact_sha,
            "rawPayloadResaleAllowed": False,
        },
        "uploadPlan": {
            "target": "0G Storage",
            "officialSdk": "https://docs.0g.ai/developer-hub/building-on-0g/storage/sdk",
            "operatorRequired": True,
            "liveUploadPerformed": live_verified,
            "transactionSigningEnabled": False,
            "uploadCommandStatus": (
                "verified_external_upload_readback"
                if live_verified
                else "not_run_from_workbench"
            ),
            "requiredBeforeLiveUpload": [
                "operator-approved storage endpoint and wallet/signer custody",
                "public-safe bundle review",
                "upload budget and rollback plan",
                "download/readback proof saved with content hash equality",
            ],
            "recordProofCommandTemplate": (
                "PYTHONPATH=src .venv/bin/python scripts/record_0g_storage_live_proof.py "
                "--bundle-file dist/0g-storage/zeroguard-public-safe-derived-bundle.json "
                "--downloaded-file <downloaded-readback.json> "
                "--root-hash <0g-storage-root-hash> "
                "--tx-hash <upload-transaction-hash> "
                "--indexer-url <0g-storage-indexer-url> "
                "--gateway-url <download-readback-url> "
                "--operator-approved-public-safe"
            ),
        },
        "readbackVerifier": local_readback,
        "liveProof": live_proof,
        "rightsPolicy": {
            "rawPayloadsReturned": False,
            "rawPayloadResaleAllowed": False,
            "publicSafeDerivedBundleOnly": True,
            "containsPrivateKeys": False,
            "containsPaymentHeaders": False,
        },
        "safety": _safety(live_storage_upload=live_verified, live_gateway_readback=live_verified),
    }


def build_storage_bundle_payload(paths: list[str | Path] | None = None) -> dict[str, Any]:
    """Return the deterministic public-safe JSON object intended for live upload."""

    _, existing_files, bundle_root = _bundle_components(paths)
    bundled_files = []
    for entry in existing_files:
        path = REPO_ROOT / entry["path"]
        content = path.read_bytes()
        bundled_files.append(
            {
                "path": entry["path"],
                "sizeBytes": entry["sizeBytes"],
                "sha256": entry["sha256"],
                "rightsClass": entry["rightsClass"],
                "rawPayloadResaleAllowed": False,
                "contentBase64": base64.b64encode(content).decode("ascii"),
            }
        )
    return {
        "schema": STORAGE_BUNDLE_ARTIFACT_SCHEMA,
        "bundleId": "zeroguard-public-safe-derived-bundle",
        "bundleRoot": bundle_root,
        "fileCount": len(bundled_files),
        "files": bundled_files,
        "rightsPolicy": {
            "rawPayloadsReturned": False,
            "rawPayloadResaleAllowed": False,
            "publicSafeDerivedBundleOnly": True,
            "containsPrivateKeys": False,
            "containsPaymentHeaders": False,
        },
    }


def storage_bundle_bytes(paths: list[str | Path] | None = None) -> bytes:
    """Return canonical bytes for the upload bundle artifact."""

    return _canonical_json_bytes(build_storage_bundle_payload(paths)) + b"\n"


def storage_bundle_sha256(paths: list[str | Path] | None = None) -> str:
    """Return the sha256 of the deterministic upload bundle artifact."""

    return hashlib.sha256(storage_bundle_bytes(paths)).hexdigest()


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


def verify_storage_live_upload_proof(
    proof: dict[str, Any] | None,
    *,
    expected_bundle_root: str | None = None,
) -> dict[str, Any]:
    """Validate an externally produced 0G Storage upload/readback proof."""

    if not isinstance(proof, dict):
        return _live_proof_status("missing", "live_proof_file_missing")

    checks = {
        "schema": proof.get("schema") == STORAGE_LIVE_PROOF_SCHEMA,
        "bundleRoot": (
            not expected_bundle_root
            or proof.get("bundleRoot") == expected_bundle_root
        ),
        "rootHash": _valid_hex_32(proof.get("rootHash")),
        "transactionHash": _valid_hex_32(proof.get("transactionHash")),
        "bundleArtifactSha256": _valid_sha256(proof.get("bundleArtifactSha256")),
        "gatewayReadbackSha256": _valid_sha256(proof.get("gatewayReadbackSha256")),
        "gatewayReadbackMatchesBundle": (
            bool(proof.get("bundleArtifactSha256"))
            and proof.get("bundleArtifactSha256") == proof.get("gatewayReadbackSha256")
        ),
        "operatorApprovedPublicSafe": proof.get("operatorApprovedPublicSafe") is True,
        "rawPayloadsReturned": proof.get("rawPayloadsReturned") is False,
        "privateKeysReturned": proof.get("privateKeysReturned") is False,
        "paymentHeadersStored": proof.get("paymentHeadersStored") is False,
    }
    verified = all(checks.values())
    return {
        "schema": STORAGE_LIVE_PROOF_VERIFICATION_SCHEMA,
        "generatedAt": _now(),
        "status": "verified" if verified else "review",
        "verified": verified,
        "proofPresent": True,
        "proofPath": proof.get("proofPath"),
        "bundleRoot": proof.get("bundleRoot"),
        "rootHash": proof.get("rootHash"),
        "transactionHash": proof.get("transactionHash"),
        "bundleArtifactSha256": proof.get("bundleArtifactSha256"),
        "gatewayReadbackSha256": proof.get("gatewayReadbackSha256"),
        "gatewayUrl": proof.get("gatewayUrl"),
        "indexerUrl": proof.get("indexerUrl"),
        "checks": checks,
        "safety": _safety(live_storage_upload=verified, live_gateway_readback=verified),
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


def _bundle_components(
    paths: list[str | Path] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], str]:
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
    return files, existing_files, bundle_root


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
    if rel.startswith("data/backfill/historical_feature_store/"):
        return "public_source_derived_historical_features"
    if rel.startswith("docs/hackathon-0g/mainnet-proof"):
        return "public_mainnet_proof"
    return "operator_review_required"


def _relative_repo_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def _hash_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return encoded


def _load_live_proof(path: str | Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    proof_path = Path(path)
    if not proof_path.is_absolute():
        proof_path = REPO_ROOT / proof_path
    try:
        payload = json.loads(proof_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return None
    if isinstance(payload, dict):
        return {**payload, "proofPath": _relative_repo_path(proof_path)}
    return None


def _live_proof_status(status: str, reason: str) -> dict[str, Any]:
    return {
        "schema": STORAGE_LIVE_PROOF_VERIFICATION_SCHEMA,
        "generatedAt": _now(),
        "status": status,
        "verified": False,
        "proofPresent": False,
        "reason": reason,
        "checks": {},
        "safety": _safety(),
    }


def _valid_hex_32(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX_32_RE.fullmatch(value.strip()))


def _valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[a-fA-F0-9]{64}", value.strip()))


def _safety(
    *,
    live_storage_upload: bool = False,
    live_gateway_readback: bool = False,
) -> dict[str, bool]:
    return {
        "readOnly": True,
        "networkCalls": False,
        "liveStorageUpload": live_storage_upload,
        "liveStorageGatewayReadback": live_gateway_readback,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "moneyMovementEnabled": False,
        "privateKeysReturned": False,
        "paymentHeadersStored": False,
        "telegramSendsEnabled": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
