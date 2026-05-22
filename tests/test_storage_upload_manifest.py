"""Tests for 0G Storage no-upload bundle manifests."""

from guard0.storage_upload_manifest import (
    STORAGE_LIVE_PROOF_SCHEMA,
    build_storage_live_upload_preflight,
    build_storage_bundle_payload,
    build_storage_upload_manifest,
    storage_bundle_bytes,
    storage_bundle_sha256,
    verify_storage_live_upload_proof,
    verify_storage_upload_manifest,
)


def test_storage_upload_manifest_hashes_public_safe_bundle(tmp_path):
    first = tmp_path / "incident_eval.jsonl"
    second = tmp_path / "reputation.json"
    first.write_text('{"caseId":"case-1","rights":{"rawPayloadResaleAllowed":false}}\n')
    second.write_text('{"sourceId":"phishdestroy_destroylist","rawDomainsReturned":false}\n')

    manifest = build_storage_upload_manifest([first, second])

    assert manifest["schema"] == "0guard.0g_storage_upload_manifest.v1"
    assert manifest["status"] == "pending_live_upload_readback"
    assert manifest["verified"] is False
    assert manifest["proofPresent"] is False
    assert manifest["bundleFileCount"] == 2
    assert manifest["bundleRoot"] == manifest["bundle"]["bundleRoot"]
    assert manifest["bundleArtifactSha256"] == manifest["bundleArtifact"]["artifactSha256"]
    assert manifest["liveProofStatus"] == "missing"
    assert manifest["liveProofVerified"] is False
    assert manifest["proofBlockers"] == ["live_proof_file_missing"]
    assert manifest["preflightBlockers"] == manifest["uploadPreflight"]["blockers"]
    assert manifest["blockers"] == [
        "live_proof_file_missing",
        *manifest["uploadPreflight"]["blockers"],
    ]
    assert manifest["uploadPreflight"]["schema"] == (
        "0guard.0g_storage_live_upload_preflight.v1"
    )
    assert manifest["uploadPreflight"]["status"] == "blocked_before_live_upload"
    assert "storage_sdk_runtime_not_present" in manifest["uploadPreflight"]["blockers"]
    assert "operator_signer_not_configured" in manifest["uploadPreflight"]["blockers"]
    assert manifest["uploadPreflight"]["workbenchCanUpload"] is False
    assert manifest["uploadPreflight"]["environment"]["operatorSignerConfigured"] is False
    assert (
        manifest["uploadPreflight"]["environment"]["sdkPackageName"]
        == "@0gfoundation/0g-storage-ts-sdk"
    )
    assert (
        manifest["uploadPreflight"]["sdkRuntime"]["packageName"]
        == "@0gfoundation/0g-storage-ts-sdk"
    )
    assert "@0gfoundation/0g-ts-sdk" in (
        manifest["uploadPreflight"]["sdkRuntime"]["legacyPackageNames"]
    )
    assert manifest["uploadPreflight"]["sdkRuntime"]["installCommand"] == (
        "npm install @0gfoundation/0g-storage-ts-sdk ethers"
    )
    assert "ethers" in manifest["uploadPreflight"]["sdkRuntime"]["peerDependencies"]
    assert (
        'import { ZgFile, Indexer } from "@0gfoundation/0g-storage-ts-sdk";'
        in manifest["uploadPreflight"]["sdkRuntime"]["typescriptImports"]
    )
    assert any(
        path.endswith("node_modules/@0gfoundation/0g-storage-ts-sdk")
        for path in manifest["uploadPreflight"]["sdkRuntime"]["checkedNodeModulePaths"]
    )
    assert manifest["uploadPreflight"]["nextCommands"]["installStorageSdk"] == (
        "npm install @0gfoundation/0g-storage-ts-sdk ethers"
    )
    assert manifest["uploadPlan"]["preflightStatus"] == "blocked_before_live_upload"
    assert manifest["bundle"]["fileCount"] == 2
    assert manifest["bundle"]["bundleRoot"]
    assert manifest["uploadPlan"]["liveUploadPerformed"] is False
    assert "record_0g_storage_live_proof.py" in manifest["uploadPlan"]["recordProofCommandTemplate"]
    assert manifest["readbackVerifier"]["allMatched"] is True
    assert manifest["rightsPolicy"]["rawPayloadResaleAllowed"] is False
    assert manifest["safety"]["liveStorageUpload"] is False
    assert manifest["safety"]["transactionSigningEnabled"] is False
    assert manifest["bundleArtifact"]["artifactSha256"]
    assert manifest["liveProof"]["verified"] is False
    assert manifest["liveProof"]["proofBlockers"] == ["live_proof_file_missing"]
    assert manifest["liveProof"]["blockers"] == ["live_proof_file_missing"]


def test_default_storage_manifest_includes_historical_feature_store_seed():
    manifest = build_storage_upload_manifest()

    by_path = {item["path"]: item for item in manifest["bundle"]["files"]}
    feature_store = by_path["data/backfill/historical_feature_store/seed.v1.jsonl"]
    assert feature_store["exists"] is True
    assert feature_store["rightsClass"] == "public_source_derived_historical_features"
    assert feature_store["rawPayloadResaleAllowed"] is False


def test_storage_upload_manifest_local_readback_detects_missing_file(tmp_path):
    existing = tmp_path / "existing.json"
    missing = tmp_path / "missing.json"
    existing.write_text("{}\n")

    manifest = build_storage_upload_manifest([existing, missing])
    readback = verify_storage_upload_manifest(manifest)

    assert manifest["bundle"]["fileCount"] == 1
    assert manifest["bundle"]["missingFileCount"] == 1
    assert readback["schema"] == "0guard.0g_storage_upload_manifest_readback.v1"
    assert readback["liveStorageGatewayReadback"] is False
    assert any(check["exists"] is False for check in readback["checks"])


def test_storage_bundle_payload_is_deterministic_public_safe_json(tmp_path):
    first = tmp_path / "incident_eval.jsonl"
    first.write_text('{"caseId":"case-1","rights":{"rawPayloadResaleAllowed":false}}\n')

    payload = build_storage_bundle_payload([first])
    first_bytes = storage_bundle_bytes([first])
    second_bytes = storage_bundle_bytes([first])

    assert payload["schema"] == "0guard.0g_storage_public_bundle.v1"
    assert payload["fileCount"] == 1
    assert payload["rightsPolicy"]["rawPayloadResaleAllowed"] is False
    assert first_bytes == second_bytes
    assert len(storage_bundle_sha256([first])) == 64


def test_storage_live_upload_preflight_reports_operator_ready_when_gates_are_met(
    tmp_path,
    monkeypatch,
):
    first = tmp_path / "incident_eval.jsonl"
    first.write_text('{"caseId":"case-1","rights":{"rawPayloadResaleAllowed":false}}\n')
    monkeypatch.setenv(
        "ZG_STORAGE_LIVE_UPLOAD_ENABLE",
        "I_APPROVE_0G_STORAGE_PUBLIC_BUNDLE_UPLOAD",
    )
    monkeypatch.setenv("ZG_STORAGE_PRIVATE_KEY", "configured-but-not-read")
    monkeypatch.setenv("ZG_STORAGE_CHAIN_RPC", "https://evmrpc-testnet.0g.ai")
    monkeypatch.setenv("ZG_STORAGE_INDEXER_RPC", "https://indexer-storage-testnet-turbo.0g.ai")
    monkeypatch.setattr(
        "guard0.storage_upload_manifest.REPO_ROOT",
        tmp_path,
    )
    artifact_path = tmp_path / "bundle.json"
    artifact_path.write_bytes(storage_bundle_bytes([first]))
    sdk_path = tmp_path / "node_modules" / "@0gfoundation" / "0g-storage-ts-sdk"
    sdk_path.mkdir(parents=True)

    result = build_storage_live_upload_preflight([first], artifact_path=artifact_path)

    assert result["status"] == "operator_upload_ready"
    assert result["operatorUploadReady"] is True
    assert result["workbenchCanUpload"] is False
    assert result["blockers"] == []
    assert result["bundleArtifactMatches"] is True
    assert result["environment"]["liveUploadGateEnabled"] is True
    assert result["environment"]["sdkPackagePresent"] is True
    assert result["sdkRuntime"]["packagePresent"] is True
    assert result["sdkRuntime"]["packageName"] == "@0gfoundation/0g-storage-ts-sdk"
    assert result["safety"]["transactionSigningEnabled"] is False


def test_verified_live_storage_proof_turns_manifest_upload_readback_green(tmp_path):
    first = tmp_path / "incident_eval.jsonl"
    first.write_text('{"caseId":"case-1","rights":{"rawPayloadResaleAllowed":false}}\n')
    manifest_without_proof = build_storage_upload_manifest([first], live_proof_path=None)
    artifact_sha = storage_bundle_sha256([first])
    proof_path = tmp_path / "0g-storage-live-proof.json"
    proof_path.write_text(
        """{
  "schema": "%s",
  "bundleRoot": "%s",
  "bundleArtifactSha256": "%s",
  "gatewayReadbackSha256": "%s",
  "rootHash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "transactionHash": "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "indexerUrl": "https://indexer-storage-testnet-turbo.0g.ai",
  "gatewayUrl": "https://example.invalid/readback",
  "operatorApprovedPublicSafe": true,
  "rawPayloadsReturned": false,
  "privateKeysReturned": false,
  "paymentHeadersStored": false
}
"""
        % (
            STORAGE_LIVE_PROOF_SCHEMA,
            manifest_without_proof["bundle"]["bundleRoot"],
            artifact_sha,
            artifact_sha,
        ),
        encoding="utf-8",
    )

    manifest = build_storage_upload_manifest([first], live_proof_path=proof_path)

    assert manifest["liveProof"]["verified"] is True
    assert manifest["proofBlockers"] == []
    assert manifest["status"] == "verified_live_readback"
    assert manifest["verified"] is True
    assert manifest["proofPresent"] is True
    assert manifest["liveProofStatus"] == "verified"
    assert manifest["liveProofVerified"] is True
    assert manifest["liveUploadPerformed"] is True
    assert manifest["liveStorageGatewayReadback"] is True
    assert manifest["uploadPlan"]["liveUploadPerformed"] is True
    assert manifest["readbackVerifier"]["liveStorageGatewayReadback"] is True
    assert manifest["safety"]["liveStorageUpload"] is True
    assert manifest["safety"]["transactionSigningEnabled"] is False
    assert manifest["safety"]["moneyMovementEnabled"] is False


def test_live_storage_proof_rejects_mismatched_gateway_readback():
    proof = {
        "schema": STORAGE_LIVE_PROOF_SCHEMA,
        "bundleRoot": "expected",
        "bundleArtifactSha256": "a" * 64,
        "gatewayReadbackSha256": "b" * 64,
        "rootHash": "0x" + "c" * 64,
        "transactionHash": "0x" + "d" * 64,
        "operatorApprovedPublicSafe": True,
        "rawPayloadsReturned": False,
        "privateKeysReturned": False,
        "paymentHeadersStored": False,
    }

    result = verify_storage_live_upload_proof(proof, expected_bundle_root="expected")

    assert result["verified"] is False
    assert result["checks"]["gatewayReadbackMatchesBundle"] is False
    assert result["safety"]["liveStorageUpload"] is False
