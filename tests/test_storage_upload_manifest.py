"""Tests for 0G Storage no-upload bundle manifests."""

from guard0.storage_upload_manifest import (
    build_storage_upload_manifest,
    verify_storage_upload_manifest,
)


def test_storage_upload_manifest_hashes_public_safe_bundle(tmp_path):
    first = tmp_path / "incident_eval.jsonl"
    second = tmp_path / "reputation.json"
    first.write_text('{"caseId":"case-1","rights":{"rawPayloadResaleAllowed":false}}\n')
    second.write_text('{"sourceId":"phishdestroy_destroylist","rawDomainsReturned":false}\n')

    manifest = build_storage_upload_manifest([first, second])

    assert manifest["schema"] == "0guard.0g_storage_upload_manifest.v1"
    assert manifest["bundle"]["fileCount"] == 2
    assert manifest["bundle"]["bundleRoot"]
    assert manifest["uploadPlan"]["liveUploadPerformed"] is False
    assert manifest["readbackVerifier"]["allMatched"] is True
    assert manifest["rightsPolicy"]["rawPayloadResaleAllowed"] is False
    assert manifest["safety"]["liveStorageUpload"] is False
    assert manifest["safety"]["transactionSigningEnabled"] is False


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
