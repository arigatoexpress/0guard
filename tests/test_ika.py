"""Tests for Ika / Ikavery read-only integration planning."""

from guard0.ika import evaluate_ika_signing_request, ika_integration_manifest


def test_ika_manifest_is_source_cited_and_non_mutating():
    manifest = ika_integration_manifest()

    assert manifest["schema"] == "0guard.ika_integration_manifest.v1"
    assert manifest["mode"] == "pre_signing_firewall_and_receipt_layer"
    assert manifest["safety"]["privateKeyImportEnabled"] is False
    assert manifest["safety"]["transactionSigningEnabled"] is False
    assert manifest["safety"]["sweepingEnabled"] is False
    repos = {repo["id"]: repo for repo in manifest["repositories"]}
    assert repos["ikavery"]["reusePolicy"] == "reference_architecture_only_until_license_or_written_permission"
    assert repos["mpckit"]["license"] == "BSD-3-Clause"
    assert repos["odws"]["license"] == "BSD-3-Clause-Clear"
    assert repos["encrypt_pre_alpha"]["status"] == "pre_alpha_plaintext_warning"
    assert any(contract["id"] == "ika_signing_preflight" for contract in manifest["integrationContracts"])


def test_ika_signing_preflight_denies_live_signing_and_sensitive_encrypt():
    live = evaluate_ika_signing_request(
        {
            "sourceProject": "mpckit",
            "operation": "sign_transaction",
            "chain": "eip155:1",
            "liveSigning": True,
            "messageHex": "0x095ea7b3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        }
    )
    sensitive = evaluate_ika_signing_request(
        {
            "sourceProject": "encrypt_pre_alpha",
            "operation": "encrypt_input",
            "sensitiveData": True,
        }
    )

    assert live["schema"] == "0guard.ika_signing_preflight.v1"
    assert live["decision"] == "deny"
    assert live["safety"]["transactionSigningEnabled"] is False
    assert {finding["id"] for finding in live["findings"]} >= {
        "ika_signing_surface_operator_only",
        "hosted_or_sdk_signing_requires_policy_gate",
    }
    assert sensitive["decision"] == "deny"
    assert any(
        finding["id"] == "encrypt_pre_alpha_plaintext_boundary"
        for finding in sensitive["findings"]
    )


def test_ika_read_only_context_can_allow():
    result = evaluate_ika_signing_request(
        {
            "sourceProject": "ika",
            "operation": "read_status",
            "chain": "sui:testnet",
            "environment": "preview",
        }
    )

    assert result["decision"] == "allow"
    assert result["receipt"]["liveUploadPerformed"] is False
