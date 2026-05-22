"""Tests for the EIP-1193 wallet-provider guard contract."""

import json

import pytest

from guard0.wallet_provider_guard import build_wallet_provider_guard
from guard0.wallet_provider_guard import (
    WALLET_PROVIDER_EXTERNAL_PROOF_SCHEMA,
    build_wallet_provider_external_proof_status,
    verify_wallet_provider_external_proof,
    wallet_address_hash,
)


def test_wallet_provider_guard_allows_read_only_chain_probe():
    result = build_wallet_provider_guard(
        {
            "origin": "https://safe.example",
            "method": "eth_chainId",
            "params": [],
        }
    )

    assert result["schema"] == "0guard.wallet_provider_guard.v1"
    assert result["decision"] == "allow"
    assert result["enforcement"]["providerCallAllowed"] is True
    assert result["enforcement"]["walletPromptBlocked"] is False
    assert result["request"]["method"] == "eth_chainId"
    assert result["safety"]["providerForwardingPerformedBy0guard"] is False
    assert result["safety"]["rawParamsReturned"] is False


def test_wallet_provider_guard_blocks_unlimited_approval_before_wallet_prompt():
    result = build_wallet_provider_guard(
        {
            "origin": "https://claim-drop.evil.example",
            "method": "eth_sendTransaction",
            "params": [
                {
                    "chainId": "0x1",
                    "to": "0x000000000000000000000000000000000000dEaD",
                    "data": (
                        "0x095ea7b3"
                        "ffffffffffffffffffffffffffffffff"
                        "ffffffffffffffffffffffffffffffff"
                    ),
                    "value": "0x0",
                }
            ],
        }
    )

    assert result["decision"] == "deny"
    assert result["enforcement"]["action"] == "block_before_wallet_prompt"
    assert result["enforcement"]["providerCallAllowed"] is False
    assert result["request"]["selector"] == "0x095ea7b3"
    assert result["request"]["targetRedacted"] == "0x0000...dEaD"
    assert result["preflight"]["decision"] == "deny"
    assert result["preflight"]["safety"]["walletSignaturesRequested"] is False
    assert result["safety"]["moneyMovementEnabled"] is False


def test_wallet_provider_guard_reviews_chain_switch_without_forwarding():
    result = build_wallet_provider_guard(
        {
            "origin": "https://bridge.example",
            "method": "wallet_switchEthereumChain",
            "params": [{"chainId": "0xa4b1"}],
        }
    )

    assert result["decision"] == "review"
    assert result["enforcement"]["providerCallAllowed"] is False
    assert result["enforcement"]["walletPromptBlocked"] is True
    assert result["request"]["chain"] == "eip155:42161"


def test_wallet_provider_guard_rejects_bad_shapes_and_omits_raw_params():
    with pytest.raises(ValueError):
        build_wallet_provider_guard({})
    with pytest.raises(ValueError):
        build_wallet_provider_guard({"method": "eth_chainId", "params": "bad"})

    result = build_wallet_provider_guard(
        {
            "origin": "https://safe.example",
            "method": "personal_sign",
            "params": ["0x68656c6c6f", "0x885b0892D241Cb5033C9995e09cA521d54f936b5"],
        }
    )
    encoded = json.dumps(result)
    assert "0x68656c6c6f" not in encoded
    assert "params" not in result
    assert result["decision"] == "deny"


def test_wallet_provider_external_proof_status_is_missing_without_artifact(tmp_path):
    result = build_wallet_provider_external_proof_status(tmp_path / "missing.json")

    assert result["schema"] == "0guard.wallet_provider_external_proof_verification.v1"
    assert result["status"] == "missing"
    assert result["verified"] is False
    assert result["proofBlockers"] == [
        "wallet_provider_external_proof_file_missing",
        "real_wallet_extension_proof_missing",
        "window_ethereum_proof_missing",
        "throwaway_empty_wallet_proof_missing",
        "operator_review_proof_missing",
    ]
    assert result["blockers"] == result["proofBlockers"]
    assert "record_wallet_provider_external_proof.py" in result["recordProofCommandTemplate"]
    assert "--draft-file /tmp/0guard-wallet-provider-proof-draft.json" in (
        result["draftFileRecorderCommandTemplate"]
    )
    assert "--external-dapp-origin https://arigatoexpress.github.io" in (
        result["recordProofCommandTemplate"]
    )
    assert result["proofDraftAssistant"]["schema"] == (
        "0guard.wallet_provider_external_operator_proof_packet.v1"
    )
    assert result["proofDraftAssistant"]["externalDappSuggestedUrl"] == (
        "https://arigatoexpress.github.io/0guard/wallet-provider-proof/"
    )
    assert (
        result["suggestedExternalProofUrl"]
        == "https://arigatoexpress.github.io/0guard/wallet-provider-proof/"
    )
    assert result["requiresRealWalletExtension"] is True
    assert result["requiresWindowEthereum"] is True
    assert result["requiresThrowawayEmptyWallet"] is True
    assert result["proofDraftAssistant"]["rawWalletAddressRequired"] is False
    assert result["proofDraftAssistant"]["proofDraftFileSupported"] is True
    assert "--draft-file /tmp/0guard-wallet-provider-proof-draft.json" in (
        result["proofDraftAssistant"]["draftFileRecorderCommandTemplate"]
    )
    assert result["privateKeysReturned"] is False
    assert result["rawParamsReturned"] is False
    assert result["transactionSigningEnabled"] is False
    assert result["transactionBroadcastingEnabled"] is False
    assert result["safety"]["transactionSigningEnabled"] is False


def test_wallet_provider_external_proof_command_uses_repo_relative_default_path():
    result = build_wallet_provider_external_proof_status()

    assert result["proofPath"].endswith("docs/hackathon-0g/wallet-provider-external-proof.json")
    assert result["operatorProofPath"] == "docs/hackathon-0g/wallet-provider-external-proof.json"
    assert "--out docs/hackathon-0g/wallet-provider-external-proof.json" in (
        result["recordProofCommandTemplate"]
    )
    assert "/app/docs/hackathon-0g/wallet-provider-external-proof.json" not in (
        result["recordProofCommandTemplate"]
    )
    assert "--out docs/hackathon-0g/wallet-provider-external-proof.json" in (
        result["draftFileRecorderCommandTemplate"]
    )
    assert "/app/docs/hackathon-0g/wallet-provider-external-proof.json" not in (
        result["draftFileRecorderCommandTemplate"]
    )


def test_wallet_provider_external_proof_accepts_real_extension_flow():
    proof = _valid_external_proof()

    result = verify_wallet_provider_external_proof(proof)

    assert result["verified"] is True
    assert result["blockers"] == []
    assert result["proofBlockers"] == []
    assert result["realWalletExtension"] is True
    assert result["mockProvider"] is False
    assert result["throwawayWallet"] is True
    assert (
        result["suggestedExternalProofUrl"]
        == "https://arigatoexpress.github.io/0guard/wallet-provider-proof/"
    )
    assert result["privateKeysReturned"] is False
    assert result["rawParamsReturned"] is False
    assert result["transactionSigningEnabled"] is False
    assert result["readOnlyRequest"]["forwardedToProvider"] is True
    assert result["reviewRequest"]["forwardedToProvider"] is False
    assert result["denyRequest"]["forwardedToProvider"] is False
    assert result["checks"]["denyDidNotAddProviderCall"] is True
    assert result["safety"]["privateKeysReturned"] is False
    assert result["safety"]["moneyMovementEnabled"] is False


def test_wallet_provider_external_proof_rejects_mock_or_wallet_prompt():
    proof = _valid_external_proof()
    proof["mockProvider"] = True
    proof["denyRequest"]["walletPromptShown"] = True

    result = verify_wallet_provider_external_proof(proof)

    assert result["verified"] is False
    assert "proof_check_failed:mockProvider" in result["blockers"]
    assert "proof_check_failed:denyRequest" in result["proofBlockers"]
    assert result["checks"]["mockProvider"] is False
    assert result["checks"]["denyRequest"] is False
    assert result["safety"]["providerForwardingPerformedBy0guard"] is False


def test_wallet_address_hash_is_stable_and_does_not_return_raw_address():
    address = "0x000000000000000000000000000000000000bEEF"

    result = wallet_address_hash(address)

    assert len(result) == 64
    assert result == wallet_address_hash(address.lower())
    assert address.lower() not in result


def _valid_external_proof() -> dict:
    wallet_hash = wallet_address_hash("0x000000000000000000000000000000000000bEEF")
    return {
        "schema": WALLET_PROVIDER_EXTERNAL_PROOF_SCHEMA,
        "proofMode": "real_wallet_extension_window_ethereum",
        "externalDappOrigin": "http://127.0.0.1:8142",
        "guardBaseUrl": "https://guard0-miniapp-s77j6bxyra-uc.a.run.app",
        "windowEthereumPresent": True,
        "realWalletExtension": True,
        "mockProvider": False,
        "throwawayWallet": True,
        "walletWasEmpty": True,
        "walletAddressHash": wallet_hash,
        "readOnlyRequest": {
            "method": "eth_chainId",
            "decision": "allow",
            "forwardedToProvider": True,
            "walletPromptShown": False,
            "providerCallCount": 1,
            "receiptHash": "a" * 64,
        },
        "reviewRequest": {
            "method": "wallet_switchEthereumChain",
            "decision": "review",
            "forwardedToProvider": False,
            "walletPromptShown": False,
            "providerCallCount": 1,
            "receiptHash": "b" * 64,
        },
        "denyRequest": {
            "method": "eth_sendTransaction",
            "decision": "deny",
            "forwardedToProvider": False,
            "walletPromptShown": False,
            "providerCallCount": 1,
            "receiptHash": "c" * 64,
        },
        "operatorReviewed": True,
        "rawParamsReturned": False,
        "providerCallLogRawParamsStored": False,
        "privateKeysReturned": False,
        "mnemonicsReturned": False,
        "transactionSigningByZeroGuard": False,
        "transactionBroadcastingByZeroGuard": False,
        "moneyMovementByZeroGuard": False,
    }
