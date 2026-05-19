"""Tests for the EIP-1193 wallet-provider guard contract."""

import json

import pytest

from guard0.wallet_provider_guard import build_wallet_provider_guard


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
