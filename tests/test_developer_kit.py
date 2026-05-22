"""Tests for the 0guard developer-kit manifest and examples."""

from __future__ import annotations

import py_compile
from pathlib import Path

from guard0.developer_kit import developer_kit_manifest

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_developer_kit_manifest_is_actionable_and_non_mutating():
    manifest = developer_kit_manifest()

    assert manifest["schema"] == "0guard.developer_kit.v1"
    assert manifest["mode"] == "no_secret_native_preflight_sdk"
    assert manifest["quickstart"]["localServer"] == "python3 -m guard0.cli serve --port 8109"
    assert "normalize-reputation-adapter" in manifest["quickstart"]["cliAdapterNormalizeProbe"]
    assert "reputation-shadow-cache" in manifest["quickstart"]["cliReputationShadowCacheProbe"]
    assert "proof-ladder" in manifest["quickstart"]["cliProofLadderProbe"]
    assert any(route["path"] == "/api/native-preflight" for route in manifest["routes"])
    assert any(route["path"] == "/api/wallet/provider-guard" for route in manifest["routes"])
    assert any(route["path"] == "/api/readyz" for route in manifest["routes"])
    assert any(route["path"] == "/api/threat-case-file" for route in manifest["routes"])
    assert any(route["path"] == "/api/experiments/frontier" for route in manifest["routes"])
    assert any(route["path"] == "/api/developer-kit" for route in manifest["routes"])
    assert any(route["path"] == "/api/reputation/probe" for route in manifest["routes"])
    assert any(route["path"] == "/api/reputation/adapters" for route in manifest["routes"])
    assert any(route["path"] == "/api/reputation/adapters/normalize" for route in manifest["routes"])
    assert any(route["path"] == "/api/reputation/shadow-cache" for route in manifest["routes"])
    assert any(route["path"] == "/api/0g/proof-ladder" for route in manifest["routes"])
    assert {recipe["id"] for recipe in manifest["adapterRecipes"]} >= {
        "agentkit_turnkey_safe_evm",
        "ika_mpckit_odws",
        "x402_prepared_payment",
        "telegram_ton_miniapp",
        "arbitrum_l2_ci_gate",
    }
    assert manifest["examplePayloads"]["readOnlyEvmStatus"]["expectedDecision"] == "allow"
    assert manifest["examplePayloads"]["blockIkaSweep"]["expectedDecision"] == "deny"
    assert manifest["examplePayloads"]["blockProviderApproval"]["expectedDecision"] == "deny"
    assert manifest["safety"]["transactionSigningEnabled"] is False
    assert manifest["safety"]["paymentSettlementEnabled"] is False
    assert manifest["safety"]["telegramSendsEnabled"] is False


def test_native_preflight_examples_are_present_and_do_not_execute_live_paths():
    python_example = REPO_ROOT / "examples" / "native_preflight" / "python_client.py"
    ts_example = REPO_ROOT / "examples" / "native_preflight" / "nativePreflight.ts"
    readme = REPO_ROOT / "examples" / "native_preflight" / "README.md"

    assert python_example.exists()
    assert ts_example.exists()
    assert readme.exists()
    py_compile.compile(str(python_example), doraise=True)

    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in [python_example, ts_example, readme]
    )
    banned_live_terms = [
        "private_key",
        "sendRawTransaction",
        "sendTransaction",
        "createWallet",
        "broadcastTransaction",
        "setWebhook",
    ]
    for term in banned_live_terms:
        assert term not in combined


def test_wallet_provider_guard_example_is_present_and_blocks_before_prompt():
    ts_example = REPO_ROOT / "examples" / "wallet_provider_guard" / "providerGuard.ts"
    readme = REPO_ROOT / "examples" / "wallet_provider_guard" / "README.md"
    docs = REPO_ROOT / "docs" / "WALLET_PROVIDER_GUARD.md"
    external_dapp = REPO_ROOT / "examples" / "wallet_provider_guard" / "external_dapp"
    pages_capture = REPO_ROOT / "docs" / "wallet-provider-proof"

    assert ts_example.exists()
    assert readme.exists()
    assert docs.exists()
    assert (external_dapp / "index.html").exists()
    assert (external_dapp / "app.js").exists()
    assert (pages_capture / "index.html").exists()
    assert (pages_capture / "app.js").exists()

    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in [
            ts_example,
            readme,
            docs,
            external_dapp / "index.html",
            external_dapp / "app.js",
            pages_capture / "index.html",
            pages_capture / "app.js",
        ]
    )
    assert "/api/wallet/provider-guard" in combined
    assert "WalletGuardBlockedError" in combined
    assert "provider.request<T>(request)" in combined
    assert "window.ethereum" in combined
    assert "https://arigatoexpress.github.io/0guard/wallet-provider-proof/" in combined
    assert "wallet_provider_external_proof_draft" in combined
    assert "rawWalletAddressStored" in combined
    assert "proofOutputPath" in combined
    assert "--out docs/hackathon-0g/wallet-provider-external-proof.json" in combined
    assert "record_wallet_provider_external_proof.py" in combined
    assert "unexpected_allow_refused_by_capture_page" in combined
    assert "review" in combined
    assert "deny" in combined
    assert "private_key" not in combined
    assert "seed phrase" not in combined.lower()
