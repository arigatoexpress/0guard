"""CLI tests for public-safe wallet-provider proof recording."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from guard0.wallet_provider_guard import wallet_address_hash


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_wallet_provider_proof_recorder_accepts_public_safe_draft_file(tmp_path):
    draft = tmp_path / "wallet-proof-draft.json"
    out = tmp_path / "wallet-provider-external-proof.json"
    wallet_hash = wallet_address_hash("0x000000000000000000000000000000000000bEEF")
    draft.write_text(
        json.dumps(
            {
                "schema": "0guard.wallet_provider_external_proof_draft.v1",
                "status": "ready_for_operator_review",
                "externalDappOrigin": "https://arigatoexpress.github.io",
                "guardBaseUrl": "https://guard0-miniapp-s77j6bxyra-uc.a.run.app",
                "windowEthereumPresent": True,
                "walletAddressHash": wallet_hash,
                "rawWalletAddressStored": False,
                "rawParamsStored": False,
                "scenarioEvidence": {
                    "readOnlyRequest": {
                        "method": "eth_chainId",
                        "decision": "allow",
                        "forwardedToProvider": True,
                        "walletPromptShown": False,
                        "providerCallCount": 1,
                        "receiptHash": _receipt_hash("read-only"),
                    },
                    "reviewRequest": {
                        "method": "wallet_switchEthereumChain",
                        "decision": "review",
                        "forwardedToProvider": False,
                        "walletPromptShown": False,
                        "providerCallCount": 1,
                        "receiptHash": _receipt_hash("review"),
                    },
                    "denyRequest": {
                        "method": "eth_sendTransaction",
                        "decision": "deny",
                        "forwardedToProvider": False,
                        "walletPromptShown": False,
                        "providerCallCount": 1,
                        "receiptHash": _receipt_hash("deny"),
                    },
                },
            }
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/record_wallet_provider_external_proof.py",
            "--draft-file",
            str(draft),
            "--out",
            str(out),
            "--real-wallet-extension",
            "--window-ethereum-present",
            "--throwaway-empty-wallet",
            "--operator-reviewed",
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONPATH": "src"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr or result.stdout
    record = json.loads(result.stdout)
    assert record["schema"] == "0guard.wallet_provider_external_proof_record.v1"
    assert record["verification"]["verified"] is True

    proof_text = out.read_text(encoding="utf-8")
    proof = json.loads(proof_text)
    assert proof["walletAddressHash"] == wallet_hash
    assert proof["externalDappOrigin"] == "https://arigatoexpress.github.io"
    assert proof["readOnlyRequest"]["receiptHash"] == _receipt_hash("read-only")
    assert proof["reviewRequest"]["receiptHash"] == _receipt_hash("review")
    assert proof["denyRequest"]["receiptHash"] == _receipt_hash("deny")
    assert proof["safety"]["rawWalletAddressStored"] is False
    assert "0x000000000000000000000000000000000000beef" not in proof_text.lower()
    assert "private_key" not in proof_text.lower()
    assert proof["mnemonicsReturned"] is False


def test_wallet_provider_proof_recorder_rejects_incomplete_draft_file(tmp_path):
    draft = tmp_path / "wallet-proof-draft.json"
    out = tmp_path / "wallet-provider-external-proof.json"
    draft.write_text(
        json.dumps(
            {
                "schema": "0guard.wallet_provider_external_proof_draft.v1",
                "status": "incomplete",
                "windowEthereumPresent": True,
                "rawWalletAddressStored": False,
                "rawParamsStored": False,
            }
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/record_wallet_provider_external_proof.py",
            "--draft-file",
            str(draft),
            "--out",
            str(out),
            "--real-wallet-extension",
            "--window-ethereum-present",
            "--throwaway-empty-wallet",
            "--operator-reviewed",
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONPATH": "src"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "ready_for_operator_review" in result.stderr
    assert not out.exists()


def test_wallet_provider_proof_recorder_rejects_localhost_placeholder_draft(tmp_path):
    draft = tmp_path / "wallet-proof-draft.json"
    out = tmp_path / "wallet-provider-external-proof.json"
    wallet_hash = wallet_address_hash("0x000000000000000000000000000000000000bEEF")
    draft.write_text(
        json.dumps(
            {
                "schema": "0guard.wallet_provider_external_proof_draft.v1",
                "status": "ready_for_operator_review",
                "externalDappOrigin": "http://127.0.0.1:8142",
                "guardBaseUrl": "https://guard0-miniapp-s77j6bxyra-uc.a.run.app",
                "windowEthereumPresent": True,
                "walletAddressHash": wallet_hash,
                "rawWalletAddressStored": False,
                "rawParamsStored": False,
                "scenarioEvidence": {
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
                },
            }
        ),
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "scripts/record_wallet_provider_external_proof.py",
            "--draft-file",
            str(draft),
            "--out",
            str(out),
            "--real-wallet-extension",
            "--window-ethereum-present",
            "--throwaway-empty-wallet",
            "--operator-reviewed",
        ],
        cwd=REPO_ROOT,
        env={**os.environ, "PYTHONPATH": "src"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "externalDappOrigin" in result.stdout
    assert "readOnlyRequest" in result.stdout
    assert not out.exists()


def _receipt_hash(label: str) -> str:
    return hashlib.sha256(f"wallet-provider-proof:{label}".encode()).hexdigest()
