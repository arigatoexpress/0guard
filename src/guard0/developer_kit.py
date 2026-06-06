"""Developer-kit manifest for the 0guard native preflight product surface."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

DEVELOPER_KIT_SCHEMA = "0guard.developer_kit.v1"


def developer_kit_manifest() -> dict[str, Any]:
    """Return the install-light developer kit for pre-signer integrations."""
    return {
        "schema": DEVELOPER_KIT_SCHEMA,
        "generatedAt": _now(),
        "mode": "no_secret_native_preflight_sdk",
        "transactionSigningEnabled": False,
        "positioning": {
            "headline": "One deterministic preflight call before any signer.",
            "whoItServes": [
                "wallet apps",
                "AI agent frameworks",
                "Telegram Mini Apps",
                "x402 facilitators",
                "EVM L2 applications",
            ],
            "whyNow": (
                "Agentic crypto products need a small safety gate that catches intent, "
                "calldata, policy, and known exploit signatures before a wallet prompt."
            ),
        },
        "quickstart": {
            "localServer": "python3 -m guard0.cli serve --port 8109",
            "cliAllowProbe": (
                "python3 -m guard0.cli native-preflight "
                "--payload-json '{\"surface\":\"evm\",\"operation\":\"read_status\","
                "\"chain\":\"eip155:8453\"}'"
            ),
            "apiAllowProbe": {
                "method": "POST",
                "path": "/api/native-preflight",
                "body": {
                    "surface": "evm",
                    "operation": "read_status",
                    "chain": "eip155:8453",
                    "intent": {"mode": "preview"},
                },
            },
            "cliAdapterNormalizeProbe": (
                "python3 -m guard0.cli normalize-reputation-adapter "
                "--payload-json '{\"sourceId\":\"chainabuse\",\"payload\":{\"reported_count\":1}}'"
            ),
            "cliReputationShadowCacheProbe": "python3 -m guard0.cli reputation-shadow-cache",
            "cliProofLadderProbe": (
                "python3 -m guard0.cli proof-ladder "
                "--payload-json '{\"intent\":{\"action\":\"approve\","
                "\"mode\":\"live_transaction\",\"requires_signature\":true}}'"
            ),
        },
        "routes": [
            {
                "method": "GET",
                "path": "/api/developer-kit",
                "purpose": "Machine-readable manifest for SDK, CI, wallet, and Mini App adapters.",
            },
            {
                "method": "GET",
                "path": "/api/readyz",
                "purpose": "Operational readiness profile for mainnet verifier config, data freshness, shadow cache, and safety posture.",
            },
            {
                "method": "GET",
                "path": "/api/deployment/readiness",
                "purpose": "No-side-effect promotion packet for Pages, hosted API, Docker, Render, and Cloud Run readiness.",
            },
            {
                "method": "POST",
                "path": "/api/native-preflight",
                "purpose": "Primary allow/review/deny verdict before a signing surface.",
            },
            {
                "method": "POST",
                "path": "/api/wallet/provider-guard",
                "purpose": "EIP-1193 wallet-provider request verdict before a dapp forwards to MetaMask or another injected wallet.",
            },
            {
                "method": "POST",
                "path": "/api/threat-case-file",
                "purpose": "Composed proof dossier for one agent intent across policy, reputation, provenance, and receipts.",
            },
            {
                "method": "GET",
                "path": "/api/experiments/frontier",
                "purpose": "Ranked read-only experiment lab for safe next-integration planning.",
            },
            {
                "method": "POST",
                "path": "/api/experiments/run",
                "purpose": "No-side-effect preview for one frontier experiment.",
            },
            {
                "method": "GET",
                "path": "/api/hackathon/strategy",
                "purpose": "0G-first build order and next-hackathon target rationale.",
            },
            {
                "method": "GET",
                "path": "/api/hackathons/next",
                "purpose": "Chronological Arbitrum, MetaMask, and AI-agent hackathon execution plan.",
            },
            {
                "method": "GET",
                "path": "/api/intelligence/events",
                "purpose": "Polling snapshot of real read-only OSINT signals, source readiness, and chain heads.",
            },
            {
                "method": "GET",
                "path": "/api/integrations/arbitrum",
                "purpose": "Arbitrum One/Nova/Sepolia safety-pack plan and pre-signer risk rules.",
            },
            {
                "method": "GET",
                "path": "/api/integrations/metamask",
                "purpose": "MetaMask Connect, Snap insights, and delegated-permission guardrail plan.",
            },
            {
                "method": "POST",
                "path": "/api/reputation/probe",
                "purpose": "Rights-aware domain, address, label, and source-evidence reputation probe.",
            },
            {
                "method": "GET/POST",
                "path": "/api/reputation/connectors",
                "purpose": "No-network manifest for GoPlus, Chainabuse, Forta, TON, simulation, and cross-chain connector activation.",
            },
            {
                "method": "GET",
                "path": "/api/reputation/adapters",
                "purpose": "No-network normalization contract for PhishDestroy, CryptoScamDB, Forta, GoPlus, and Chainabuse payload shapes.",
            },
            {
                "method": "POST",
                "path": "/api/reputation/adapters/normalize",
                "purpose": "Convert caller-provided external reputation payloads into derived evidence without echoing raw source payloads.",
            },
            {
                "method": "GET/POST",
                "path": "/api/reputation/shadow-cache",
                "purpose": "Compose multiple reviewed adapter payloads into a reusable derived intelligence snapshot with no live fetch or raw resale.",
            },
            {
                "method": "GET/POST",
                "path": "/api/0g/proof-ladder",
                "purpose": "Build a Chain, Storage, DA, Compute, and Alignment proof packet without live uploads, inference, signing, or broadcasts.",
            },
            {
                "method": "POST",
                "path": "/api/integrations/external-guardrails/evaluate",
                "purpose": "Targeted guardrail checks for x402, L2, DA, bridge, and exchange intents.",
            },
        ],
        "examples": [
            {
                "language": "python",
                "path": "examples/native_preflight/python_client.py",
                "runtime": "stdlib urllib only",
                "purpose": "CI or backend gate that exits non-zero unless the verdict is allow.",
            },
            {
                "language": "typescript",
                "path": "examples/native_preflight/nativePreflight.ts",
                "runtime": "fetch-compatible browser, Node, or worker",
                "purpose": "Drop-in wrapper that calls 0guard before invoking an app-owned signer.",
            },
            {
                "language": "typescript",
                "path": "examples/wallet_provider_guard/providerGuard.ts",
                "runtime": "EIP-1193 browser wallet provider",
                "purpose": "Proxy wrapper that blocks deny/review wallet-provider requests before the wallet popup.",
            },
            {
                "language": "javascript",
                "path": "examples/wallet_provider_guard/external_dapp/",
                "runtime": "static browser dapp with injected window.ethereum",
                "purpose": "External-origin smoke page that proves only allow verdicts reach window.ethereum.request.",
            },
        ],
        "adapterRecipes": _adapter_recipes(),
        "examplePayloads": _example_payloads(),
        "receiptContract": {
            "hashAlgorithm": "sha256_canonical_json",
            "0gChainReady": True,
            "0gStorageReady": True,
            "liveAnchorPerformedByDeveloperKit": False,
            "liveUploadPerformedByDeveloperKit": False,
        },
        "developerPromise": [
            "Call 0guard before signer access.",
            "Treat deny as a hard stop.",
            "Treat review as a user-visible explanation and simulation-only lane.",
            "Store or anchor receipts only from an operator-approved deployment path.",
        ],
        "safety": _safety(),
    }


def _adapter_recipes() -> list[dict[str, Any]]:
    return [
        {
            "id": "agentkit_turnkey_safe_evm",
            "ecosystem": "EVM wallets and agent frameworks",
            "stage": "pre_signer",
            "call": "/api/native-preflight",
            "optionalContext": "/api/reputation/probe for counterparty/domain/source-evidence context",
            "inputMapping": {
                "surface": "evm",
                "operation": "proposed wallet operation or method",
                "chain": "CAIP-2 chain id such as eip155:42161 or eip155:8453",
                "target": "contract or counterparty address",
                "messageHex": "calldata or typed-data digest when available",
                "intentText": "human-readable agent/user instruction",
            },
            "allowBehavior": "continue to the app-owned simulation or signing flow",
            "reviewBehavior": "show receipt explanation, require manual review, avoid signing",
            "denyBehavior": "do not request a wallet signature",
        },
        {
            "id": "x402_prepared_payment",
            "ecosystem": "x402 and paid API products",
            "stage": "before payment settlement",
            "call": "/api/native-preflight",
            "inputMapping": {
                "surface": "x402",
                "operation": "quote, pay, settle, refund, or fulfill",
                "intentText": "resource being purchased and why",
                "config": "payment amount, network, facilitator, and refund policy metadata",
            },
            "allowBehavior": "continue to quote or fulfillment preview",
            "reviewBehavior": "show price, policy, and receipt before settlement",
            "denyBehavior": "do not settle from the 0guard workbench",
        },
        {
            "id": "telegram_ton_miniapp",
            "ecosystem": "Telegram Mini App and TON wallet context",
            "stage": "before tonProof or transaction prompt",
            "call": "/api/native-preflight",
            "inputMapping": {
                "surface": "ton",
                "chain": "ton:mainnet or ton:testnet",
                "tonAddress": "wallet address when available",
                "intentText": "what the Mini App wants the user to approve",
            },
            "allowBehavior": "show low-noise alert preview",
            "reviewBehavior": "show TON risk passport and Mira-style explanation",
            "denyBehavior": "do not request tonProof or a transaction from this surface",
        },
        {
            "id": "arbitrum_l2_ci_gate",
            "ecosystem": "Arbitrum and EVM L2 deployment pipelines",
            "stage": "pre_deploy_or_pre_admin_action",
            "call": "python3 -m guard0.cli native-preflight --payload-json ...",
            "inputMapping": {
                "surface": "evm",
                "operation": "deploy, upgrade, grantRole, approve, or bridge_release",
                "chain": "target L2 CAIP-2 id",
                "messageHex": "constructor/admin calldata or selector",
            },
            "allowBehavior": "continue to CI simulation or multisig proposal",
            "reviewBehavior": "attach receipt to PR or multisig proposal",
            "denyBehavior": "fail CI before any operator wallet prompt",
        },
    ]


def _example_payloads() -> dict[str, dict[str, Any]]:
    return {
        "readOnlyEvmStatus": {
            "surface": "evm",
            "operation": "read_status",
            "chain": "eip155:8453",
            "intent": {"mode": "preview"},
            "expectedDecision": "allow",
        },
        "reviewX402Payment": {
            "surface": "x402",
            "operation": "settle",
            "chain": "eip155:8453",
            "intentText": "Pay for an intelligence artifact before fulfillment preview.",
            "config": {"amountUsd": "5.00", "facilitator": "operator-reviewed"},
            "expectedDecision": "review",
        },
        "blockProviderApproval": {
            "method": "eth_sendTransaction",
            "origin": "https://example-dapp.test",
            "params": [
                {
                    "chainId": "0x1",
                    "to": "0x000000000000000000000000000000000000dEaD",
                    "data": "0x095ea7b3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    "value": "0x0",
                }
            ],
            "expectedDecision": "deny",
        },
    }


def _safety() -> dict[str, bool]:
    return {
        "readOnly": True,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "privateKeyImportEnabled": False,
        "walletCreationEnabled": False,
        "bridgingEnabled": False,
        "paymentSettlementEnabled": False,
        "exchangeOrdersEnabled": False,
        "telegramSendsEnabled": False,
        "socialPostingEnabled": False,
        "secretDisplayEnabled": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
