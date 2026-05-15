"""Cross-chain integration fabric for 0guard.

This module is intentionally read-only. It exposes verified network metadata,
payment/agent integration posture, and optional RPC health probes without
signing, broadcasting, bridging, swapping, or launching agents.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

CROSSCHAIN_CATALOG_SCHEMA = "0guard.crosschain_catalog.v1"
CROSSCHAIN_READINESS_SCHEMA = "0guard.crosschain_readiness.v1"
AGENT_FACILITATOR_SCHEMA = "0guard.virtuals_facilitator_manifest.v1"


@dataclass(frozen=True)
class ChainTarget:
    id: str
    name: str
    kind: str
    status: str
    chain_id: int | None
    rpc_env: str | None
    default_rpc: str | None
    http_status_env: str | None
    default_http_status_url: str | None
    explorer: str | None
    native_asset: str
    evm_compatible: bool
    probe_default: bool
    capabilities: tuple[str, ...]
    x402_posture: str
    proof_strategy: str
    official_sources: tuple[str, ...]
    caveats: tuple[str, ...] = ()

    def public(self) -> dict[str, Any]:
        rpc = configured_rpc(self)
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "status": self.status,
            "chainId": self.chain_id,
            "nativeAsset": self.native_asset,
            "evmCompatible": self.evm_compatible,
            "rpc": rpc,
            "rpcEnv": self.rpc_env,
            "rpcConfigured": bool(rpc),
            "httpStatusUrl": configured_http_status_url(self),
            "httpStatusEnv": self.http_status_env,
            "explorer": self.explorer,
            "probeDefault": self.probe_default,
            "capabilities": list(self.capabilities),
            "x402Posture": self.x402_posture,
            "proofStrategy": self.proof_strategy,
            "officialSources": list(self.official_sources),
            "caveats": list(self.caveats),
        }


CHAIN_TARGETS: tuple[ChainTarget, ...] = (
    ChainTarget(
        id="0g_mainnet",
        name="0G Mainnet",
        kind="proof_anchor",
        status="mainnet",
        chain_id=16661,
        rpc_env="ZGG_CHAIN_RPC",
        default_rpc="https://evmrpc.0g.ai",
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://chainscan.0g.ai",
        native_asset="0G",
        evm_compatible=True,
        probe_default=True,
        capabilities=(
            "policy_receipt_anchor",
            "read_only_rpc",
            "storage_ready_root_hashes",
            "custom_x402_facilitator_candidate",
        ),
        x402_posture=(
            "custom_facilitator_required; current public x402 facilitators do not list 0G "
            "as a default settlement network"
        ),
        proof_strategy="Anchor receipt hashes and readable summaries on 0G; store full receipt JSON in 0G Storage when configured.",
        official_sources=(
            "https://docs.0g.ai/developer-hub/mainnet/mainnet-overview",
            "https://docs.0g.ai/developer-hub/building-on-0g/contracts-on-0g/deploy-contracts",
        ),
    ),
    ChainTarget(
        id="base_mainnet",
        name="Base Mainnet",
        kind="agent_payment_network",
        status="mainnet",
        chain_id=8453,
        rpc_env="BASE_RPC_URL",
        default_rpc="https://mainnet.base.org",
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://basescan.org",
        native_asset="ETH",
        evm_compatible=True,
        probe_default=True,
        capabilities=("virtuals_protocol", "x402_default_network", "agent_identity", "read_only_rpc"),
        x402_posture="supported_default_network_for_x402_payments",
        proof_strategy="Use Base/x402 for paid artifact access; anchor the resulting 0guard policy proof to 0G.",
        official_sources=(
            "https://docs.base.org/base-chain/network-information",
            "https://docs.cdp.coinbase.com/x402/network-support",
            "https://whitepaper.virtuals.io/",
        ),
        caveats=("Launching or tokenizing an agent on Virtuals is an external side effect and stays operator-only.",),
    ),
    ChainTarget(
        id="abstract_mainnet",
        name="Abstract Mainnet",
        kind="consumer_l2_guardrail",
        status="mainnet",
        chain_id=2741,
        rpc_env="ABSTRACT_RPC_URL",
        default_rpc="https://api.mainnet.abs.xyz",
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://abscan.org",
        native_asset="ETH",
        evm_compatible=True,
        probe_default=True,
        capabilities=(
            "read_only_rpc",
            "abstract_global_wallet_context",
            "consumer_app_risk_preview",
            "native_l2_receipt_context",
        ),
        x402_posture="custom_facilitator_required_or_supported_network_bridge_needed",
        proof_strategy=(
            "Use Abstract as a native consumer-wallet risk lane; keep 0G as the common "
            "receipt/provenance anchor instead of requiring bridge flows."
        ),
        official_sources=(
            "https://docs.abs.xyz/connect-to-abstract",
            "https://docs.abs.xyz/what-is-abstract",
            "https://docs.abs.xyz/abstract-global-wallet/agw-client/wallet-linking/overview",
        ),
        caveats=(
            "Abstract funding, portal, and wallet-linking actions are external side effects and stay outside API routes.",
        ),
    ),
    ChainTarget(
        id="arbitrum_one",
        name="Arbitrum One",
        kind="agent_payment_network",
        status="mainnet",
        chain_id=42161,
        rpc_env="ARBITRUM_RPC_URL",
        default_rpc="https://arb1.arbitrum.io/rpc",
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://arbiscan.io",
        native_asset="ETH",
        evm_compatible=True,
        probe_default=True,
        capabilities=("x402_default_network", "read_only_rpc", "artifact_access"),
        x402_posture="supported_default_network_for_x402_payments",
        proof_strategy="Offer paid read access to derived threat receipts while preserving 0G as the proof anchor.",
        official_sources=(
            "https://docs.arbitrum.io/for-devs/dev-tools-and-resources/chain-info",
            "https://docs.cdp.coinbase.com/x402/network-support",
        ),
    ),
    ChainTarget(
        id="polygon_pos",
        name="Polygon PoS",
        kind="agent_payment_network",
        status="mainnet",
        chain_id=137,
        rpc_env="POLYGON_RPC_URL",
        default_rpc="https://polygon.drpc.org",
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://polygonscan.com",
        native_asset="POL",
        evm_compatible=True,
        probe_default=True,
        capabilities=("x402_default_network", "polygon_x402_facilitator", "read_only_rpc"),
        x402_posture="supported_default_network_for_x402_payments",
        proof_strategy="Use x402 facilitator support for low-cost paid API gates; settle proof hashes separately on 0G.",
        official_sources=(
            "https://docs.polygon.technology/pos/reference/rpc-endpoints/",
            "https://docs.polygon.technology/tools/x402/",
            "https://docs.cdp.coinbase.com/x402/network-support",
        ),
        caveats=("Set POLYGON_RPC_URL to override the default public read-only endpoint.",),
    ),
    ChainTarget(
        id="megaeth_mainnet",
        name="MegaETH Mainnet",
        kind="evm_expansion_network",
        status="mainnet",
        chain_id=4326,
        rpc_env="MEGAETH_MAINNET_RPC_URL",
        default_rpc="https://mainnet.megaeth.com/rpc",
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://megaexplorer.xyz",
        native_asset="ETH",
        evm_compatible=True,
        probe_default=True,
        capabilities=("read_only_rpc", "evm_policy_simulation", "future_low_latency_agent_flow"),
        x402_posture="custom_facilitator_required_or_supported_network_bridge_needed",
        proof_strategy="Treat MegaETH mainnet as a fast EVM readiness lane until payment support is explicit.",
        official_sources=("https://docs.megaeth.com/tools/rpc",),
        caveats=("Use for read-only readiness unless a separate operator approves deployment or settlement.",),
    ),
    ChainTarget(
        id="megaeth_testnet",
        name="MegaETH Testnet",
        kind="evm_expansion_network",
        status="public_testnet",
        chain_id=6343,
        rpc_env="MEGAETH_RPC_URL",
        default_rpc="https://carrot.megaeth.com/rpc",
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://www.megaexplorer.xyz",
        native_asset="ETH",
        evm_compatible=True,
        probe_default=True,
        capabilities=("read_only_rpc", "evm_policy_simulation", "future_low_latency_agent_flow"),
        x402_posture="custom_facilitator_required_or_supported_network_bridge_needed",
        proof_strategy="Treat MegaETH as a fast EVM policy simulation/readiness lane until payment support is explicit.",
        official_sources=("https://docs.megaeth.com/tools/rpc",),
        caveats=("Use as testnet/readiness evidence, not production settlement.",),
    ),
    ChainTarget(
        id="monad_mainnet",
        name="Monad Mainnet",
        kind="evm_expansion_network",
        status="mainnet",
        chain_id=143,
        rpc_env="MONAD_RPC_URL",
        default_rpc="https://rpc.monad.xyz",
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://explorer.monad.xyz",
        native_asset="MON",
        evm_compatible=True,
        probe_default=True,
        capabilities=("read_only_rpc", "evm_policy_simulation", "high_throughput_agent_flow"),
        x402_posture="custom_facilitator_required_or_supported_network_bridge_needed",
        proof_strategy="Use Monad as a high-throughput EVM readiness lane; keep payment/facilitator claims separate.",
        official_sources=("https://docs.monad.xyz/network-reference/network-information",),
        caveats=("Set MONAD_RPC_URL to override the default public read-only endpoint.",),
    ),
    ChainTarget(
        id="hyperevm_mainnet",
        name="HyperEVM Mainnet",
        kind="evm_expansion_network",
        status="mainnet",
        chain_id=999,
        rpc_env="HYPEREVM_RPC_URL",
        default_rpc="https://rpc.hyperliquid.xyz/evm",
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://hyperevmscan.io",
        native_asset="HYPE",
        evm_compatible=True,
        probe_default=True,
        capabilities=("read_only_rpc", "evm_policy_simulation", "hype_ecosystem_guardrail"),
        x402_posture="custom_facilitator_required_or_supported_network_bridge_needed",
        proof_strategy="Add HyperEVM calldata/intent checks while leaving trade/order execution out of scope.",
        official_sources=("https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/hyperevm",),
    ),
    ChainTarget(
        id="tempo_moderato_testnet",
        name="Tempo Moderato Testnet",
        kind="payment_expansion_network",
        status="testnet",
        chain_id=42431,
        rpc_env="TEMPO_RPC_URL",
        default_rpc="https://rpc.moderato.tempo.xyz",
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://explore.tempo.xyz",
        native_asset="ETH",
        evm_compatible=True,
        probe_default=True,
        capabilities=("read_only_rpc", "payment_chain_watchlist", "future_agentic_payments"),
        x402_posture="custom_facilitator_required_or_supported_network_bridge_needed",
        proof_strategy="Track Tempo as an emerging payment chain and gate claims to testnet readback until mainnet support is explicit.",
        official_sources=("https://docs.tempo.xyz/testnet/getting-started",),
        caveats=("Tempo is treated as testnet/integration-watchlist in 0guard until mainnet details are configured.",),
    ),
    ChainTarget(
        id="lighter_exchange",
        name="Lighter exchange API",
        kind="verifiable_exchange_guardrail",
        status="mainnet_api",
        chain_id=None,
        rpc_env=None,
        default_rpc=None,
        http_status_env="LIGHTER_API_URL",
        default_http_status_url="https://mainnet.zklighter.elliot.ai/",
        explorer="https://etherscan.io/token/0x232ce3bd40fcd6f80f3d55a522d03f25df784ee2",
        native_asset="N/A",
        evm_compatible=False,
        probe_default=True,
        capabilities=(
            "read_only_status_api",
            "verifiable_order_matching",
            "ethereum_anchored_zk_rollup",
            "pre_trade_guardrail",
            "exchange_account_policy_context",
        ),
        x402_posture="not_an_evm_settlement_target_for_x402_by_default; protect as trading venue/API risk lane",
        proof_strategy=(
            "Use 0guard as a pre-trade policy guard for Lighter API/order intents; "
            "anchor blocked receipts to 0G and never generate API keys, place orders, "
            "use fee credits, trade, or request withdrawals from the workbench."
        ),
        official_sources=(
            "https://docs.lighter.xyz/",
            "https://docs.lighter.xyz/about-lighter/technical-architecture-lighter-core",
            "https://docs.lighter.xyz/about-lighter/lit-utility",
            "https://docs.lighter.xyz/perpetual-futures/api",
            "https://apidocs.lighter.xyz/reference/status",
        ),
        caveats=(
            "Lighter is integrated as a verifiable exchange/API guardrail, not as an EVM deployment network.",
            "Token, fee-credit, deposit, order, transfer, and withdrawal operations are external side effects.",
        ),
    ),
    ChainTarget(
        id="ton_telegram",
        name="TON / Telegram Wallet",
        kind="telegram_wallet_network",
        status="mainnet_read_only_preview",
        chain_id=None,
        rpc_env="TONCENTER_API_BASE",
        default_rpc=None,
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://tonscan.org",
        native_asset="TON",
        evm_compatible=False,
        probe_default=False,
        capabilities=(
            "telegram_mini_app_context",
            "ton_connect_manifest",
            "ton_wallet_risk_passport",
            "future_jetton_nft_activity_enrichment",
        ),
        x402_posture="not_an_evm_settlement_target_for_x402; protect as Telegram wallet risk lane",
        proof_strategy=(
            "Generate a TON risk passport in Telegram, hash the claim packet, and anchor "
            "selected receipts to 0G without asking TON wallets to sign."
        ),
        official_sources=(
            "https://core.telegram.org/bots/blockchain-guidelines",
            "https://docs.ton.org/v3/guidelines/ton-connect/overview",
            "https://docs.ton.org/ecosystem/api/toncenter/v3/overview",
        ),
        caveats=(
            "TON Connect transaction, signData, tonProof, and wallet-send flows are not called by 0guard.",
        ),
    ),
    ChainTarget(
        id="solana_mainnet",
        name="Solana Mainnet",
        kind="non_evm_wallet_monitor",
        status="planned_read_only_adapter",
        chain_id=None,
        rpc_env="SOLANA_RPC_URL",
        default_rpc=None,
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://explorer.solana.com",
        native_asset="SOL",
        evm_compatible=False,
        probe_default=False,
        capabilities=(
            "parsed_transaction_monitoring",
            "spl_token_risk_context",
            "helius_webhook_candidate",
            "no_signing_read_only",
        ),
        x402_posture="not_an_evm_settlement_target_for_x402; protect as native Solana risk lane",
        proof_strategy=(
            "Use parsed Solana activity as derived risk evidence and anchor 0guard verdict "
            "receipts to 0G; do not bridge funds into the product story."
        ),
        official_sources=(
            "https://solana.com/docs/rpc/http",
            "https://www.helius.dev/docs/webhooks",
        ),
        caveats=("No Solana signing, transaction submission, or wallet adapter is wired in this repo slice.",),
    ),
    ChainTarget(
        id="hyperliquid_info_api",
        name="Hyperliquid Info API",
        kind="exchange_read_only_monitor",
        status="planned_read_only_adapter",
        chain_id=None,
        rpc_env=None,
        default_rpc=None,
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://app.hyperliquid.xyz",
        native_asset="HYPE",
        evm_compatible=False,
        probe_default=False,
        capabilities=(
            "account_exposure_context",
            "order_and_fill_readback",
            "market_risk_digest",
            "no_exchange_actions",
        ),
        x402_posture="not_an_x402_settlement_target; protect as read-only exposure lane",
        proof_strategy=(
            "Read account/exposure context through official info endpoints only; keep orders, "
            "withdrawals, and signed exchange actions out of 0guard routes."
        ),
        official_sources=(
            "https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/info-endpoint",
            "https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/websocket",
        ),
        caveats=("Do not call exchange endpoints that place/cancel orders, transfer, or withdraw funds.",),
    ),
    ChainTarget(
        id="ika_dwallets",
        name="Ika dWallet Network",
        kind="zero_trust_signing_fabric",
        status="mainnet_sdk_reference",
        chain_id=None,
        rpc_env=None,
        default_rpc=None,
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://ika.xyz",
        native_asset="IKA",
        evm_compatible=False,
        probe_default=False,
        capabilities=(
            "native_multichain_signatures",
            "2pc_mpc_dwallets",
            "sui_coordinated_policy_caps",
            "pre_signing_0guard_receipts",
        ),
        x402_posture="not_an_x402_settlement_target; use as custody/signing fabric behind policy gates",
        proof_strategy=(
            "Run 0guard before any dWallet signature request; anchor 0guard verdicts to 0G "
            "while Ika handles native chain signatures only after separate operator approval."
        ),
        official_sources=(
            "https://docs.ika.xyz/",
            "https://docs.ika.xyz/docs/core-concepts/multi-chain-vs-cross-chain",
            "https://github.com/dwallet-labs/ika",
        ),
        caveats=(
            "0guard routes do not import keys, create dWallets, sign messages, or submit Ika transactions.",
        ),
    ),
    ChainTarget(
        id="ikavery_recovery",
        name="Ikavery quorum recovery",
        kind="quorum_recovery_reference",
        status="testnet_devnet_pre_alpha_reference",
        chain_id=None,
        rpc_env=None,
        default_rpc=None,
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://github.com/Iamknownasfesal/ikavery",
        native_asset="SUI/SOL",
        evm_compatible=False,
        probe_default=False,
        capabilities=(
            "passkey_or_wallet_quorum",
            "sui_testnet_recovery",
            "solana_devnet_recovery",
            "sweep_intent_preview",
        ),
        x402_posture="not_a_payment_settlement_target; integrate as recovery/custody UX reference",
        proof_strategy=(
            "Attach 0guard preflight receipts to Ikavery recovery/sweep proposals before quorum execution."
        ),
        official_sources=(
            "https://github.com/Iamknownasfesal/ikavery",
            "https://github.com/Iamknownasfesal/clear-msig-ika",
        ),
        caveats=(
            "Ikavery README says pre-alpha devnet/testnet only and unaudited; never import real-fund keys.",
            "Repository metadata does not declare a license, so do not vendor source without permission.",
        ),
    ),
    ChainTarget(
        id="encrypt_pre_alpha",
        name="Encrypt Pre-Alpha",
        kind="confidential_compute_watchlist",
        status="pre_alpha_devnet_plaintext_warning",
        chain_id=None,
        rpc_env=None,
        default_rpc=None,
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://github.com/dwallet-labs/encrypt-pre-alpha",
        native_asset="SOL",
        evm_compatible=False,
        probe_default=False,
        capabilities=(
            "solana_devnet_fhe_sdk",
            "mock_executor",
            "future_private_risk_scoring_candidate",
            "plaintext_today_warning",
        ),
        x402_posture="not_a_payment_settlement_target; future private-risk proof lane only",
        proof_strategy=(
            "Treat Encrypt as a future private-risk computation lane after real encryption guarantees; "
            "today it is devnet/plaintext and cannot protect sensitive 0guard data."
        ),
        official_sources=("https://github.com/dwallet-labs/encrypt-pre-alpha",),
        caveats=(
            "Encrypt pre-alpha README states there is no real encryption and data is public/plaintext.",
        ),
    ),
    ChainTarget(
        id="chainlink_ccip",
        name="Chainlink CCIP",
        kind="cross_chain_security_protocol",
        status="protocol_guardrail_catalog",
        chain_id=None,
        rpc_env=None,
        default_rpc=None,
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://ccip.chain.link",
        native_asset="N/A",
        evm_compatible=False,
        probe_default=False,
        capabilities=(
            "ccip_lane_policy_review",
            "cross_chain_token_pool_checks",
            "router_allowlist_review",
            "rate_limit_and_risk_control_context",
        ),
        x402_posture="not_an_x402_settlement_target; protect as cross-chain protocol-risk lane",
        proof_strategy=(
            "Score CCIP message and token-transfer intents before signer access; "
            "anchor blocked policy receipts to 0G instead of initiating transfers."
        ),
        official_sources=(
            "https://docs.chain.link/ccip",
            "https://chain.link/cross-chain",
        ),
        caveats=("Catalog-only in this repo; no CCIP send, token pool update, or router transaction is executed.",),
    ),
    ChainTarget(
        id="layerzero_v2",
        name="LayerZero V2",
        kind="cross_chain_security_protocol",
        status="protocol_guardrail_catalog",
        chain_id=None,
        rpc_env=None,
        default_rpc=None,
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://layerzeroscan.com",
        native_asset="N/A",
        evm_compatible=False,
        probe_default=False,
        capabilities=(
            "dvn_executor_config_review",
            "uln_threshold_checks",
            "send_receive_config_symmetry",
            "dead_dvn_detection",
            "replay_and_nonce_guardrails",
        ),
        x402_posture="not_an_x402_settlement_target; protect as cross-chain message-risk lane",
        proof_strategy=(
            "Detect weak DVN or asymmetric send/receive configs before a wallet signs bridge "
            "or omnichain app actions; anchor denials and evidence summaries to 0G."
        ),
        official_sources=(
            "https://docs.layerzero.network/v2/developers/evm/configuration/dvn-executor-config",
            "https://docs.layerzero.network/v2/concepts/modular-security/production-dvn-configuration",
        ),
        caveats=("Catalog-only in this repo; no LayerZero send, receive, DVN, or executor configuration is changed.",),
    ),
    ChainTarget(
        id="wormhole_ntt",
        name="Wormhole NTT",
        kind="cross_chain_security_protocol",
        status="protocol_guardrail_catalog",
        chain_id=None,
        rpc_env=None,
        default_rpc=None,
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://wormholescan.io",
        native_asset="N/A",
        evm_compatible=False,
        probe_default=False,
        capabilities=(
            "vaa_attestation_review",
            "transceiver_registry_checks",
            "global_accountant_supply_invariant",
            "guardian_threshold_context",
            "native_token_transfer_guardrails",
        ),
        x402_posture="not_an_x402_settlement_target; protect as cross-chain transfer-risk lane",
        proof_strategy=(
            "Preflight Wormhole NTT or VAA-driven actions for supply-invariant, registry, "
            "and replay risk; use 0G as the receipt/provenance anchor."
        ),
        official_sources=(
            "https://wormhole.com/docs/products/token-transfers/native-token-transfers/concepts/security/",
            "https://docs.wormhole.com/protocol/security/",
        ),
        caveats=("Catalog-only in this repo; no VAA submission, relayer call, or token transfer is executed.",),
    ),
    ChainTarget(
        id="celestia_blobstream",
        name="Celestia / TIA Blobstream",
        kind="data_availability_proof",
        status="mainnet_da_layer",
        chain_id=None,
        rpc_env="CELESTIA_RPC_URL",
        default_rpc=None,
        http_status_env=None,
        default_http_status_url=None,
        explorer="https://celenium.io",
        native_asset="TIA",
        evm_compatible=False,
        probe_default=False,
        capabilities=("data_availability", "blobstream_evm_proof_bridge", "catalog_ready_env_rpc_required"),
        x402_posture="not_an_evm_settlement_target_for_x402_by_default",
        proof_strategy="Use Celestia as a DA/Blobstream proof lane for receipt bundles, not as an EVM payment rail.",
        official_sources=(
            "https://docs.celestia.org/how-to-guides/blobstream",
            "https://docs.celestia.org/how-to-guides/interact",
        ),
        caveats=("TIA is not an EVM chain target; integrate via DA proofs or Blobstream, not EVM tx assumptions.",),
    ),
)


def configured_rpc(target: ChainTarget) -> str | None:
    if target.rpc_env:
        configured = os.getenv(target.rpc_env)
        if configured:
            return configured
    return target.default_rpc


def configured_http_status_url(target: ChainTarget) -> str | None:
    if target.http_status_env:
        configured = os.getenv(target.http_status_env)
        if configured:
            return configured
    return target.default_http_status_url


def cross_chain_catalog() -> dict[str, Any]:
    """Return source-cited cross-chain integration metadata."""
    targets = [target.public() for target in CHAIN_TARGETS]
    safety = _crosschain_safety(live=False)
    x402 = _x402_posture()
    return {
        "schema": CROSSCHAIN_CATALOG_SCHEMA,
        "generatedAt": _now(),
        "targetCount": len(targets),
        "evmTargetCount": sum(1 for target in targets if target["evmCompatible"]),
        "probeDefaultCount": sum(1 for target in targets if target["probeDefault"]),
        "targets": targets,
        "virtualsOnBase": virtuals_facilitator_manifest(include_catalog=False)["virtuals"],
        "x402": x402,
        "x402Mode": x402.get("mode"),
        "readableReceiptPlan": _readable_receipt_plan(),
        "safety": safety,
        "moneyMovementEnabled": safety.get("moneyMovementEnabled"),
    }


def cross_chain_readiness(
    *,
    live: bool = False,
    timeout_seconds: float = 3.0,
    include_non_default: bool = False,
) -> dict[str, Any]:
    """Return cross-chain readiness, optionally with read-only RPC probes."""
    probes = []
    attempted = 0
    ok = 0
    http_attempted = 0
    http_ok = 0
    for target in CHAIN_TARGETS:
        should_probe = (
            live
            and target.evm_compatible
            and bool(configured_rpc(target))
            and (target.probe_default or include_non_default)
        )
        should_probe_http = (
            live
            and not target.evm_compatible
            and bool(configured_http_status_url(target))
            and (target.probe_default or include_non_default)
        )
        if should_probe:
            attempted += 1
            probe = _probe_evm_rpc(target, timeout_seconds=timeout_seconds)
            if probe["status"] == "ok":
                ok += 1
        elif should_probe_http:
            http_attempted += 1
            probe = _probe_http_status(target, timeout_seconds=timeout_seconds)
            if probe["status"] == "ok":
                http_ok += 1
        else:
            probe = _not_probed(target, live=live, include_non_default=include_non_default)
        probes.append(probe)

    return {
        "schema": CROSSCHAIN_READINESS_SCHEMA,
        "generatedAt": _now(),
        "live": live,
        "attemptedRpcProbes": attempted,
        "okRpcProbes": ok,
        "rpcReadinessRatio": round(ok / attempted, 4) if attempted else None,
        "attemptedHttpProbes": http_attempted,
        "okHttpProbes": http_ok,
        "httpReadinessRatio": round(http_ok / http_attempted, 4) if http_attempted else None,
        "paymentReadiness": _payment_readiness(),
        "agentReadiness": _agent_readiness(),
        "probes": probes,
        "nextOperatorActions": _next_operator_actions(),
        "safety": _crosschain_safety(live=live),
    }


def virtuals_facilitator_manifest(*, include_catalog: bool = True) -> dict[str, Any]:
    """Return a deployable-but-not-deployed Virtuals/Base facilitator manifest."""
    manifest = {
        "schema": AGENT_FACILITATOR_SCHEMA,
        "generatedAt": _now(),
        "agent": {
            "name": "0guard Facilitator",
            "purpose": (
                "Broker pre-wallet risk checks, paid threat-receipt access, and 0G proof "
                "verification for agentic wallet workflows."
            ),
            "network": "Base",
            "chainId": 8453,
            "launchStatus": "prepared_operator_required",
            "deploymentMode": "manifest_only_no_external_side_effects",
            "operatorRequired": [
                "Create or connect Virtuals account/project.",
                "Review any Virtuals launch/token/agent terms.",
                "Provide explicit approval before any on-chain launch, payment, or agent publish.",
                "Configure BASE_RPC_URL and any Virtuals/GAME credentials outside the repo.",
            ],
        },
        "virtuals": {
            "protocol": "Virtuals Protocol",
            "primaryNetwork": "Base",
            "integrationUse": "agent_identity_and_distribution",
            "officialSources": [
                "https://whitepaper.virtuals.io/",
                "https://whitepaper.virtuals.io/developer-documents/game-framework/",
            ],
            "caveats": [
                "0guard has not launched a live Virtuals agent in this repo state.",
                "Any Virtuals launch or token action is an external side effect and is not triggered by API routes.",
            ],
        },
        "capabilities": [
            {
                "id": "risk_assess_intent",
                "route": "/api/evaluate",
                "mode": "read_only_pre_wallet",
                "output": "allow_review_deny_receipt",
            },
            {
                "id": "verify_0g_receipt",
                "route": "/api/0g/receipt",
                "mode": "read_only_contract_lookup",
                "output": "verified_receipt_or_not_found",
            },
            {
                "id": "cross_chain_readiness",
                "route": "/api/integrations/cross-chain/readiness",
                "mode": "read_only_rpc_probe_optional",
                "output": "chain_probe_and_payment_readiness",
            },
            {
                "id": "quote_paid_threat_packet",
                "route": "planned:/api/x402/threat-packets/<packet_id>/quote",
                "mode": "planned_x402_no_live_settlement_yet",
                "output": "payment_requirements_plus_rights_envelope",
            },
        ],
        "paymentPolicy": _x402_posture(),
        "safety": _crosschain_safety(live=False),
    }
    if include_catalog:
        manifest["crossChainTargets"] = [target.public() for target in CHAIN_TARGETS]
    return manifest


def _probe_evm_rpc(target: ChainTarget, *, timeout_seconds: float) -> dict[str, Any]:
    started = time.perf_counter()
    rpc = configured_rpc(target)
    if not rpc:
        return _not_probed(target, live=True, include_non_default=True)
    try:
        observed_chain_id = _rpc_int(rpc, "eth_chainId", timeout_seconds=timeout_seconds)
        latest_block = _rpc_int(rpc, "eth_blockNumber", timeout_seconds=timeout_seconds)
        chain_id_matches = target.chain_id is None or observed_chain_id == target.chain_id
        return {
            "id": target.id,
            "name": target.name,
            "status": "ok" if chain_id_matches else "chain_id_mismatch",
            "rpc": rpc,
            "chainId": target.chain_id,
            "observedChainId": observed_chain_id,
            "latestBlockNumber": latest_block,
            "latencyMs": int((time.perf_counter() - started) * 1000),
            "error": None,
            "readOnly": True,
        }
    except Exception as exc:  # pragma: no cover - live network dependent
        return {
            "id": target.id,
            "name": target.name,
            "status": "degraded",
            "rpc": rpc,
            "chainId": target.chain_id,
            "observedChainId": None,
            "latestBlockNumber": None,
            "latencyMs": int((time.perf_counter() - started) * 1000),
            "error": f"{type(exc).__name__}: {exc}",
            "readOnly": True,
        }


def _probe_http_status(target: ChainTarget, *, timeout_seconds: float) -> dict[str, Any]:
    started = time.perf_counter()
    url = configured_http_status_url(target)
    if not url:
        return _not_probed(target, live=True, include_non_default=True)
    try:
        request = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "0guard-crosschain/0.1"},
        )
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = response.read(4096)
            http_status = int(response.status)
        decoded = json.loads(body.decode("utf-8"))
        body_status = decoded.get("status")
        network_id = decoded.get("network_id")
        ok = 200 <= http_status < 300 and (body_status in (None, 200, "200", "ok", "OK"))
        return {
            "id": target.id,
            "name": target.name,
            "status": "ok" if ok else "degraded",
            "probeType": "http_status",
            "httpStatusUrl": url,
            "httpStatus": http_status,
            "bodyStatus": body_status,
            "networkId": network_id,
            "latencyMs": int((time.perf_counter() - started) * 1000),
            "error": None if ok else "status endpoint did not report ok",
            "readOnly": True,
        }
    except Exception as exc:  # pragma: no cover - live network dependent
        return {
            "id": target.id,
            "name": target.name,
            "status": "degraded",
            "probeType": "http_status",
            "httpStatusUrl": url,
            "httpStatus": None,
            "bodyStatus": None,
            "networkId": None,
            "latencyMs": int((time.perf_counter() - started) * 1000),
            "error": f"{type(exc).__name__}: {exc}",
            "readOnly": True,
        }


def _rpc_int(rpc: str, method: str, *, timeout_seconds: float) -> int:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": []}).encode()
    request = urllib.request.Request(
        rpc,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "0guard-crosschain/0.1"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        body = response.read(4096)
    decoded = json.loads(body.decode("utf-8"))
    if "error" in decoded:
        raise RuntimeError(decoded["error"])
    result = decoded.get("result")
    if not isinstance(result, str):
        raise RuntimeError(f"{method} returned no hex result")
    return int(result, 16)


def _not_probed(target: ChainTarget, *, live: bool, include_non_default: bool) -> dict[str, Any]:
    if not target.evm_compatible:
        if configured_http_status_url(target) and not live:
            status = "not_checked"
            reason = "Live HTTP status probing disabled."
        elif configured_http_status_url(target) and not include_non_default:
            status = "not_default_probed"
            reason = "Set include_non_default=1 to probe configured non-default targets."
        else:
            status = "catalog_only_non_evm"
            reason = "Target is not an EVM RPC endpoint; use its native/API/DA proof path."
    elif not live:
        status = "not_checked"
        reason = "Live RPC probing disabled."
    elif not configured_rpc(target):
        status = "env_rpc_required"
        reason = f"Set {target.rpc_env} to enable a read-only probe." if target.rpc_env else "No RPC configured."
    elif not target.probe_default and not include_non_default:
        status = "not_default_probed"
        reason = "Set include_non_default=1 to probe configured non-default targets."
    else:
        status = "not_checked"
        reason = "No probe attempted."
    return {
        "id": target.id,
        "name": target.name,
        "status": status,
        "rpc": configured_rpc(target),
        "httpStatusUrl": configured_http_status_url(target),
        "chainId": target.chain_id,
        "observedChainId": None,
        "latestBlockNumber": None,
        "latencyMs": None,
        "error": reason,
        "readOnly": True,
    }


def _payment_readiness() -> dict[str, Any]:
    supported = [
        target.id
        for target in CHAIN_TARGETS
        if target.x402_posture == "supported_default_network_for_x402_payments"
    ]
    custom = [
        target.id
        for target in CHAIN_TARGETS
        if target.x402_posture.startswith("custom_facilitator_required")
    ]
    return {
        "x402Ready": False,
        "liveSettlementAllowed": False,
        "defaultSupportedNetworkIds": supported,
        "customFacilitatorCandidateIds": custom,
        "payToConfigured": bool(os.getenv("X402_PAY_TO_ADDRESS")),
        "middlewareActive": False,
        "note": (
            "This repo exposes payment posture only. Live x402 middleware should be enabled "
            "after pay-to address, facilitator, auth, and replay controls are reviewed."
        ),
    }


def _agent_readiness() -> dict[str, Any]:
    return {
        "virtualsBaseAgentPrepared": True,
        "virtualsLiveAgentLaunched": False,
        "operatorLaunchRequired": True,
        "baseRpcConfigured": bool(configured_rpc(_target_by_id("base_mainnet"))),
        "externalSideEffectsAllowed": False,
    }


def _x402_posture() -> dict[str, Any]:
    return {
        "mode": "prepared_not_live",
        "recommendedFirstSettlementNetworks": ["base_mainnet", "polygon_pos", "arbitrum_one"],
        "proofAnchorNetwork": "0g_mainnet",
        "sellableArtifacts": [
            "derived_threat_receipt_packets",
            "source_cited_detector_gap_reports",
            "cross_chain_agent_safety_readiness",
        ],
        "rightsEnvelope": {
            "paymentIsNotPermission": True,
            "rawPayloadResaleAllowed": False,
            "outputPolicy": "derived_metadata_links_hashes_receipts_and_defensive_analysis",
        },
        "minimumControlsBeforeLive": [
            "bind payment requirements to route, chain, token, recipient, amount, and content hash",
            "dedupe nonces and replay windows before returning paid artifacts",
            "redact sensitive request metadata before any facilitator call",
            "settle only derived artifacts whose source licenses permit redistribution",
            "anchor payment decision receipts to 0G without exposing private payloads",
        ],
        "claimsToAvoid": [
            "Do not claim x402 settlement is live until middleware verifies and settles a real payment.",
            "Do not claim 0G-native x402 without a configured facilitator for eip155:16661.",
            "Do not resell raw upstream OSINT payloads behind payment.",
        ],
    }


def _readable_receipt_plan() -> dict[str, Any]:
    return {
        "currentContract": "PolicyReceiptAnchor",
        "currentReadableFields": ["decision", "severity", "agentId", "timestamp", "submitter"],
        "preparedNextContract": "contracts/PolicyReceiptAnchorV2.sol",
        "recommendedEventFields": [
            "receiptHash",
            "decision",
            "severity",
            "agentId",
            "policyVersion",
            "datasetFingerprint",
            "evidenceRoot",
            "storageRoot",
            "shortMemo",
            "sourceIds",
        ],
        "memoExample": "Blocked unlimited ERC20 approval before signer",
        "why": (
            "Keep explorer logs human-readable while storing full receipt JSON in Storage or "
            "off-chain artifacts addressed by hashes."
        ),
    }


def _next_operator_actions() -> list[dict[str, str]]:
    return [
        {
            "id": "virtuals_launch",
            "owner": "operator",
            "action": "Review and explicitly approve any Virtuals/Base agent launch or token action.",
        },
        {
            "id": "x402_pay_to",
            "owner": "operator",
            "action": "Configure X402_PAY_TO_ADDRESS and facilitator choice before enabling middleware.",
        },
        {
            "id": "non_default_rpcs",
            "owner": "operator",
            "action": "Add MONAD_RPC_URL or CELESTIA_RPC_URL only if readback from official/provider docs is desired.",
        },
        {
            "id": "protocol_config_inputs",
            "owner": "operator",
            "action": "Provide target CCIP, LayerZero, or Wormhole contract/config addresses before turning catalog guardrails into live config inspections.",
        },
    ]


def _target_by_id(target_id: str) -> ChainTarget:
    for target in CHAIN_TARGETS:
        if target.id == target_id:
            return target
    raise KeyError(target_id)


def _crosschain_safety(*, live: bool) -> dict[str, Any]:
    return {
        "readOnly": True,
        "liveRpcProbes": live,
        "rawPayloadsReturned": False,
        "privateKeyRequired": False,
        "transactionSigningEnabled": False,
        "broadcastingEnabled": False,
        "bridgingEnabled": False,
        "swappingEnabled": False,
        "moneyMovementEnabled": False,
        "externalAgentLaunchEnabled": False,
        "tradingEnabled": False,
        "exchangeApiKeysEnabled": False,
        "stakingEnabled": False,
        "withdrawalsEnabled": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
