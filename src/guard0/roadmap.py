"""Strategic roadmap and rights-aware data-stream plan for 0guard."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

INTELLIGENCE_STREAM_PLAN_SCHEMA = "0guard.intelligence_stream_plan.v1"
ECOSYSTEM_ROADMAP_SCHEMA = "0guard.ecosystem_roadmap.v1"


def intelligence_stream_plan() -> dict[str, Any]:
    """Return ranked source streams with rights and integration posture."""
    streams = [
        {
            "rank": 1,
            "id": "unified_reputation_adapter",
            "name": "GoPlus + Chainabuse + phishing databases",
            "cost": "free_or_keyed_first_paid_later",
            "sources": [
                "https://docs.gopluslabs.io/",
                "https://docs.chainabuse.com/docs/welcome-to-chainabuse-api",
                "https://cryptoscamdb.org/",
                "https://www.scamsniffer.io/",
                "https://github.com/MetaMask/eth-phishing-detect",
            ],
            "whyItMatters": "Best near-term lift for domain checks, recipient checks, approvals, and Telegram alerts.",
            "integrationShape": (
                "Normalize domain/address/token votes into one risk_probe result consumed by "
                "/api/domain, /api/evaluate, /api/wallet/alert-preview, and Telegram previews."
            ),
            "rightsEnvelope": "Return derived verdicts, source ids, confidence, links, and hashes; do not resell raw feeds.",
            "status": "planned_adapter",
            "buildPhase": "phase_1",
        },
        {
            "rank": 2,
            "id": "forta_attack_labels_digest",
            "name": "Forta attack detector and labelled datasets",
            "cost": "public_labels_plus_possible_subscription",
            "sources": [
                "https://docs.forta.network/en/latest/attack-detector-bot/",
                "https://docs.forta.network/en/latest/api-reference/",
                "https://github.com/forta-network/labelled-datasets",
            ],
            "whyItMatters": "Live exploit-stage labels become emerging-risk digest items before they become hard blockers.",
            "integrationShape": "Digest-only by default; promote to wallet-specific alert only with direct source/detector evidence.",
            "rightsEnvelope": "Respect premium feed terms; preserve attribution and confidence.",
            "status": "registry_seeded",
            "buildPhase": "phase_1",
        },
        {
            "rank": 3,
            "id": "evm_simulation_adapter",
            "name": "Tenderly or BlockSec transaction simulation",
            "cost": "free_tier_or_paid_developer_plan",
            "sources": [
                "https://docs.tenderly.co/",
                "https://docs.blocksec.com/phalcon/phalcon-explorer/simulator",
            ],
            "whyItMatters": "Turns policy from static signatures into state-change previews for approvals and swaps.",
            "integrationShape": "Optional simulate_intent adapter returning asset deltas, approvals, dangerous calls, and source hashes.",
            "rightsEnvelope": "Do not persist or redistribute full traces unless vendor terms allow it.",
            "status": "planned_adapter",
            "buildPhase": "phase_2",
        },
        {
            "rank": 4,
            "id": "ton_telegram_risk_passport",
            "name": "TON Center / TONAPI read-only activity for Telegram wallets",
            "cost": "free_or_affordable_keyed_infra",
            "sources": [
                "https://docs.ton.org/ecosystem/api/toncenter/v3/overview",
                "https://docs.ton.org/v3/guidelines/ton-connect/overview",
                "https://core.telegram.org/bots/blockchain-guidelines",
            ],
            "whyItMatters": "Telegram users need pre-wallet risk explanations inside the same chat surface.",
            "integrationShape": "Read-only account/Jetton/NFT event watcher feeding TON risk passports; no wallet prompts.",
            "rightsEnvelope": "Derived activity features only; no raw indexer dumps.",
            "status": "preview_api_added",
            "buildPhase": "phase_2",
        },
        {
            "rank": 5,
            "id": "solana_read_only_risk",
            "name": "Helius enhanced transactions and webhooks",
            "cost": "free_tier_then_paid_if_usage_grows",
            "sources": [
                "https://www.helius.dev/docs/webhooks",
                "https://www.helius.dev/pricing",
            ],
            "whyItMatters": "Solana coverage is valuable, but it should enter as read-only account/token risk, not a bridge story.",
            "integrationShape": "SPL token and parsed transaction monitor feeding the same alert-quality gate.",
            "rightsEnvelope": "Vendor API terms; derived wallet features and links only.",
            "status": "planned_phase_2",
            "buildPhase": "phase_2",
        },
        {
            "rank": 6,
            "id": "cross_chain_message_monitors",
            "name": "LayerZero Scan and Wormholescan APIs",
            "cost": "public_api",
            "sources": [
                "https://docs.layerzero.network/v2/tools/layerzeroscan/api",
                "https://wormhole.com/docs/products/messaging/guides/wormholescan-api/",
            ],
            "whyItMatters": "0guard can protect cross-chain message configuration without initiating bridge transfers.",
            "integrationShape": "Read message state, DVN config, VAA/transfer status, and flag single-verifier or stuck-message risk.",
            "rightsEnvelope": "Derived message metadata and links only.",
            "status": "catalog_guardrails_exist",
            "buildPhase": "phase_2",
        },
        {
            "rank": 7,
            "id": "hyperliquid_read_only_exposure",
            "name": "Hyperliquid Info/WebSocket API",
            "cost": "official_free_read_api",
            "sources": [
                "https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/info-endpoint",
                "https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/websocket",
            ],
            "whyItMatters": "Useful for exposure/fill/order-context monitoring without touching exchange actions.",
            "integrationShape": "Read-only account exposure and suspicious activity monitor; no exchange endpoint that signs or places orders.",
            "rightsEnvelope": "Market context only; no advice or execution.",
            "status": "planned_phase_3",
            "buildPhase": "phase_3",
        },
        {
            "rank": 8,
            "id": "multi_chain_feature_store",
            "name": "Dune, Allium, or Bitquery",
            "cost": "trial_then_paid_subscription",
            "sources": [
                "https://docs.dune.com/api-reference/overview/introduction",
                "https://www.allium.so/product/allium-developer",
                "https://bitquery.io/products/data-streams",
            ],
            "whyItMatters": "Backfills behavior features across EVM, L2s, Solana, and Hyperliquid without maintaining every indexer.",
            "integrationShape": "Nightly feature store for fan-out, mixer proximity, new-contract interaction, and bridge bursts.",
            "rightsEnvelope": "Paid data terms; sell derived features, not raw query exports.",
            "status": "buy_later_if_needed",
            "buildPhase": "phase_3",
        },
    ]
    return {
        "schema": INTELLIGENCE_STREAM_PLAN_SCHEMA,
        "generatedAt": _now(),
        "streamCount": len(streams),
        "streams": streams,
        "buyFirst": [
            "GoPlus key or plan only after free API limits block the demo.",
            "Chainabuse API if IOC confidence/report counts materially improve alert quality.",
            "Tenderly or BlockSec simulation once reputation adapters are feeding live product flows.",
        ],
        "rightsPolicy": {
            "paymentIsNotPermission": True,
            "rawPayloadResaleAllowed": False,
            "sellableOutput": "derived_risk_scores_source_ids_links_hashes_receipts_and_defensive_summaries",
        },
        "safety": _safety(),
    }


def ecosystem_roadmap() -> dict[str, Any]:
    """Return a no-bridge roadmap for hackathon expansion."""
    phases = [
        {
            "id": "phase_0_current_submission",
            "timeframe": "now",
            "goal": "Win the 0G APAC lane with a proof-heavy pre-wallet firewall.",
            "productionLevelInfra": [
                "0G mainnet deny receipt proof and read-only 0G RPC/status routes",
                "28/28 source-linked incident detector coverage",
                "Telegram Mini App preview with server-side initData validation support",
                "Mira deterministic preview and external-action no-send contracts",
                "Cross-chain guardrail catalog for EVM, Lighter, CCIP, LayerZero, Wormhole, and Celestia",
            ],
            "nextBuild": [
                "Live 0G Storage upload/readback adapter behind operator credentials",
                "Unified reputation adapter for GoPlus, Chainabuse, and phishing databases",
                "TON risk passport inside Telegram",
            ],
            "successMetric": "Judges can reproduce a deny decision, provenance, and 0G proof without trusting screenshots.",
        },
        {
            "id": "phase_1_reputation_firewall",
            "timeframe": "1-2 weeks",
            "goal": "Move from static April 2026 intelligence to constantly updating reputation probes.",
            "productionLevelInfra": [
                "rights-aware source registry",
                "risk_probe adapter contract",
                "quality-gated Telegram alerts",
                "Mira claim preview receipts",
            ],
            "nextBuild": [
                "GoPlus token/address/approval adapter",
                "Chainabuse domain/address enrichment",
                "Forta label digest and promotion queue",
                "Domain guard suffix-hardening and phishing vote aggregation",
            ],
            "successMetric": "Every alert cites source ids, confidence, TTL, and why it did or did not notify.",
        },
        {
            "id": "phase_2_native_ecosystem_expansion",
            "timeframe": "2-5 weeks",
            "goal": "Support ecosystems natively through read-only adapters instead of bridge-dependent flows.",
            "productionLevelInfra": [
                "TON passport API and TON Connect manifest",
                "Abstract/Base/Arbitrum/Polygon EVM read-only probes",
                "LayerZero/Wormhole/CCIP config guardrails",
                "0G receipt anchor as the common proof layer",
            ],
            "nextBuild": [
                "TON Center activity adapter",
                "Tenderly or BlockSec simulation adapter",
                "Abstract Global Wallet risk context",
                "Solana Helius parsed transaction monitor",
                "Ika/Ikavery dWallet signing preflight examples",
            ],
            "successMetric": "0guard can explain risk in each ecosystem's native terms without moving funds between chains.",
        },
        {
            "id": "phase_3_agentic_distribution",
            "timeframe": "1-2 months",
            "goal": "Make 0guard the safety middleware other agent frameworks want to embed.",
            "productionLevelInfra": [
                "Virtuals/Base facilitator manifest",
                "x402 paid-artifact posture without live settlement",
                "API contracts for external guardrail evaluation",
                "public proof packets and no-secret smoke tests",
            ],
            "nextBuild": [
                "AgentKit/Turnkey middleware examples",
                "x402 paid threat-packet quote route",
                "Hyperliquid read-only exposure monitor",
                "Mira external verification adapter after API/token terms are confirmed",
                "MPCKit/OdWS SDK wrappers that require a 0guard receipt before signing",
            ],
            "successMetric": "A wallet or agent developer can call one API before signing and get a receipt-backed verdict.",
        },
    ]
    return {
        "schema": ECOSYSTEM_ROADMAP_SCHEMA,
        "generatedAt": _now(),
        "positioning": {
            "category": "pre-wallet safety layer for autonomous agents",
            "competitiveWedge": (
                "Other 0G projects show agents, markets, receipts, or audits; 0guard owns "
                "the moment before an agent reaches a signer, with exploit-derived denials and 0G receipts."
            ),
            "noBridgePrinciple": (
                "Integrate each ecosystem through native read-only proof, simulation, or reputation adapters; "
                "do not rely on trusted bridges as the product story."
            ),
            "competitiveSnapshot": {
                "checkedAt": "2026-05-15",
                "hackQuestGalleryObservedProjects": 159,
                "observedThemes": [
                    "AI agents",
                    "markets and paid artifacts",
                    "receipt/proof layers",
                    "contract audit copilots",
                    "memory and data availability tools",
                ],
            },
        },
        "phases": phases,
        "safety": _safety(),
    }


def _safety() -> dict[str, Any]:
    return {
        "readOnly": True,
        "walletSignaturesEnabled": False,
        "transactionBroadcastingEnabled": False,
        "bridgingEnabled": False,
        "telegramSendsEnabled": False,
        "moneyMovementEnabled": False,
        "rawPayloadResaleAllowed": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
