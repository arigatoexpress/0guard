"""Plain-English product brief for the current 0guard stack."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from guard0.incident_data import detection_coverage, incident_summary

PRODUCT_BRIEF_SCHEMA = "0guard.product_brief.v1"


def product_brief() -> dict[str, Any]:
    """Return a compact, honest map of what 0guard is and what is live."""
    summary = incident_summary()
    coverage = detection_coverage()
    proof_routes = [
        "/api/healthz",
        "/api/readyz",
        "/api/product/brief",
        "/api/native-preflight",
        "/api/threat-case-file",
        "/api/reputation/probe",
        "/api/reputation/connectors",
        "/api/reputation/adapters",
        "/api/reputation/adapters/normalize",
        "/api/reputation/shadow-cache",
        "/api/wallet/alert-preview",
        "/api/telegram/wallet-alert-preview",
        "/api/telegram/miniapp/preview",
        "/api/experiments/frontier",
        "/api/experiments/run",
        "/api/developer-kit",
        "/api/0g/proof-ladder",
        "/api/0g/private-computer",
        "/api/0g/peer-protection",
        "/api/0g/pi-mesh",
        "/api/peer/outreach-preview",
    ]
    return {
        "schema": PRODUCT_BRIEF_SCHEMA,
        "generatedAt": _now(),
        "name": "0guard",
        "socialPostingEnabled": False,
        "proofRoutes": proof_routes,
        "oneLiner": (
            "0guard is a pre-wallet firewall for AI agents: it checks intent, "
            "calldata, domain/reputation context, and exploit intelligence before "
            "any signer is asked to act."
        ),
        "plainEnglish": [
            "An AI agent wants to do something with a wallet.",
            "0guard reads the request before a wallet prompt appears.",
            "Safe read-only actions can continue.",
            "Risky signing, sweep, bridge, payment, exchange, or phishing-shaped actions are denied or sent to review.",
            "Every verdict can produce a receipt that is ready for 0G proof workflows.",
        ],
        "builtSystems": _built_systems(summary, coverage),
        "liveProof": _live_proof(summary, coverage),
        "currentStrengths": [
            "Clear wedge: protect the moment before wallet custody, not after a signature prompt appears.",
            "A composed threat case file turns one risky agent action into judge/operator-readable evidence.",
            "A frontier experiment lab ranks the next integrations while proving no live side effects occurred.",
            "A no-network adapter normalizer turns PhishDestroy, CryptoScamDB, Forta, GoPlus, and Chainabuse-shaped payloads into derived evidence.",
            "A derived reputation shadow cache composes multiple reviewed feeds into one reusable alert snapshot without live fetches or raw resale.",
            "0G Private Computer gives ZeroGuard a credible path to sealed AI explanations without making model output the policy authority.",
            "Peer-protection drafts turn node telemetry into useful, opt-in help for other operators instead of unsolicited spam.",
            "Raspberry Pis can become cheap edge sentinels for node health, alert dedupe, and proof-cache work while the Windows host does heavy 0G runtime work.",
            "Real source-linked incident data and detector coverage instead of mock security claims.",
            "A live Telegram Mini App surface that remains preview-only and no-send.",
            "Portable developer-kit routes that other wallets, agents, Mini Apps, CI jobs, and dWallet flows can call.",
            "Rights-aware OSINT posture: external feeds become derived signals, not raw data resale.",
        ],
        "honestLimits": [
            "0G Storage upload/readback and 0G Compute inference are prepared as product lanes, not silently enabled from the workbench.",
            "PhishDestroy, CryptoScamDB, Forta, GoPlus, Chainabuse, TONAPI, and simulation feed live fetches are activation-ready but disabled until keys and terms are reviewed.",
            "The PhishDestroy/CryptoScamDB/Forta/GoPlus/Chainabuse normalizer is live for caller-provided payloads and returns only derived evidence.",
            "The reputation shadow cache is derived from caller-supplied reviewed payloads; it is not a live autonomous feed fetcher yet.",
            "The Telegram bot and Mini App are live, but outbound Telegram sends are intentionally disabled.",
            "X, LinkedIn, Substack, wallet signing, x402 settlement, bridge/swap actions, and exchange actions require separate operator-controlled paths.",
            "0G Private Computer calls are documented and API-compatible, but no paid inference call is made unless an operator configures a key and prompt-minimization policy.",
            "Peer outreach is a draft/outbox system until opt-in contacts, rate limits, and operator-approved sender infrastructure are configured.",
            "Pi mesh work is edge-sentinel compute, not validator, miner, or 35B-model inference work.",
        ],
        "nextBestBuilds": [
            {
                "rank": 1,
                "id": "reputation_connector_activation",
                "why": "Highest practical value for wallet/domain safety and Telegram alerts.",
                "ship": "Enable one external connector worker first, probably PhishDestroy or CryptoScamDB, and route it through the existing derived-output normalizer.",
            },
            {
                "rank": 2,
                "id": "threat_case_file_productization",
                "why": "Best demo and operator comprehension lift because it stitches every existing proof surface together.",
                "ship": "Use /api/threat-case-file as the default judge/operator drill for risky agent intents.",
            },
            {
                "rank": 3,
                "id": "0g_storage_receipt_readback",
                "why": "Makes the 0G story more than a chain anchor by proving receipt payload availability.",
                "ship": "Operator-approved upload/readback CLI plus public-safe receipt hash display.",
            },
            {
                "rank": 4,
                "id": "evm_simulation_adapter",
                "why": "State deltas make approvals, swaps, upgrades, and bridge messages easier for normal users to understand.",
                "ship": "Tenderly or BlockSec adapter returning derived asset-delta summaries only.",
            },
            {
                "rank": 5,
                "id": "telegram_ton_risk_passport",
                "why": "Telegram users are the natural first audience; TON should be native rather than bridged.",
                "ship": "TON Center or TONAPI read-only account/Jetton context feeding the Mini App passport.",
            },
            {
                "rank": 6,
                "id": "peer_protection_and_pi_sentinels",
                "why": "Turns our live 0G node operation into a differentiated product loop for other operators.",
                "ship": "Run Pi sentinels, draft peer bulletins, and keep direct outreach behind opt-in review.",
            },
        ],
        "socialPositioning": {
            "xThreadFile": "content/0guard_current_update_x_thread.json",
            "substackDraftFile": "content/substack_0guard_launch_draft.md",
            "recommendedTone": "plain-spoken, proof-first, not hype-first",
            "avoidClaims": [
                "Do not claim autonomous live blocking of all wallet attacks.",
                "Do not claim raw paid-feed ownership.",
                "Do not imply 0guard signs, broadcasts, bridges, swaps, or sends alerts in production by itself.",
            ],
        },
        "safety": _safety(),
    }


def _built_systems(summary: dict[str, Any], coverage: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "id": "intent_firewall",
            "label": "Intent firewall",
            "status": "live",
            "whatItDoes": "Returns allow, review, or deny before wallet access.",
            "proofRoutes": ["/api/evaluate", "/api/native-preflight"],
        },
        {
            "id": "incident_intelligence",
            "label": "Incident-derived exploit intelligence",
            "status": "live",
            "whatItDoes": "Uses source-linked incidents and detector signatures to catch known exploit shapes.",
            "proof": {
                "incidentCount": (summary.get("meta") or {}).get("total_incidents")
                or coverage.get("incidentCount"),
                "coverageRatio": coverage.get("coverageRatio"),
                "coveredCount": coverage.get("coveredCount"),
            },
            "proofRoutes": [
                "/api/data/summary",
                "/api/data/provenance",
                "/api/data/signature-map",
            ],
        },
        {
            "id": "reputation_probe",
            "label": "Reputation probe",
            "status": "live_local_derived",
            "whatItDoes": "Scores domains, counterparties, labels, source evidence, and intent context without returning raw source payloads.",
            "proofRoutes": [
                "/api/reputation/probe",
                "/api/reputation/connectors",
                "/api/reputation/adapters",
                "/api/reputation/adapters/normalize",
                "/api/reputation/shadow-cache",
            ],
        },
        {
            "id": "threat_case_file",
            "label": "Threat case file",
            "status": "live_preview_no_side_effects",
            "whatItDoes": "Composes policy, signatures, reputation, wallet alert gates, provenance, and 0G-ready receipts into one proof dossier.",
            "proofRoutes": ["/api/threat-case-file"],
        },
        {
            "id": "frontier_experiment_lab",
            "label": "Frontier experiment lab",
            "status": "live_read_only_experiment_backlog",
            "whatItDoes": "Ranks and previews 0G Storage/Compute, reputation, simulation, TON, and Mira activation paths without live side effects.",
            "proofRoutes": ["/api/experiments/frontier", "/api/experiments/run"],
        },
        {
            "id": "telegram_mini_app",
            "label": "Telegram Mini App",
            "status": "live_preview_no_send",
            "whatItDoes": "Shows mobile wallet-alert and Mira explanations with server-side Telegram initData validation support.",
            "proofRoutes": ["/telegram", "/api/telegram/miniapp/preview"],
        },
        {
            "id": "0g_receipts",
            "label": "0G-ready receipts",
            "status": "mainnet_anchor_plus_storage_ready_payloads",
            "whatItDoes": "Produces deterministic receipts for policy and threat decisions, with public mainnet proof already recorded.",
            "proofRoutes": [
                "/api/0g/status",
                "/api/0g/receipt",
                "/api/0g/proof-ladder",
                "/api/hackathon/threat-passport",
            ],
        },
        {
            "id": "0g_private_computer",
            "label": "0G Private Computer integration",
            "status": "manifest_live_no_paid_calls",
            "whatItDoes": "Documents how 0GM-1.0 can produce sealed, OpenAI-compatible explanations over ZeroGuard risk packets.",
            "proofRoutes": ["/api/0g/private-computer"],
        },
        {
            "id": "peer_protection_outbox",
            "label": "Peer-protection outbox",
            "status": "preview_no_send",
            "whatItDoes": "Builds opt-in peer help drafts and onchain message hashes without sending or broadcasting.",
            "proofRoutes": ["/api/0g/peer-protection", "/api/peer/outreach-preview"],
        },
        {
            "id": "pi_edge_mesh",
            "label": "Raspberry Pi edge mesh",
            "status": "rvpi_a_reachable_plan_live",
            "whatItDoes": "Assigns Pis to node sentinel, proof-cache, and dedupe work without keys or signing.",
            "proofRoutes": ["/api/0g/pi-mesh"],
        },
        {
            "id": "developer_kit",
            "label": "Developer kit",
            "status": "live",
            "whatItDoes": "Exposes SDK/CI/wallet/Mini App/dWallet recipes for calling 0guard before any signer.",
            "proofRoutes": ["/api/developer-kit"],
        },
        {
            "id": "cross_ecosystem_guardrails",
            "label": "Cross-ecosystem guardrails",
            "status": "live_read_only_catalog",
            "whatItDoes": "Models x402, Virtuals/Base, Lighter, CCIP, LayerZero, Wormhole, Celestia, TON, Solana, Hyperliquid, Ika, and Ikavery as read-only policy surfaces.",
            "proofRoutes": [
                "/api/integrations/cross-chain",
                "/api/integrations/external-guardrails",
                "/api/integrations/ika",
            ],
        },
    ]


def _live_proof(summary: dict[str, Any], coverage: dict[str, Any]) -> dict[str, Any]:
    return {
        "miniApp": "https://guard0-miniapp-s77j6bxyra-uc.a.run.app/telegram",
        "telegramBot": "https://t.me/Raris0guardBot",
        "proofHub": "https://arigatoexpress.github.io/0guard/hackathon-0g/",
        "demoVideo": "https://arigatoexpress.github.io/0guard/hackathon-0g/assets/0guard-hackquest-demo-final.mp4",
        "repo": "https://github.com/arigatoexpress/0guard",
        "productionHealth": "/api/healthz",
        "incidentCount": (summary.get("meta") or {}).get("total_incidents")
        or coverage.get("incidentCount"),
        "detectorCoverageRatio": coverage.get("coverageRatio"),
        "readOnlyDefault": True,
    }


def _safety() -> dict[str, bool]:
    return {
        "readOnly": True,
        "telegramSendsEnabled": False,
        "socialPostingEnabled": False,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "paymentSettlementEnabled": False,
        "exchangeOrdersEnabled": False,
        "bridgingEnabled": False,
        "rawPayloadsReturned": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
