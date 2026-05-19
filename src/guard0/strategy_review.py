"""Critical product strategy review for the current ZeroGuard stack."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from guard0.production_gaps import build_production_gap_matrix
from guard0.readiness import production_readiness

STRATEGY_REVIEW_SCHEMA = "0guard.strategy_review.v1"


def build_strategy_review() -> dict[str, Any]:
    """Return an opinionated, no-side-effect critique and next-build sequence."""

    readiness = production_readiness()
    gap_matrix = build_production_gap_matrix()
    gaps_by_id = {gap["id"]: gap for gap in gap_matrix.get("gaps", [])}
    storage_gap = gaps_by_id.get("node.0g_storage_soak", {})
    storage_evidence = storage_gap.get("currentEvidence") or {}

    return {
        "schema": STRATEGY_REVIEW_SCHEMA,
        "generatedAt": _now(),
        "mode": "critical_strategy_review_no_side_effects",
        "executiveTake": (
            "ZeroGuard should narrow from a broad 0G demo surface into a pre-wallet "
            "risk receipt network: deterministic policy first, source-linked evidence "
            "second, 0G proof and paid delivery third."
        ),
        "whatIWouldDoDifferently": _what_i_would_do_differently(),
        "productSpine": _product_spine(),
        "debugFindings": {
            "productionHealthy": readiness.get("productionHealthy"),
            "hardGates": readiness.get("hardGates") or [],
            "topProductionGates": gap_matrix.get("topHardGates", [])[:6],
            "storageNode": {
                "status": storage_evidence.get("status"),
                "blockedBy": storage_evidence.get("blockedBy") or [],
                "connectedPeers": storage_evidence.get("connectedPeers"),
                "logSyncHeight": storage_evidence.get("logSyncHeight"),
                "activeMinerBalanceOg": storage_evidence.get("activeMinerBalanceOg"),
                "hundredOgTransferSent": storage_evidence.get("hundredOgTransferSent"),
            },
            "claimPosture": (
                "Strong as a proof-backed, read-only defensive intelligence product; "
                "not yet ready to claim live paid settlement, autonomous alerting, "
                "0G Storage availability, or node revenue."
            ),
        },
        "nextBuildSequence": _next_build_sequence(),
        "niceToHave": _nice_to_have(),
        "killOrDefer": _kill_or_defer(),
        "decisionRules": [
            "If a feature cannot produce a receipt, source id, or readiness check, defer it.",
            "If a workflow needs a private key, live send, or payment settlement, keep it out of the workbench.",
            "If a claim depends on current network state, expose a live readback instead of writing marketing copy.",
            "If a model produces text, treat it as explanation; deterministic policy remains the authority.",
            "If a dataset cannot be backfilled or cited, it is not a production moat yet.",
        ],
        "judgeNarrative": {
            "shortVersion": (
                "ZeroGuard prevents unsafe agentic wallet actions before the signer sees them, "
                "turns the decision into a source-linked receipt, and uses 0G for public proof, "
                "storage, compute, and operator telemetry."
            ),
            "differentiator": (
                "The product is honest about live boundaries: one real mainnet anchor, real "
                "incident/eval data, real node telemetry, and gated previews for every risky action."
            ),
            "demoPath": [
                "Run a risky wallet intent through /api/evaluate.",
                "Open /api/threat-case-file for the composed evidence packet.",
                "Verify the 0G mainnet receipt and production gap matrix.",
                "Show the x402 dry-run, 0G Storage manifest, Private Computer smoke contract, and Pi mesh as promotion gates.",
            ],
        },
        "safety": _safety(),
    }


def _what_i_would_do_differently() -> list[dict[str, Any]]:
    return [
        {
            "id": "narrow_the_claim",
            "critique": "The repo has many impressive surfaces, but the product risks sounding like a pile of integrations.",
            "change": "Lead with one sentence: pre-wallet risk receipts for AI agents.",
            "shipNext": "Make every public page and demo flow start from a wallet/agent action, not from the integration catalog.",
        },
        {
            "id": "one_paid_route_first",
            "critique": "x402, 0G Storage, and Private Computer are all prepared, but none should be half-live.",
            "change": "Pick one derived wallet-preflight route as the first paid SKU.",
            "shipNext": "Freeze response schema, unpaid 402, paid-fixture, refund language, and spend caps before any facilitator call.",
        },
        {
            "id": "data_moat_before_more_adapters",
            "critique": "More source names do not create a moat unless the data is historical, queryable, and labeled.",
            "change": "Prioritize append-only feature runs and eval cases over adding connector logos.",
            "shipNext": "Create a tiny historical feature store with run ids, source manifests, rights envelopes, and hashes.",
        },
        {
            "id": "model_as_narrator_not_judge",
            "critique": "0GM/Private Computer is compelling, but model output must not become policy authority.",
            "change": "Use 0GM for sealed summaries, dedupe, and user-language rewrites over deterministic packets.",
            "shipNext": "Run one budget-capped smoke on a redacted verdict packet, store only metadata and advisory text.",
        },
        {
            "id": "telegram_as_operator_console",
            "critique": "Push alerts too early create spam risk and trust debt.",
            "change": "Use Telegram first as an opt-in pull console with quiet status and previews.",
            "shipNext": "Configure bot identity and webhook proof, then keep sends behind a separate approved worker.",
        },
        {
            "id": "node_ops_as_proof_not_revenue",
            "critique": "The storage node is credibility, telemetry, and dogfooding; near-term yield claims are weak.",
            "change": "Sell node-watch intelligence and proof receipts, not speculative monthly 0G revenue.",
            "shipNext": "Keep soaking until peer count clears, then publish a node-health sample packet.",
        },
        {
            "id": "separate_demo_fixtures_from_claims",
            "critique": "Fixtures are useful, but they make the product feel vibe-coded when mixed with live data.",
            "change": "Label fixture-only payloads at the route and UI level.",
            "shipNext": "Graduate the best fixtures into eval cases; keep customer-facing intelligence routes fixture-free by default.",
        },
    ]


def _product_spine() -> list[dict[str, Any]]:
    return [
        {
            "layer": "decision",
            "name": "Pre-wallet policy engine",
            "mustBeTrue": "Every risky action gets allow/review/deny before a signer or wallet prompt.",
            "routes": ["/api/evaluate", "/api/native-preflight"],
        },
        {
            "layer": "evidence",
            "name": "Threat case file",
            "mustBeTrue": "A normal operator can see why a verdict happened without raw paid payloads.",
            "routes": ["/api/threat-case-file", "/api/reputation/shadow-cache"],
        },
        {
            "layer": "proof",
            "name": "0G receipt and storage trail",
            "mustBeTrue": "Important verdicts have hashes, public proof, and eventually storage readback.",
            "routes": ["/api/0g/receipt", "/api/0g/proof-ladder", "/api/0g/storage-upload/manifest"],
        },
        {
            "layer": "distribution",
            "name": "Opt-in Telegram and x402 delivery",
            "mustBeTrue": "Users and agents can pull or buy derived intelligence without spam or raw-feed resale.",
            "routes": ["/api/telegram/status", "/api/x402/dry-run/wallet-preflight"],
        },
        {
            "layer": "operations",
            "name": "0G node and Pi sentinel telemetry",
            "mustBeTrue": "Our own infrastructure produces trustworthy readiness and blocker evidence.",
            "routes": ["/api/0g/storage-node/status?snapshot=1", "/api/0g/pi-mesh?snapshot=1"],
        },
    ]


def _next_build_sequence() -> list[dict[str, Any]]:
    return [
        {
            "rank": 1,
            "id": "production_contract_freeze",
            "timebox": "1 day",
            "goal": "Freeze the first customer-readable product contract.",
            "acceptance": [
                "One wallet-preflight response schema is documented and tested.",
                "Fixture-only examples are marked fixture-only.",
                "README points judges to the exact demo path and hard gates.",
            ],
        },
        {
            "rank": 2,
            "id": "historical_feature_store_seed",
            "timebox": "2-3 days",
            "goal": "Turn current incident/eval/reputation artifacts into the first append-only feature store.",
            "acceptance": [
                "JSONL rows include run id, source id, rights class, hash, observed_at, and entity fields.",
                "A query route can filter by source, chain, entity, decision, and time window.",
                "No raw paid feeds or secrets are stored.",
            ],
        },
        {
            "rank": 3,
            "id": "telegram_identity_no_send",
            "timebox": "0.5 day after token is available",
            "goal": "Prove the real bot identity and webhook secret without sending messages.",
            "acceptance": [
                "/api/telegram/status?live=1 reads back getMe for the intended bot.",
                "Opt-in store remains persistent and git-ignored or managed.",
                "Outbound sends stay disabled in readiness.",
            ],
        },
        {
            "rank": 4,
            "id": "0g_storage_readback",
            "timebox": "2 days after operator approval",
            "goal": "Upload the public-safe bundle to 0G Storage and prove download hash equality.",
            "acceptance": [
                "Bundle root, tx/root metadata, and gateway readback hash are saved.",
                "Readback route proves every file hash matches the manifest.",
                "No secrets, raw vendor payloads, or private logs are uploaded.",
            ],
        },
        {
            "rank": 5,
            "id": "private_compute_smoke",
            "timebox": "1 day after Router budget/API key",
            "goal": "Run one budget-capped 0GM smoke on a redacted deterministic verdict packet.",
            "acceptance": [
                "Prompt scrubber rejects secrets and raw payment headers.",
                "The smoke records model id, request hash, budget, and advisory output.",
                "Model text cannot change deterministic verdicts.",
            ],
        },
        {
            "rank": 6,
            "id": "x402_testnet_facilitator",
            "timebox": "2-4 days",
            "goal": "Promote dry-run x402 to a spend-capped testnet route.",
            "acceptance": [
                "Unpaid, malformed, paid-fixture, and testnet-paid paths are covered.",
                "Paid output contains only derived intelligence and receipt metadata.",
                "Refund/support language and rate limits are visible.",
            ],
        },
    ]


def _nice_to_have() -> list[dict[str, str]]:
    return [
        {
            "id": "operator_timeline",
            "value": "A single timeline of incident data, reputation runs, node soak snapshots, and proof receipts.",
        },
        {
            "id": "competitor_comparison_page",
            "value": "A proof-first comparison against wallet simulation, phishing blocklists, and compliance APIs without dunking on them.",
        },
        {
            "id": "risk_receipt_explorer",
            "value": "A searchable local explorer for receipts, source ids, verdicts, and 0G proof links.",
        },
        {
            "id": "pi_node_health_timeseries",
            "value": "Pi-collected storage peer/sync/relay timeseries with anomaly labels for future model evals.",
        },
        {
            "id": "judge_mode",
            "value": "A one-click read-only demo path that hides unfinished surfaces and highlights live proof.",
        },
        {
            "id": "customer_terms_packet",
            "value": "Plain terms explaining defensive analysis, no legal sanctions advice, no raw-feed resale, and no custody.",
        },
    ]


def _kill_or_defer() -> list[dict[str, str]]:
    return [
        {
            "id": "yield_marketing",
            "why": "Rewards are not sufficiently proven; focus on node-watch intelligence until official reward evidence exists.",
        },
        {
            "id": "unsolicited_peer_messages",
            "why": "Peer protection only earns trust if it is opt-in, rate-limited, and reviewable.",
        },
        {
            "id": "more_dashboard_tabs",
            "why": "More panels make the product feel less real unless they attach to the product spine.",
        },
        {
            "id": "live_mainnet_payment_before_testnet",
            "why": "x402 needs schema, support, caps, refund rules, and testnet proof before mainnet settlement.",
        },
        {
            "id": "model_override_language",
            "why": "The model can explain and compress, but deterministic policy must remain the source of truth.",
        },
    ]


def _safety() -> dict[str, bool]:
    return {
        "readOnly": True,
        "networkCalls": False,
        "telegramSendsEnabled": False,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "moneyMovementEnabled": False,
        "paymentSettlementEnabled": False,
        "paidInferenceEnabled": False,
        "rawPayloadsReturned": False,
        "privateKeysReturned": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
