"""Production gap matrix and model-training roadmap for ZeroGuard."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from guard0.da_node import DEFAULT_STORAGE_STATUS_PATH, build_storage_node_status
from guard0.historical_feature_store import build_historical_feature_store
from guard0.incident_data import detection_coverage, incident_summary
from guard0.local_inference import (
    build_historical_backfill_plan,
    build_local_inference_mesh,
    build_x402_data_products,
)
from guard0.osint import source_registry_public
from guard0.peer_protection import (
    DEFAULT_PI_MESH_STATUS_PATH,
    build_0g_private_computer_integration,
    build_pi_mesh_plan,
)
from guard0.private_compute_adapter import build_private_compute_smoke_preview
from guard0.readiness import production_readiness
from guard0.reputation_backfill import (
    DEFAULT_REPUTATION_BACKFILL_PATH,
    build_reputation_backfill_status,
)
from guard0.storage_upload_manifest import build_storage_upload_manifest
from guard0.training_data import DEFAULT_INCIDENT_EVAL_PATH
from guard0.wallet_provider_guard import build_wallet_provider_guard
from guard0.x402_guard import build_x402_settlement_policy, build_x402_wallet_preflight_dry_run

PRODUCTION_GAP_MATRIX_SCHEMA = "0guard.production_gap_matrix.v1"
MODEL_TRAINING_ROADMAP_SCHEMA = "0guard.model_training_roadmap.v1"

STATUS_LIVE_REAL_DATA = "live_real_data"
STATUS_LOCAL_ONLY = "local_only"
STATUS_SOURCE_READY_LIVE_PENDING = "source_ready_live_pending"
STATUS_MOCK_FIXTURE_ONLY = "mock_fixture_only"
STATUS_BLOCKED = "blocked_external_dependency"


def build_production_gap_matrix() -> dict[str, Any]:
    """Return the honest local-vs-production gap matrix with no side effects."""

    source_registry = source_registry_public()
    readiness = production_readiness()
    storage = build_storage_node_status(live=False, status_file=DEFAULT_STORAGE_STATUS_PATH)
    pi_mesh = build_pi_mesh_plan(status_file=DEFAULT_PI_MESH_STATUS_PATH)
    reputation_backfill = build_reputation_backfill_status(DEFAULT_REPUTATION_BACKFILL_PATH)
    private_computer = build_0g_private_computer_integration(live=False)
    local_inference = build_local_inference_mesh(live=False)
    backfill = build_historical_backfill_plan()
    historical_feature_store = build_historical_feature_store()
    x402 = build_x402_data_products()
    x402_dry_run = build_x402_wallet_preflight_dry_run()
    x402_policy = build_x402_settlement_policy()
    private_compute_smoke = build_private_compute_smoke_preview()
    storage_upload_manifest = build_storage_upload_manifest()
    wallet_provider_guard = build_wallet_provider_guard(
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
    summary = incident_summary()
    coverage = detection_coverage()
    model_roadmap = build_model_training_roadmap(
        incident_summary_payload=summary,
        detection_coverage_payload=coverage,
        source_registry_payload=source_registry,
        private_computer_payload=private_computer,
        local_inference_payload=local_inference,
    )

    gaps = [
        _gap(
            "data.incident_corpus",
            "Validated incident corpus",
            "data",
            STATUS_LIVE_REAL_DATA,
            {
                "incidentCount": (summary.get("stats") or {}).get("incidentCount"),
                "totalLossUsd": (summary.get("stats") or {}).get("totalLossUsd"),
                "datasetFingerprint": coverage.get("datasetFingerprint"),
                "coverageRatio": coverage.get("coverageRatio"),
            },
            "Keep the curated incident corpus source-linked, fingerprinted, and reproducible.",
            "This is not mock data; the risk is that it is a narrow April 2026 slice unless backfilled.",
            "Backfill 2020-present incident features from public reports, DeFiLlama-style indexes, Rekt, SlowMist, CertiK, BlockSec, Chainalysis public blogs, and reviewed chain-specific postmortems.",
            "ZeroGuard data pipeline",
            1,
            [],
            "Create append-only historical feature runs under a fingerprinted feature store.",
            "Do not mirror raw vendor payloads or claim complete threat coverage from one month of data.",
            [
                "At least 24 months of source-cited incidents are queryable by chain, attack vector, entity, and detector id.",
                "Every record has source ids, source URLs, rights class, canonical hash, and detector/eval labels.",
            ],
            ["/api/data/summary", "/api/data/provenance", "/api/data/detection-coverage"],
        ),
        _gap(
            "data.live_reputation_feeds",
            "Continuous reputation and sanctions feeds",
            "data",
            STATUS_SOURCE_READY_LIVE_PENDING,
            {
                "sourceCount": source_registry.get("sourceCount"),
                "enabledByDefaultCount": source_registry.get("enabledByDefaultCount"),
                "firstOpenFeedStatus": reputation_backfill.get("status"),
                "firstOpenFeedLatestRunExists": reputation_backfill.get("latestRunExists"),
                "firstOpenFeedDerivedEvidenceCount": reputation_backfill.get("derivedEvidenceCount"),
                "firstOpenFeedParsedDomainCount": reputation_backfill.get("parsedDomainCount"),
                "firstOpenFeedHash": reputation_backfill.get("feedHash"),
                "firstOpenFeedPath": reputation_backfill.get("path"),
                "vendorLanes": ["Chainalysis", "TRM", "OFAC", "GoPlus", "Forta", "PhishDestroy"],
            },
            "Production protection needs fresh labels for domains, wallets, contracts, and malicious infrastructure.",
            "A first open-feed derived artifact is present when the backfill status is ready; the remaining risk is supervision and broader source coverage.",
            "Promote one open feed first, then add credentialed TRM/Chainalysis integrations only after terms, retention, and derived-output rules are approved.",
            "ZeroGuard reputation worker",
            1,
            _reputation_backfill_blockers(reputation_backfill),
            _reputation_backfill_next_step(reputation_backfill),
            "Do not store paid raw payloads, bypass upstream terms, or sell feed dumps through x402.",
            [
                "Freshness timestamps are present per source.",
                "Connector failures are visible without breaking deterministic policy verdicts.",
                "Paid/vendor fields are reduced to allowed derived labels before reaching public or paid routes.",
            ],
            [
                "/api/osint/sources",
                "/api/osint/readiness",
                "/api/reputation/connectors/live",
                "/api/reputation/backfill/status",
            ],
        ),
        _gap(
            "data.historical_feature_store",
            "Historical feature store",
            "data",
            STATUS_SOURCE_READY_LIVE_PENDING,
            {
                "currentPlan": backfill.get("schema"),
                "nearTermStorage": (backfill.get("storage") or {}).get("nearTerm"),
                "scalePath": (backfill.get("storage") or {}).get("scalePath"),
                "featureStoreSchema": historical_feature_store.get("schema"),
                "featureCount": historical_feature_store.get("featureCount"),
                "featureCountsByType": historical_feature_store.get("featureCountsByType"),
                "featureStoreReceiptHash": (
                    historical_feature_store.get("featureStoreReceipt") or {}
                ).get("hash"),
                "defaultJsonlPath": (
                    historical_feature_store.get("storage") or {}
                ).get("defaultJsonlPath"),
            },
            "The product becomes valuable when it can answer what changed over time, not just what is true now.",
            "A seed feature-store API and JSONL export now compose current curated/local artifacts; the wider historical backfill and query index are still pending.",
            "Expand the append-only JSONL seed into DuckDB or SQLite tables with run ids, source manifests, hashes, and rights envelopes.",
            "ZeroGuard data pipeline",
            1,
            _historical_feature_store_blockers(historical_feature_store),
            "Schedule the seed feature-store export and expand the incident/reputation backfill beyond the April 2026 slice.",
            "Do not backfill private chats, private keys, payment headers, or raw paid feeds.",
            [
                "Backfill runs are reproducible from manifests.",
                "Queries can filter by time window, source id, chain, entity, attack vector, and detector id.",
                "Each output row has a rights class and raw-resale flag.",
            ],
            ["/api/data/backfill-plan", "/api/data/historical-feature-store"],
        ),
        _gap(
            "onchain.mainnet_anchor",
            "0G mainnet receipt anchor",
            "onchain",
            STATUS_LIVE_REAL_DATA,
            _mainnet_proof_evidence(readiness),
            "The public proof path needs one real onchain receipt to show this is more than a local simulation.",
            "No mock risk on the existing anchor; the remaining risk is limited coverage because only one deny receipt is anchored.",
            "Add a controlled anchor queue for selected reviewed receipts, with signer custody outside the workbench.",
            "ZeroGuard operator",
            2,
            ["signer_custody_runbook", "receipt_anchor_queue"],
            "Keep verifier readback live and add a no-key anchor manifest for the next receipt before signing anything.",
            "Do not put private keys in the repo or browser workbench.",
            [
                "Verifier returns the deployed contract, timestamp, emitter, and event status for selected receipt hashes.",
                "Anchor queue has per-receipt human approval and rollback notes.",
            ],
            ["/api/0g/receipt", "/api/0g/proof-ladder", "/api/readyz"],
        ),
        _gap(
            "onchain.0g_storage_upload_readback",
            "0G Storage upload and readback",
            "onchain",
            STATUS_SOURCE_READY_LIVE_PENDING,
            {
                "current": "storage_ready_root_hashes_only",
                "officialSdkPath": "0G Storage SDK supports upload/download and proof verification.",
                "manifestSchema": storage_upload_manifest.get("schema"),
                "bundleFileCount": (storage_upload_manifest.get("bundle") or {}).get("fileCount"),
                "bundleRoot": (storage_upload_manifest.get("bundle") or {}).get("bundleRoot"),
                "localReadbackAllMatched": (
                    storage_upload_manifest.get("readbackVerifier") or {}
                ).get("allMatched"),
                "liveUploadPerformed": (storage_upload_manifest.get("safety") or {}).get(
                    "liveStorageUpload"
                ),
            },
            "Storage is how threat packets become durable data products instead of local API responses.",
            "The app now prepares a public-safe bundle manifest and local hash readback; it still does not upload or read back from 0G Storage by default.",
            "Use the 0G TypeScript or Go SDK to upload public-safe derived bundles, save roots, and verify downloads before public claims.",
            "ZeroGuard storage adapter",
            1,
            ["storage_sdk_live_adapter", "operator_signer", "upload_budget", "gateway_readback"],
            "Use `/api/0g/storage-upload/manifest` to review the public-safe bundle before a live SDK upload/readback.",
            "Do not upload secrets, raw paid feeds, or private operational logs.",
            [
                "A public-safe bundle uploads successfully.",
                "Root hash, tx hash, source manifest hash, and download proof are stored in a proof route.",
                "A readback test verifies content hash equality.",
            ],
            ["/api/evaluate", "/api/0g/proof-ladder", "/api/0g/storage-upload/manifest"],
        ),
        _gap(
            "onchain.x402_settlement",
            "x402 paid data routes",
            "onchain",
            STATUS_SOURCE_READY_LIVE_PENDING,
            {
                "current": (x402.get("protocolPosture") or {}).get("initialSettlement"),
                "productCount": len(x402.get("products") or []),
                "dryRunSchema": x402_dry_run.get("schema"),
                "dryRunStatus": x402_dry_run.get("status"),
                "dryRunHttpStatus": x402_dry_run.get("httpStatus"),
                "settlementPolicySchema": x402_policy.get("schema"),
                "spendCapsConfigured": bool(x402_policy.get("spendCaps")),
                "termsConfigured": bool(x402_policy.get("terms")),
                "payToConfigured": (
                    x402_policy.get("paymentRequirement") or {}
                ).get("payToConfigured"),
                "settlementEnabled": (x402_dry_run.get("safety") or {}).get(
                    "x402SettlementEnabled"
                ),
            },
            "x402 turns ZeroGuard from a demo into a machine-payable defensive intelligence API.",
            "The product manifest, dry-run HTTP-402 route, caps, and terms are real, but pay-to/facilitator readback and settlement remain disabled.",
            "Start with dry-run 402 metadata, add testnet facilitator coverage, then enable one low-cost derived route with caps.",
            "ZeroGuard payment/API lane",
            2,
            _x402_settlement_blockers(x402_policy),
            "Wire the dry-run route to the Base Sepolia x402.org facilitator only after the pay-to address is reviewed.",
            "Do not enable mainnet payment settlement before route schemas, refund policy, and rate limits are fixed.",
            [
                "Protected route has contract tests for unpaid, paid-fixture, and malformed payment states.",
                "Paid response contains only derived analysis, source ids, hashes, and receipt metadata.",
            ],
            [
                "/api/x402/data-products",
                "/api/x402/dry-run/wallet-preflight",
                "/api/x402/settlement-policy",
            ],
        ),
        _gap(
            "wallet.provider_guard",
            "EIP-1193 wallet-provider guard",
            "wallet",
            STATUS_SOURCE_READY_LIVE_PENDING,
            {
                "schema": wallet_provider_guard.get("schema"),
                "mode": wallet_provider_guard.get("mode"),
                "demoMethod": wallet_provider_guard.get("providerMethod"),
                "demoDecision": wallet_provider_guard.get("decision"),
                "demoAction": (wallet_provider_guard.get("enforcement") or {}).get("action"),
                "providerCallAllowed": (
                    wallet_provider_guard.get("enforcement") or {}
                ).get("providerCallAllowed"),
                "walletPromptBlocked": (
                    wallet_provider_guard.get("enforcement") or {}
                ).get("walletPromptBlocked"),
                "providerForwardingPerformedBy0guard": (
                    wallet_provider_guard.get("safety") or {}
                ).get("providerForwardingPerformedBy0guard"),
                "rawParamsReturned": (
                    wallet_provider_guard.get("safety") or {}
                ).get("rawParamsReturned"),
                "sdkExample": "examples/wallet_provider_guard/providerGuard.ts",
            },
            "Production wallet protection needs a guard in front of real EIP-1193 provider requests before wallet popups appear.",
            "The API, workbench control, and SDK wrapper are implemented locally; they do not protect external users until deployed and embedded in a dapp or extension flow.",
            "Deploy the route, wrap one MetaMask-compatible provider surface with the TypeScript helper, and prove deny/review requests stop before `provider.request`.",
            "ZeroGuard wallet integration lane",
            1,
            ["hosted_route_deploy", "dapp_provider_integration", "production_review_ui"],
            "Embed `examples/wallet_provider_guard/providerGuard.ts` in one demo dapp and verify read-only requests pass while signing/broadcast requests block before the wallet prompt.",
            "Do not ask for private keys, forward denied requests, auto-broadcast transactions, or treat 0guard as wallet custody.",
            [
                "Hosted `/api/wallet/provider-guard` returns the same schema and safety flags as local tests.",
                "The wrapper only forwards allow verdicts to the provider.",
                "Review and deny verdicts show a user-readable receipt before any wallet popup.",
                "Raw params, secrets, signatures, and payment headers are never returned by the guard route.",
            ],
            [
                "/api/wallet/provider-guard",
                "/api/native-preflight",
                "examples/wallet_provider_guard/providerGuard.ts",
            ],
        ),
        _gap(
            "infra.hosting_and_secrets",
            "Hosted production runtime and secret posture",
            "infrastructure",
            STATUS_LOCAL_ONLY,
            {
                "currentReadiness": readiness.get("readiness"),
                "telegramStoreMode": _readiness_check_detail(readiness, "telegram_state_store").get("storeMode"),
                "currentLocalServer": "http://127.0.0.1:8109",
            },
            "Production needs stable hosting, managed secret injection, managed persistence, health checks, and rollback.",
            "The current service can be production-ready locally, but local JSON and shell env state do not survive real traffic cleanly.",
            "Use Cloud Run or equivalent with Secret Manager, managed Firestore/Cloud SQL/SQLite volume, readiness probes, and deploy rollback notes.",
            "ZeroGuard platform lane",
            1,
            ["managed_secret_store", "managed_opt_in_store", "deployment_pipeline"],
            "Promote the app with no external sends enabled and prove `/api/readyz` from the hosted URL.",
            "Do not broaden workbench permissions or expose secrets in browser routes.",
            [
                "Hosted `/api/readyz` is green.",
                "Secrets are injected server-side only.",
                "State survives restart without writing tracked files.",
            ],
            ["/api/readyz", "/api/healthz"],
        ),
        _gap(
            "infra.telegram_live_identity",
            "Telegram bot identity and webhook proof",
            "infrastructure",
            STATUS_SOURCE_READY_LIVE_PENDING,
            {
                "currentProcessTokenConfigured": False,
                "currentBehavior": "status/preview routes only; no sends",
            },
            "Telegram is the operator surface, so production needs identity readback, webhook proof, opt-in persistence, and rate limits.",
            "Local previews work, but the current restarted local process does not have the bot token loaded.",
            "Configure bot token and webhook secret through server-side env, verify `getMe` and webhook info, keep sends disabled until opt-in and throttling are reviewed.",
            "ZeroGuard Telegram lane",
            1,
            ["TELEGRAM_BOT_TOKEN", "TELEGRAM_WEBHOOK_SECRET_TOKEN", "managed_opt_in_store"],
            "Restart the local/hosted service with Telegram env and run read-only `/api/telegram/status?live=1`.",
            "Do not send messages or auto-register webhooks from the workbench.",
            [
                "Bot identity readback shows the intended bot.",
                "Webhook secret validation is enforced.",
                "Opt-in records persist outside process memory.",
                "Sends remain handled by a separate gated worker.",
            ],
            ["/api/telegram/status", "/api/telegram/registrations", "/api/telegram/webhook"],
        ),
        _gap(
            "node.0g_storage_soak",
            "0G storage node funded soak",
            "node",
            STATUS_LOCAL_ONLY,
            {
                "status": (storage.get("readiness") or {}).get("status"),
                "blockedBy": (storage.get("readiness") or {}).get("blockedBy"),
                "connectedPeers": (storage.get("storageRpc") or {}).get("connectedPeers"),
                "logSyncHeight": (storage.get("storageRpc") or {}).get("logSyncHeight"),
                "activeMinerBalanceOg": (storage.get("funding") or {}).get("activeMinerBalanceOg"),
                "hundredOgTransferSent": (storage.get("funding") or {}).get("hundredOgTransferSent"),
            },
            "The node is a credible 0G operations wedge only after peer count, sync gap, and relay posture are stable.",
            "This is real local infrastructure data, but it is not yet green enough for larger funding claims.",
            "Continue snapshots until peer and sync blockers clear, then prepare a reviewed funding or storage-expansion manifest.",
            "ZeroGuard node ops",
            1,
            (storage.get("readiness") or {}).get("blockedBy") or [],
            "Keep the soak running and publish only read-only telemetry until expansion blockers are gone.",
            "Do not send the large 0G transfer while `largeFundingExpansionReady` is false.",
            [
                "Connected peers meet target.",
                "Storage log sync gap is inside policy.",
                "Relay health is stable.",
                "Only the expected small test funding is observed until expansion approval.",
            ],
            ["/api/0g/storage-node/status?snapshot=1"],
        ),
        _gap(
            "node.pi_mesh",
            "Raspberry Pi edge mesh",
            "node",
            STATUS_LIVE_REAL_DATA,
            {
                "status": (pi_mesh.get("readiness") or {}).get("status"),
                "clusterReady": (pi_mesh.get("readiness") or {}).get("clusterReady"),
                "blockers": (pi_mesh.get("readiness") or {}).get("blockers"),
            },
            "The Pi pair gives ZeroGuard cheap, resilient edge telemetry and proof-cache capacity.",
            "The snapshot is real local evidence, but production still needs service supervision and append-only export.",
            "Promote Pi sentinels into systemd services that write signed/redacted heartbeat JSONL for backfill and Telegram previews.",
            "ZeroGuard edge lane",
            2,
            (pi_mesh.get("readiness") or {}).get("blockers") or [],
            "Add a service manifest and heartbeat schema for rvpi-a/rvpi-b without storing secrets.",
            "Do not put wallet keys, Telegram tokens, or paid API keys on the Pis.",
            [
                "Both Pis publish heartbeat snapshots over the private Ethernet link.",
                "Mac/host app ingests the heartbeat without SSH scraping.",
                "No secrets or raw chats are present in heartbeat files.",
            ],
            ["/api/0g/pi-mesh?snapshot=1"],
        ),
        _gap(
            "model.0g_private_computer",
            "0G Private Computer and 0GM-1.0",
            "model",
            STATUS_SOURCE_READY_LIVE_PENDING,
            {
                "model": (private_computer.get("model") or {}).get("id"),
                "apiKeyConfigured": (private_computer.get("api") or {}).get("apiKeyConfigured"),
                "paidInferenceEnabled": bool(
                    (private_computer.get("safety") or {}).get("paidInferenceEnabled")
                ),
                "smokePreviewSchema": private_compute_smoke.get("schema"),
                "smokePreviewStatus": private_compute_smoke.get("status"),
                "promptScrubberReady": bool(
                    (private_compute_smoke.get("promptScrub") or {}).get("safeForInference")
                ),
                "smokeInferenceExecuted": (private_compute_smoke.get("safety") or {}).get(
                    "inferenceExecuted"
                ),
            },
            "Attested inference lets ZeroGuard summarize sensitive risk packets without trusting an ordinary centralized model host.",
            "The adapter, prompt scrubber, and no-inference smoke preview are ready, but no server-side Router key or paid smoke is configured in this runtime.",
            "Create a server-side Router key, deposit a small reviewed budget, and run one prompt-minimized smoke on a deterministic verdict packet.",
            "ZeroGuard model lane",
            1,
            ["0g_router_api_key", "router_deposit", "paid_inference_env_gate", "inference_smoke_test"],
            "Use `/api/0g/private-computer/smoke-preview` as the reviewed contract before running the first server-side paid smoke.",
            "Do not send secrets, raw private chats, private keys, mnemonics, or full paid-feed payloads to any model.",
            [
                "Inference route is server-side only.",
                "Prompt scrubber and budget limits are tested.",
                "Model output is stored as advisory explanation, never policy authority.",
                "Response metadata includes model id and attestation/proof references when available.",
            ],
            [
                "/api/0g/private-computer",
                "/api/0g/private-computer/smoke-preview",
                "/api/model/training-roadmap",
            ],
        ),
        _gap(
            "model.training_and_evals",
            "Training, eval, and research data loop",
            "model",
            STATUS_SOURCE_READY_LIVE_PENDING,
            {
                "roadmapSchema": model_roadmap.get("schema"),
                "datasetCount": len(model_roadmap.get("datasets") or []),
                "modelAuthority": model_roadmap.get("authorityBoundary"),
            },
            "The model gets useful when ZeroGuard can evaluate it on our own incidents, traces, node telemetry, and no-send drafts.",
            "The training plan is structured, but the reviewed eval corpus and labeling workflow are not complete.",
            "Turn deterministic verdicts, incident features, and sanitized ops telemetry into eval sets before any fine-tuning claim.",
            "ZeroGuard model lane",
            1,
            ["historical_feature_store", "labeling_guidelines", "eval_harness"],
            "Generate the first public-safe JSONL eval split from existing incidents and policy traces.",
            "Do not train on secrets, raw private user chats, unlicensed vendor payloads, or unreviewed Telegram messages.",
            [
                "Eval cases include prompt, expected deterministic verdict, evidence ids, and source rights.",
                "0GM explanations are scored for faithfulness to deterministic verdict packets.",
                "Regression suite fails if model text contradicts guardrail verdicts.",
            ],
            ["/api/model/training-roadmap", "/api/data/backfill-plan"],
        ),
        _gap(
            "mock.demo_fixtures",
            "Demo fixtures and preview payloads",
            "business",
            STATUS_MOCK_FIXTURE_ONLY,
            {
                "examples": [
                    "workbench deny/simulation samples",
                    "MetaMask x 1Shot permission preview payload",
                    "peer outreach demo contact",
                    "frontier experiment previews",
                ],
            },
            "Fixtures are useful for demos and tests, but judges and customers need to know which data is real.",
            "If fixture outputs are mixed into production claims, the product looks less credible than the actual work deserves.",
            "Label fixtures explicitly, keep them out of paid routes, and graduate repeated useful fixtures into replayable eval cases.",
            "ZeroGuard product lane",
            2,
            [],
            "Add fixture labels to every demo-only payload and include fixture count in the production matrix.",
            "Do not let mock payloads appear as fresh intelligence, vendor data, live x402 settlement, or peer contact proof.",
            [
                "Every demo-only endpoint declares fixture mode.",
                "Paid or public intelligence routes reject fixture-only evidence unless explicitly requested for a demo.",
            ],
            ["/api/hackathons/metamask-1shot/permission-preview", "/api/peer/outreach-preview"],
        ),
        _gap(
            "business.paid_intelligence_sku",
            "Production data product value proposition",
            "business",
            STATUS_SOURCE_READY_LIVE_PENDING,
            {
                "candidateProducts": [item.get("id") for item in x402.get("products") or []],
                "rawPayloadResaleAllowed": False,
            },
            "A production ZeroGuard business needs buyers to pay for durable, rights-cleared defensive intelligence, not dashboards.",
            "The SKUs are shaped, but pricing, SLAs, terms, route contracts, and example customer workflows are not validated.",
            "Start with wallet preflight verdicts and node health snapshots because they are concrete, narrow, and machine-consumable.",
            "ZeroGuard business lane",
            2,
            ["x402_settlement", "historical_feature_store", "customer_terms"],
            "Publish one sample response packet, one route contract, one pricing policy, and one judge/client walkthrough.",
            "Do not sell raw upstream feeds, sanctions decisions as legal advice, or unverified yield estimates.",
            [
                "One paid-route schema is frozen.",
                "Response examples include provenance, disclaimers, source ids, hashes, and receipt fields.",
                "Terms distinguish defensive analysis from legal/compliance advice.",
            ],
            ["/api/x402/data-products", "/api/product/brief"],
        ),
    ]

    return {
        "schema": PRODUCTION_GAP_MATRIX_SCHEMA,
        "generatedAt": _now(),
        "mode": "local_snapshot_and_manifest_no_side_effects",
        "productionReady": False,
        "whyNotProductionReadyYet": [
            "Historical feature store has a seed API/export from current curated/local artifacts, but not the wider scheduled 2020-present backfill and query index.",
            "0G Storage bundle/readback plus x402 dry-run/caps/terms routes are prepared, but live upload/settlement are not enabled.",
            "Wallet-provider protection is implemented locally, but it is not yet hosted and embedded in a production dapp/provider flow.",
            "0G Private Computer has no server-side Router key or paid inference smoke in this runtime.",
            "Telegram live identity/webhook proof is not loaded in the current local process.",
            "The funded 0G storage node is near-current, but peer depth still blocks larger funding expansion.",
        ],
        "whatIsRealNow": [
            "Validated 28-incident April 2026 corpus with 28/28 detector coverage.",
            "First incident eval JSONL and first open reputation backfill artifact when present locally.",
            "Seed historical feature-store rows for incident detector traces and reputation-feed summary evidence.",
            "EIP-1193 wallet-provider guard route, workbench control, and TypeScript wrapper that block deny/review requests before a wallet prompt.",
            "Public 0G mainnet receipt anchor and read-only verifier path.",
            "Local RV 0G storage-node soak snapshot with small test funding only.",
            "Raspberry Pi mesh snapshot showing cluster-ready edge posture.",
            "Rights-aware source registry and connector manifests.",
        ],
        "classificationSummary": _classification_summary(gaps),
        "topHardGates": _top_hard_gates(gaps),
        "safeBuildOrder": [
            "Freeze the production gap matrix route and docs so every claim is inspectable.",
            "Deploy and embed the EIP-1193 provider guard in a demo dapp before claiming live wallet protection.",
            "Schedule and expand the append-only historical feature store beyond the current seed run.",
            _reputation_backfill_build_order(reputation_backfill),
            "Configure Router funding/key only after reviewing the disabled 0G Private Computer smoke contract.",
            "Promote the dry-run x402 route to testnet facilitator readback after pay-to review without enabling mainnet settlement.",
            "Wait for storage-node peer/sync blockers to clear before any larger 0G funding.",
        ],
        "gaps": gaps,
        "modelTrainingRoadmap": model_roadmap,
        "sourceReferences": [
            "https://0g.ai/blog/0gm-1-0-35b-a3b",
            "https://0g.ai/blog/0g-private-computer",
            "https://docs.0g.ai/developer-hub/building-on-0g/storage/sdk",
            "https://docs.0g.ai/run-a-node/validator-node",
        ],
        "safety": _safety(),
    }


def build_model_training_roadmap(
    *,
    incident_summary_payload: dict[str, Any] | None = None,
    detection_coverage_payload: dict[str, Any] | None = None,
    source_registry_payload: dict[str, Any] | None = None,
    private_computer_payload: dict[str, Any] | None = None,
    local_inference_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the rights-aware training/eval roadmap for 0GM and local models."""

    summary = incident_summary_payload or incident_summary()
    coverage = detection_coverage_payload or detection_coverage()
    sources = source_registry_payload or source_registry_public()
    private_computer = private_computer_payload or build_0g_private_computer_integration(live=False)
    local_inference = local_inference_payload or build_local_inference_mesh(live=False)
    incident_count = (summary.get("stats") or {}).get("incidentCount")
    source_count = sources.get("sourceCount")

    datasets = [
        {
            "id": "incident_detector_eval_set",
            "status": STATUS_LIVE_REAL_DATA,
            "source": "data/april_2026_incidents.json plus reviewed source evidence",
            "currentScale": {"incidents": incident_count, "coveredSeeds": coverage.get("coveredCount")},
            "rights": "public-source-derived defensive features; raw upstream resale disabled",
            "storageTarget": "data/evals/incident_detector_eval.v1.jsonl",
            "labelingPlan": "Each case stores normalized intent, detector ids, expected verdict, evidence ids, source refs, and rights class.",
            "modelUse": "Evaluate whether 0GM summaries faithfully explain deterministic ZeroGuard verdicts.",
            "doNotTrainOn": ["private keys", "mnemonics", "paid raw payloads", "unlicensed source dumps"],
            "acceptanceCriteria": [
                "Every row has a deterministic expected verdict.",
                "Every row maps back to at least one source id or reviewed evidence hash.",
                "Model-generated explanations cannot override policy verdicts.",
            ],
        },
        {
            "id": "reputation_shadow_features",
            "status": STATUS_SOURCE_READY_LIVE_PENDING,
            "source": f"{source_count} source lanes from the rights-aware registry",
            "currentScale": {"sourceLanes": source_count, "liveScheduledWorkers": 0},
            "rights": "derived labels, hashes, first-seen/last-seen metadata, and source ids only",
            "storageTarget": "data/backfill/reputation_features/*.jsonl",
            "labelingPlan": "Normalize source verdicts into allow/review/deny hints with confidence and freshness.",
            "modelUse": "Train/evaluate dedupe, summarization, and source-conflict explanation behavior.",
            "doNotTrainOn": ["raw paid vendor payloads", "private customer investigations"],
            "acceptanceCriteria": [
                "No raw feed body is returned or stored in public artifacts.",
                "Each feature row carries rawPayloadResaleAllowed=false.",
                "Scheduled workers fail closed when a source is unavailable.",
            ],
        },
        {
            "id": "wallet_preflight_policy_traces",
            "status": STATUS_SOURCE_READY_LIVE_PENDING,
            "source": "deterministic policy engine, signature engine, and native preflight routes",
            "currentScale": {"routes": ["/api/evaluate", "/api/native-preflight", "/api/threat-case-file"]},
            "rights": "first-party deterministic traces generated by ZeroGuard",
            "storageTarget": "data/evals/wallet_preflight_traces.v1.jsonl",
            "labelingPlan": "Record request class, normalized intent, blockers, warnings, verdict, and receipt hash.",
            "modelUse": "Teach/examine explanations that match the exact blockers without inventing facts.",
            "doNotTrainOn": ["real user wallet secrets", "full private chat transcripts", "raw payment headers"],
            "acceptanceCriteria": [
                "Trace export redacts addresses when requested.",
                "Each row includes a deterministic receipt hash.",
                "Regression tests catch model explanations that contradict verdicts.",
            ],
        },
        {
            "id": "node_soak_telemetry",
            "status": STATUS_LOCAL_ONLY,
            "source": "RV Windows storage node snapshots and Pi mesh heartbeat snapshots",
            "currentScale": {
                "storageSnapshotRoute": "/api/0g/storage-node/status?snapshot=1",
                "piMeshRoute": "/api/0g/pi-mesh?snapshot=1",
            },
            "rights": "operator-owned telemetry, public-safe only after redaction",
            "storageTarget": "data/backfill/node_ops_timeseries/*.jsonl",
            "labelingPlan": "Label sync blockers, peer drops, relay posture, and no-key/no-funding states.",
            "modelUse": "Summarize operational blockers for Telegram digests and runbooks.",
            "doNotTrainOn": ["private logs", "private keys", "LAN secrets", "home-network credentials"],
            "acceptanceCriteria": [
                "No private keys or local secrets appear in telemetry rows.",
                "Snapshots include source host class, timestamp, peer count, sync gap, and blocker ids.",
                "Model summaries never recommend funding while expansion blockers remain.",
            ],
        },
        {
            "id": "peer_outreach_draft_eval",
            "status": STATUS_MOCK_FIXTURE_ONLY,
            "source": "preview-only peer-protection drafts and operator-authored examples",
            "currentScale": {"sendEnabled": False, "broadcastEnabled": False},
            "rights": "first-party generated drafts; no scraped private contact data",
            "storageTarget": "data/evals/peer_outreach_drafts.v1.jsonl",
            "labelingPlan": "Human score drafts for clarity, non-alarmism, evidence faithfulness, and opt-in respect.",
            "modelUse": "Tune/re-rank messages that are helpful without spamming peers.",
            "doNotTrainOn": ["unconsented contact records", "private Telegram chats"],
            "acceptanceCriteria": [
                "Every draft declares preview_no_send.",
                "Contact source and opt-in state are explicit.",
                "No draft contains a live transaction payload.",
            ],
        },
        {
            "id": "x402_receipt_and_usage_metadata",
            "status": STATUS_SOURCE_READY_LIVE_PENDING,
            "source": "future testnet/mainnet x402 paid route metadata",
            "currentScale": {"settlementEnabled": False},
            "rights": "payment metadata, response schema id, receipt hash, and route id only",
            "storageTarget": "data/backfill/x402_usage/*.jsonl",
            "labelingPlan": "Classify paid requests by product id, route version, source mix, and customer-safe outcome.",
            "modelUse": "Forecast product value and summarize purchased defensive packets.",
            "doNotTrainOn": [
                "payment headers",
                "signatures",
                "customer secrets",
                "raw paid payloads",
                "raw paid feeds",
            ],
            "acceptanceCriteria": [
                "No payment header or signature is retained.",
                "Usage rows can reproduce billing/support context without storing secrets.",
                "Paid outputs remain derived analysis only.",
            ],
        },
    ]

    return {
        "schema": MODEL_TRAINING_ROADMAP_SCHEMA,
        "generatedAt": _now(),
        "mode": "rights_aware_eval_plan_no_training_run",
        "targetModels": [
            {
                "id": (private_computer.get("model") or {}).get("id", "0GM-1.0-35B-A3B"),
                "role": "attested hosted explanation and long-context triage",
                "status": "adapter_ready_no_paid_inference",
            },
            {
                "id": "windows_local_model",
                "role": "future local summarizer after a model is loaded",
                "status": _node_status(local_inference, "windows_ollama"),
            },
            {
                "id": "pi_tiny_filters",
                "role": "small dedupe/filter heuristics only",
                "status": "sentinel_not_large_model_host",
            },
        ],
        "authorityBoundary": (
            "Models may summarize, dedupe, draft, classify, and explain deterministic packets; "
            "they may not approve transactions, override deny verdicts, move funds, or send Telegram messages."
        ),
        "datasets": datasets,
        "evaluationPlan": [
            "Start with deterministic offline evals before paid inference.",
            "Score faithfulness to blockers, source citation accuracy, refusal quality, and unsafe-action avoidance.",
            "Keep 0GM prompts minimized: verdict packet, source ids, short evidence excerpts, no secrets.",
            "Compare hosted 0GM, local Windows model, and deterministic baseline on the same JSONL cases.",
        ],
        "promotionGates": [
            "Historical feature store exists and records rights metadata.",
            "Prompt scrubber has tests for secrets, keys, Telegram chats, and payment headers.",
            "Budget and rate limits are enforced server-side.",
            "A human reviews the first paid 0G Private Computer smoke before enabling recurring use.",
        ],
        "storagePlan": {
            "localFirst": "data/evals/ and data/backfill/ JSONL with run manifests",
            "queryScale": "DuckDB or SQLite feature store after first useful runs",
            "zeroGStorage": "public-safe derived bundles only after upload/readback proof exists",
            "rawPayloadPolicy": "never store private keys, mnemonics, raw chats, raw paid feeds, or payment headers",
        },
        "firstExport": {
            "route": "/api/model/incident-eval-set",
            "jsonlPath": "data/evals/incident_detector_eval.v1.jsonl",
            "exists": DEFAULT_INCIDENT_EVAL_PATH.exists(),
            "generator": "scripts/build_incident_eval_set.py --out data/evals/incident_detector_eval.v1.jsonl",
        },
        "safety": _safety(),
    }


def _gap(
    gap_id: str,
    label: str,
    section: str,
    current_status: str,
    current_evidence: dict[str, Any],
    production_requirement: str,
    mock_or_local_risk: str,
    real_data_plan: str,
    owner: str,
    priority: int,
    blocked_by: list[str],
    safe_next_step: str,
    unsafe_to_do_now: str,
    acceptance_criteria: list[str],
    routes: list[str],
) -> dict[str, Any]:
    return {
        "id": gap_id,
        "label": label,
        "section": section,
        "currentStatus": current_status,
        "currentEvidence": current_evidence,
        "productionRequirement": production_requirement,
        "whyItMatters": production_requirement,
        "mockOrLocalRisk": mock_or_local_risk,
        "realDataPlan": real_data_plan,
        "owner": owner,
        "priority": priority,
        "blockedBy": blocked_by,
        "safeNextStep": safe_next_step,
        "unsafeToDoNow": unsafe_to_do_now,
        "acceptanceCriteria": acceptance_criteria,
        "routes": routes,
    }


def _classification_summary(gaps: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {
        STATUS_LIVE_REAL_DATA: 0,
        STATUS_LOCAL_ONLY: 0,
        STATUS_SOURCE_READY_LIVE_PENDING: 0,
        STATUS_MOCK_FIXTURE_ONLY: 0,
        STATUS_BLOCKED: 0,
    }
    sections: dict[str, int] = {}
    for gap in gaps:
        status = gap.get("currentStatus")
        counts[status] = counts.get(status, 0) + 1
        section = str(gap.get("section") or "other")
        sections[section] = sections.get(section, 0) + 1
    return {
        "counts": counts,
        "sections": sections,
        "highestPriorityOpenCount": sum(
            1
            for gap in gaps
            if gap.get("priority") == 1 and gap.get("currentStatus") != STATUS_LIVE_REAL_DATA
        ),
    }


def _top_hard_gates(gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    open_gaps = [
        gap
        for gap in gaps
        if gap.get("priority") == 1 and gap.get("currentStatus") != STATUS_LIVE_REAL_DATA
    ]
    return [
        {
            "id": gap["id"],
            "label": gap["label"],
            "blockedBy": gap["blockedBy"],
            "safeNextStep": gap["safeNextStep"],
        }
        for gap in open_gaps[:8]
    ]


def _readiness_check_detail(readiness: dict[str, Any], check_id: str) -> dict[str, Any]:
    for check in readiness.get("checks") or []:
        if check.get("id") == check_id:
            detail = check.get("detail")
            return detail if isinstance(detail, dict) else {}
    return {}


def _mainnet_proof_evidence(readiness: dict[str, Any]) -> dict[str, Any]:
    proof = _readiness_check_detail(readiness, "mainnet_proof_file")
    config = _readiness_check_detail(readiness, "mainnet_verifier_profile")
    return {
        "contractAddress": proof.get("contractAddress"),
        "anchorTxHash": proof.get("anchorTxHash"),
        "anchorVerified": proof.get("anchorVerified"),
        "currentChainId": config.get("currentChainId"),
        "currentRpc": config.get("currentRpc"),
        "receiptContractConfigured": config.get("receiptContractConfigured"),
    }


def _reputation_backfill_blockers(status: dict[str, Any]) -> list[str]:
    blockers = ["schedule_supervisor", "credentialed_sources", "vendor_terms"]
    if status.get("status") != "ready":
        return ["first_open_feed_backfill_run", *blockers]
    return blockers


def _historical_feature_store_blockers(store: dict[str, Any]) -> list[str]:
    blockers = ["scheduled_backfill_runner", "query_index", "24_month_incident_backfill"]
    if int(store.get("featureCount") or 0) <= 0:
        return ["feature_schema_freeze", *blockers]
    return blockers


def _x402_settlement_blockers(policy: dict[str, Any]) -> list[str]:
    blockers = ["testnet_facilitator_readback", "settlement_receipt_storage"]
    payment = policy.get("paymentRequirement") if isinstance(policy.get("paymentRequirement"), dict) else {}
    if not payment.get("payToConfigured"):
        blockers.insert(0, "pay_to_address")
    return blockers


def _reputation_backfill_next_step(status: dict[str, Any]) -> str:
    if status.get("status") == "ready":
        return "Install a supervisor schedule for the derived-only PhishDestroy worker, then add one credentialed vendor after terms review."
    return "Run the PhishDestroy derived-only backfill worker and persist the latest feature artifact without raw feed rows."


def _reputation_backfill_build_order(status: dict[str, Any]) -> str:
    if status.get("status") == "ready":
        return "Install supervision for the first open reputation feed and add freshness alerts around the derived artifact."
    return "Promote one open reputation feed into a derived-feature backfill artifact."


def _node_status(mesh: dict[str, Any], node_id: str) -> str:
    for node in mesh.get("nodes") or []:
        if node.get("id") == node_id:
            return str(node.get("status") or "unknown")
    return "unknown"


def _safety() -> dict[str, bool]:
    return {
        "readOnly": True,
        "liveNetworkCalls": False,
        "privateKeysReturned": False,
        "secretDisplayEnabled": False,
        "promptExecutionEnabled": False,
        "paidInferenceEnabled": False,
        "telegramSendsEnabled": False,
        "externalMessagesEnabled": False,
        "transactionSigningEnabled": False,
        "transactionBroadcastingEnabled": False,
        "moneyMovementEnabled": False,
        "x402SettlementEnabled": False,
        "rawPayloadsReturned": False,
        "trainingRunStarted": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
