"""Read-only peer protection, 0G Private Computer, and Pi mesh plans."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any

import requests

from guard0.da_node import build_storage_node_status

PRIVATE_COMPUTER_SCHEMA = "0guard.0g_private_computer_integration.v1"
HOT_WALLET_RESOURCES_SCHEMA = "0guard.0g_hot_wallet_resources.v1"
PEER_PROTECTION_SCHEMA = "0guard.peer_protection_plan.v1"
PEER_OUTREACH_PREVIEW_SCHEMA = "0guard.peer_outreach_preview.v1"
PI_MESH_SCHEMA = "0guard.pi_mesh_plan.v1"
PI_MESH_SNAPSHOT_SCHEMA = "0guard.rv_pi_mesh_snapshot.v1"
DEFAULT_PI_MESH_STATUS_PATH = "content/rv_pi_mesh.local.json"

MODEL_ID = "0GM-1.0-35B-A3B"
MODEL_HF_REPO = "0G-AI/0GM-1.0-35B-A3B-0427"
ROUTER_BASE_URL = "https://router-api.0g.ai/v1"
ROUTER_TESTNET_BASE_URL = "https://router-api-testnet.integratenetwork.work/v1"
CHAT_COMPLETIONS_URL = f"{ROUTER_BASE_URL}/chat/completions"
ROUTER_MODELS_URL = f"{ROUTER_BASE_URL}/models"
MODEL_URL = "https://pc.0g.ai/models/0GM-1.0-35B-A3B"
API_REFERENCE_URL = "https://docs.0g.ai/developer-hub/building-on-0g/compute-network/router/quickstart"
ROUTER_OVERVIEW_URL = "https://docs.0g.ai/developer-hub/building-on-0g/compute-network/router/overview"
ROUTER_AUTH_URL = "https://docs.0g.ai/developer-hub/building-on-0g/compute-network/router/authentication"
ROUTER_MODELS_DOC_URL = "https://docs.0g.ai/developer-hub/building-on-0g/compute-network/router/models"
ROUTER_BILLING_URL = "https://docs.0g.ai/developer-hub/building-on-0g/compute-network/router/account/deposits"
DIRECT_INFERENCE_URL = "https://docs.0g.ai/developer-hub/building-on-0g/compute-network/inference"
MODEL_BLOG_URL = "https://0g.ai/blog/0gm-1-0-35b-a3b"
PRIVATE_COMPUTER_BLOG_URL = "https://0g.ai/blog/0g-private-computer"
PAYMENT_LAYER_MAINNET = "0xA3b15Bd2aD18BFB6b5f92D8AA9F444Dd59d1cE32"
PAYMENT_LAYER_TESTNET = "0x0AD9690e0b34aB2d493DE02cDF149ee34f6C9939"
DEFAULT_FUNDED_WALLET = "0x885b0892D241Cb5033C9995e09cA521d54f936b5"
DEFAULT_STORAGE_MINER = "0x8c497E41405C924D81dB24aB033CAca71ED559E9"


def build_0g_private_computer_integration(
    *,
    live: bool = False,
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """Return the current 0G model integration posture without calling paid inference."""

    api_key_configured = bool(
        os.getenv("ZG_0G_PC_API_KEY")
        or os.getenv("ZG_0G_ROUTER_API_KEY")
        or os.getenv("ZERO_G_API_KEY")
    )
    catalog = (
        _read_router_model_catalog(timeout_seconds=timeout_seconds)
        if live
        else _router_model_catalog_not_checked()
    )
    return {
        "schema": PRIVATE_COMPUTER_SCHEMA,
        "generatedAt": _now(),
        "mode": "live_router_catalog_no_inference_call" if live else "capability_manifest_no_inference_call",
        "model": {
            "id": MODEL_ID,
            "huggingFaceRepo": MODEL_HF_REPO,
            "license": "Apache-2.0",
            "architecture": "qwen3_5_moe",
            "totalParameters": "35B",
            "activeParametersPerToken": "~3B",
            "nativeContextTokens": 262_144,
            "extensibleContextTokens": 1_010_000,
            "maxOutputTokens": 32_768,
            "modality": "image_text_to_text",
            "thinkingModeDefault": True,
            "trainingNetwork": "0G Compute",
            "servingSurface": "0G Private Computer",
        },
        "api": {
            "openAiCompatible": True,
            "recommendedPath": "router",
            "routerDashboard": "https://pc.0g.ai",
            "routerTestnetDashboard": "https://pc.testnet.0g.ai",
            "routerBaseUrl": ROUTER_BASE_URL,
            "routerTestnetBaseUrl": ROUTER_TESTNET_BASE_URL,
            "chatCompletionsUrl": CHAT_COMPLETIONS_URL,
            "modelsUrl": ROUTER_MODELS_URL,
            "modelUrl": MODEL_URL,
            "apiReferenceUrl": API_REFERENCE_URL,
            "apiKeyConfigured": api_key_configured,
            "apiKeyEnv": ["ZG_0G_PC_API_KEY", "ZG_0G_ROUTER_API_KEY", "ZERO_G_API_KEY"],
            "apiKeyPrefix": "sk-",
            "keyHandling": (
                "Create the key in pc.0g.ai Dashboard -> API Keys, store it server-side, "
                "and never ship it to browsers because it can spend deposited 0G."
            ),
            "sampleRequest": {
                "model": MODEL_ID,
                "messages": [{"role": "user", "content": "Summarize this risk packet."}],
                "stream": False,
                "chat_template_kwargs": {"enable_thinking": False},
            },
        },
        "directAdvancedMode": {
            "whenToUse": "Only when we need manual provider selection or wallet-signed direct control.",
            "serviceUrlShape": "<service.url>/v1/proxy",
            "authTokenPrefix": "app-sk-",
            "minimumLedgerDepositOg": 3,
            "minimumProviderSubAccountOg": 1,
            "walletKeyRequiredByCli": True,
            "zeroGuardDefault": "avoid_direct_mode_until_operator_present",
        },
        "modelCatalog": catalog,
        "currentPublishedPricing": {
            "routerReadbackNeuronPerTokenInput": "310000000000",
            "routerReadbackNeuronPerTokenOutput": "1910000000000",
            "routerReadbackUsdPerMillionInput": 0.16,
            "routerReadbackUsdPerMillionOutput": 0.96,
            "blogUsdPerMillionCache": 0.05,
            "pricingCanDrift": True,
            "source": "live /v1/models readback on 2026-05-17 plus 0G model launch notes",
        },
        "zeroGuardUses": [
            {
                "id": "attested_peer_bulletin_reviewer",
                "value": (
                    "Use sealed inference to rewrite peer-protection bulletins into short, "
                    "non-alarming messages with cited evidence and no secrets."
                ),
            },
            {
                "id": "long_context_node_ops_copilot",
                "value": (
                    "Feed logs, StorageScan summaries, node configs, and runbooks into a "
                    "long-context review before changing node funds or runtime settings."
                ),
            },
            {
                "id": "threat_case_file_compressor",
                "value": (
                    "Turn verbose incident, wallet, and reputation evidence into operator "
                    "case files that a normal wallet user can understand."
                ),
            },
            {
                "id": "open_weight_regression_harness",
                "value": (
                    "Because the weights are Apache-2.0, benchmark local or hosted 0GM "
                    "against ZeroGuard risk prompts without being locked to a closed model."
                ),
            },
        ],
        "implementationGates": [
            "Do not send prompts containing private keys, mnemonics, API tokens, or raw secrets.",
            "Do not call paid inference unless an operator-configured Router API key is present.",
            "Use 0GM output only for explanations, summaries, dedupe, and draft review.",
            "Keep model output advisory; policy decisions still come from deterministic guard code.",
            "Keep a per-deployment API key and revoke it if it is ever exposed.",
        ],
        "fundingState": {
            "status": "not_configured_from_repo",
            "routerDepositPrepared": False,
            "directProviderTransferPrepared": False,
            "requiresWalletSignature": True,
            "operatorConfirmationRequired": True,
            "paymentLayerContracts": {
                "mainnet": PAYMENT_LAYER_MAINNET,
                "testnet": PAYMENT_LAYER_TESTNET,
            },
            "reason": "Router deposits and direct provider transfers move mainnet 0G and remain outside the workbench.",
        },
        "sources": [
            ROUTER_OVERVIEW_URL,
            ROUTER_AUTH_URL,
            ROUTER_MODELS_DOC_URL,
            ROUTER_BILLING_URL,
            DIRECT_INFERENCE_URL,
            MODEL_BLOG_URL,
            PRIVATE_COMPUTER_BLOG_URL,
        ],
        "safety": _safety(live_network_calls=live),
    }


def build_0g_hot_wallet_resources() -> dict[str, Any]:
    """Return a no-secret wallet/resource plan for 0G compute and node operations."""

    funded_wallet = os.getenv("ZG_FUNDED_WALLET_ADDRESS", DEFAULT_FUNDED_WALLET).strip()
    storage_miner = os.getenv("ZG_STORAGE_MINER_ADDRESS", DEFAULT_STORAGE_MINER).strip()
    return {
        "schema": HOT_WALLET_RESOURCES_SCHEMA,
        "generatedAt": _now(),
        "mode": "operator_gated_resource_manifest",
        "walletRoles": [
            {
                "id": "zeroguard_funded_wallet",
                "publicAddress": funded_wallet,
                "purpose": "Main 0G treasury/deployer wallet for explicit operator-approved funding.",
                "privateKeyLocation": "external_secret_store_only",
                "repoCanReadPrivateKey": False,
                "recommendedUse": "Router deposit and small node experiments after exact transaction review.",
            },
            {
                "id": "0g_compute_router_billing",
                "publicAddress": funded_wallet,
                "purpose": "Pays 0G Compute Router requests after funds are deposited on pc.0g.ai.",
                "hotWalletRisk": "API keys can spend deposited 0G, so keep one server-side key per deployment.",
                "currentRepoState": "api_key_not_required_for_manifest",
            },
            {
                "id": "storage_or_miner_operations",
                "publicAddress": storage_miner,
                "purpose": "Storage/DA/node operations only after soak, peer health, exact recipient, and amount are confirmed.",
                "currentRepoState": "read_only_telemetry_and_digest_previews",
            },
        ],
        "preparedResources": [
            {
                "id": "router_api_key",
                "status": "operator_action_required",
                "where": "https://pc.0g.ai -> Dashboard -> API Keys",
                "env": "ZG_0G_ROUTER_API_KEY",
                "secretReturnedByApi": False,
            },
            {
                "id": "router_mainnet_deposit",
                "status": "manifest_only_no_transaction",
                "network": "0G mainnet",
                "paymentLayerContract": PAYMENT_LAYER_MAINNET,
                "suggestedInitialBudgetOg": 5,
                "largerBudgetRequestedByUserOg": 25,
                "requiresFinalConfirmation": True,
                "reason": "Deposits move 0G into the Router payment contract and should be reviewed in the wallet UI.",
            },
            {
                "id": "direct_provider_subaccount",
                "status": "not_recommended_for_default_path",
                "minimumProviderSubAccountOg": 1,
                "requiresProviderAddress": True,
                "requiresWalletSignature": True,
                "reason": "Router is simpler and avoids per-provider fund management for ZeroGuard's server-side use case.",
            },
        ],
        "confirmationChecklist": [
            "Exact chain ID and wallet address.",
            "Exact contract, deposit method, or provider address.",
            "Exact amount and max fee.",
            "Whether the spend is Router balance, Direct provider sub-account, storage miner, or validator stake.",
            "Rollback/revoke path: revoke API key, stop service, or leave provider sub-account unused.",
        ],
        "notAllowedFromWorkbench": [
            "Reading, printing, copying, or exporting private keys.",
            "Depositing 0G, transferring provider funds, staking, delegating, swapping, bridging, or broadcasting transactions.",
            "Creating API keys in browser automation where the secret might be exposed in logs or screenshots.",
        ],
        "sources": [ROUTER_OVERVIEW_URL, ROUTER_AUTH_URL, ROUTER_BILLING_URL, DIRECT_INFERENCE_URL],
        "safety": _safety(live_network_calls=False),
    }


def build_peer_protection_plan(
    *,
    live: bool = False,
    storage_status: dict[str, Any] | None = None,
    private_computer: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build ZeroGuard's no-send peer-protection operating model."""

    storage = storage_status or build_storage_node_status(live=live)
    storage_rpc = storage.get("storageRpc") or {}
    node = storage.get("node") or {}
    private_ai = private_computer or build_0g_private_computer_integration()
    return {
        "schema": PEER_PROTECTION_SCHEMA,
        "generatedAt": _now(),
        "mode": "live_read_only" if live else "configured_strategy",
        "thesis": (
            "ZeroGuard is the peer-protection layer for AI-native infrastructure: it observes "
            "0G node health and wallet-adjacent risk, drafts verified help for peers, and keeps "
            "every outbound message behind opt-in, proof, and operator approval."
        ),
        "nodeContext": {
            "storageNode": {
                "name": node.get("name"),
                "publicSocket": node.get("publicSocket"),
                "readiness": (storage.get("readiness") or {}).get("status"),
                "connectedPeers": storage_rpc.get("connectedPeers"),
                "logSyncHeight": storage_rpc.get("logSyncHeight"),
                "nextTxSeq": storage_rpc.get("nextTxSeq"),
            },
            "privateComputerModel": private_ai["model"]["id"],
        },
        "protectionLoop": [
            {
                "stage": "observe",
                "description": (
                    "Read node health, public explorer stats, opt-in registrations, and "
                    "rights-cleared reputation signals."
                ),
            },
            {
                "stage": "triage",
                "description": (
                    "Use deterministic ZeroGuard policy first; use 0GM for explanation, "
                    "dedupe, and operator-facing summaries."
                ),
            },
            {
                "stage": "draft",
                "description": (
                    "Create Telegram, email, 0G Storage, or onchain memo drafts with hashes "
                    "and source ids, but do not send."
                ),
            },
            {
                "stage": "approve",
                "description": (
                    "Require opt-in contact records plus explicit operator approval before "
                    "any external message or transaction."
                ),
            },
            {
                "stage": "publish_or_notify",
                "description": (
                    "Prefer public pull-based bulletins and receipts; direct messages are "
                    "only for opted-in peers."
                ),
            },
        ],
        "peerContactModel": {
            "publicPeersExposeContactInfo": False,
            "contactInfoPolicy": (
                "Return contact details only when a peer supplied them through an opt-in "
                "record, a public security contact, or an operator-provided payload."
            ),
            "supportedChannels": [
                "telegram_opt_in_preview",
                "0g_storage_bulletin",
                "onchain_message_hash_draft",
                "email_security_contact_draft",
                "public_status_page_pull",
            ],
        },
        "protectiveProducts": [
            {
                "id": "peer_node_health_bulletin",
                "customer": "0G node operators",
                "whatShips": "A signed, source-cited node risk bulletin peers can pull.",
                "zeroGFit": "Store bulletin payloads on 0G Storage and anchor receipt hashes.",
            },
            {
                "id": "opt_in_operator_digest",
                "customer": "Telegram-first operators",
                "whatShips": "Quiet digests for sync lag, peer drops, reward changes, and risk spikes.",
                "zeroGFit": "0G receipts make every alert explainable after the fact.",
            },
            {
                "id": "attested_ai_risk_review",
                "customer": "Agent and wallet teams",
                "whatShips": "0GM-written explanations over deterministic ZeroGuard verdicts.",
                "zeroGFit": "0G Private Computer provides TEE-backed inference for sensitive cases.",
            },
            {
                "id": "edge_sentinel_mesh",
                "customer": "Home/RV node operators",
                "whatShips": "Raspberry Pis perform lightweight probes and cache evidence locally.",
                "zeroGFit": "Cheap distributed watchers feed the same 0G proof trail.",
            },
        ],
        "automationGates": [
            "No unsolicited Telegram, email, or blockchain messages.",
            "No peer contact enrichment from scraped private data.",
            "No wallet signing, fund movement, or transaction broadcast from the workbench.",
            "Every draft includes a message hash, evidence ids, and delivery disabled by default.",
        ],
        "immediateNext": [
            "Keep the Windows storage node syncing and watch peer count/sync gap.",
            "Use 0G Private Computer only after an API key is configured and prompt-minimized.",
            "Bring rvpi-a online as a read-only sentinel; wait for rvpi-b or Ethernet carrier.",
            "Publish peer-protection drafts as previews first, then add an operator-approved sender.",
        ],
        "safety": _safety(live_network_calls=live),
    }


def build_peer_outreach_preview(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a Telegram/onchain peer message draft without sending or preparing a tx."""

    body = payload or {}
    peer = _dict_value(body.get("peer")) or {
        "id": "0g-storage-peer",
        "network": "0g_mainnet",
    }
    risk = _dict_value(body.get("risk")) or {
        "title": "0G node health review",
        "severity": "review",
        "evidence": ["storage_rpc_status", "public_peer_count", "operator_observation"],
    }
    contact = _dict_value(body.get("contact")) or {}
    channel = str(body.get("channel") or "0g_storage_bulletin").strip()
    opt_in = bool(contact.get("optInConfirmed"))
    can_send_after_review = opt_in and channel in {
        "telegram_opt_in_preview",
        "email_security_contact_draft",
        "0g_storage_bulletin",
        "onchain_message_hash_draft",
    }
    decision = "ready_for_operator_review" if can_send_after_review else "blocked_preview_only"
    blockers = []
    if not opt_in:
        blockers.append("peer_opt_in_not_confirmed")
    if channel not in {
        "telegram_opt_in_preview",
        "email_security_contact_draft",
        "0g_storage_bulletin",
        "onchain_message_hash_draft",
        "public_status_page_pull",
    }:
        blockers.append("unsupported_channel")

    message = _peer_message(peer, risk, channel)
    envelope = {
        "peer": peer,
        "risk": risk,
        "channel": channel,
        "message": message,
        "contact": _public_contact(contact),
        "requiresOperatorApproval": True,
        "sendEnabled": False,
        "transactionPrepared": False,
    }
    return {
        "schema": PEER_OUTREACH_PREVIEW_SCHEMA,
        "generatedAt": _now(),
        "decision": decision,
        "blockedBy": blockers,
        "delivery": "preview_no_send",
        "telegram_send": False,
        "blockchain_broadcast": False,
        "message": message,
        "contactCard": _public_contact(contact),
        "onchainEnvelope": {
            "type": "message_hash_only",
            "recipientAddress": contact.get("evmAddress"),
            "messageHash": "0x" + _sha256_hex(envelope),
            "calldata": None,
            "broadcastEnabled": False,
            "operatorApprovalRequired": True,
        },
        "operatorChecklist": [
            "Confirm peer contact source and opt-in.",
            "Review the exact message body and evidence links.",
            "Choose a delivery channel and rate limit.",
            "Approve in a separate sender or CLI; the workbench cannot send.",
        ],
        "safety": _safety(live_network_calls=False),
    }


def build_pi_mesh_plan(*, status_file: str | None = None) -> dict[str, Any]:
    """Return the Raspberry Pi edge-compute plan for ZeroGuard operations."""

    snapshot = _load_pi_mesh_snapshot(status_file)
    observed_nodes = _pi_observed_nodes(snapshot)
    readiness = _pi_mesh_readiness(snapshot)
    return {
        "schema": PI_MESH_SCHEMA,
        "generatedAt": _now(),
        "mode": "rv_pi_mesh_snapshot_file" if snapshot.get("status") == "loaded" else "lan_snapshot_plus_bootstrap_plan",
        "clusterReady": readiness.get("clusterReady") is True,
        "blockers": readiness.get("blockers") or [],
        "nodes": observed_nodes,
        "snapshot": {
            "status": snapshot.get("status"),
            "generatedAt": snapshot.get("generatedAt"),
            "path": snapshot.get("path"),
            "safe": snapshot.get("safe"),
        },
        "fileStatus": snapshot,
        "observedNodes": observed_nodes,
        "readiness": readiness,
        "distributedComputeRoles": [
            {
                "id": "node_sentinel",
                "runsOn": ["rvpi-a", "rvpi-b"],
                "tasks": [
                    "Probe Windows storage node RPC and public relay reachability.",
                    "Record sync height, peer count, DB growth, and latest public block.",
                    "Write local JSON heartbeat files for ZeroGuard ingestion.",
                ],
            },
            {
                "id": "reputation_worker",
                "runsOn": ["rvpi-a"],
                "tasks": [
                    "Normalize public phishing/reputation feed snippets into derived votes.",
                    "Deduplicate alert candidates before a Telegram or bulletin draft exists.",
                    "Never fetch or store private keys, wallet secrets, or raw paid feeds.",
                ],
            },
            {
                "id": "proof_cache",
                "runsOn": ["rvpi-b"],
                "tasks": [
                    "Cache receipt payload hashes and 0G Storage readback metadata.",
                    "Mirror public-safe bulletins over Ethernet when both Pis are cabled.",
                ],
            },
            {
                "id": "tiny_model_filter",
                "runsOn": ["rvpi-a", "rvpi-b"],
                "tasks": [
                    "Run small local classifiers or heuristics for dedupe only.",
                    "Do not attempt 0GM-35B inference on Pi hardware.",
                    "Send compact context to 0G Private Computer when approved.",
                ],
            },
        ],
        "ethernetTetherPlan": [
            "After cabling, verify `ip -br addr show eth0` reports UP/LOWER_UP on both Pis.",
            "Keep Wi-Fi as the internet gateway; use Ethernet as the private cluster link.",
            "Use static addresses such as 10.77.0.1/24 and 10.77.0.2/24 only after carrier is up.",
            "Do not bridge the Pi Ethernet pair into the LAN until probes and firewall rules are tested.",
        ],
        "bootstrapCommands": [
            "./scripts/rv_pi_mesh_snapshot.py --out content/rv_pi_mesh.local.json",
            "ssh ari@rvpi-a.local 'ip -br addr; python3 ~/zeroguard-pi-sentinel/pi_sentinel.py --once'",
            "ssh ari@rvpi-a.local 'cat ~/zeroguard-pi-sentinel/state/heartbeat.json'",
        ],
        "businessUpside": [
            "A cheap edge mesh lets ZeroGuard sell node-watch coverage without renting more servers.",
            "Pis make the product resilient: if the Mac sleeps, Pi sentinels still collect evidence.",
            "The split is credible: Windows does heavy 0G node work; Pis do watchdog and proof-cache work.",
        ],
        "safety": _safety(live_network_calls=False),
    }


def _load_pi_mesh_snapshot(status_file: str | None) -> dict[str, Any]:
    if not status_file:
        return {"status": "not_requested", "safe": True}
    try:
        with open(status_file, encoding="utf-8") as handle:
            payload = json.load(handle)
    except FileNotFoundError:
        return {"status": "missing", "path": status_file, "safe": True}
    except json.JSONDecodeError as exc:
        return {"status": "invalid_json", "path": status_file, "error": str(exc), "safe": False}
    if payload.get("schema") != PI_MESH_SNAPSHOT_SCHEMA:
        return {
            "status": "schema_mismatch",
            "path": status_file,
            "schema": payload.get("schema"),
            "safe": False,
        }
    safety = payload.get("safety") or {}
    safe = (
        safety.get("readOnly") is True
        and safety.get("privateKeysReturned") is False
        and safety.get("telegramSendsEnabled") is False
    )
    return {"status": "loaded", "path": status_file, "safe": safe, **payload}


def _pi_observed_nodes(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    if snapshot.get("status") == "loaded":
        nodes = snapshot.get("nodes") or {}
        rvpi_a = nodes.get("rvpi-a") or {}
        rvpi_b = nodes.get("rvpi-b") or {}
        return [
            {
                "id": "rvpi-a",
                "host": "rvpi-a.local",
                "lastObservedIpv4": rvpi_a.get("wifiIpv4") or "192.168.1.111",
                "ethernetIpv4": rvpi_a.get("ethernetIpv4"),
                "sshUser": "ari",
                "status": rvpi_a.get("status", "unknown"),
                "eth0": "carrier_ready" if (rvpi_a.get("eth0") or {}).get("carrier") else "carrier_missing",
                "memoryGiB": rvpi_a.get("memoryGiB"),
                "rootDisk": rvpi_a.get("rootDisk"),
                "services": rvpi_a.get("services"),
                "safeRole": rvpi_a.get("safeRole", "sentinel_probe_and_evidence_cache"),
                "sentinelScript": "~/zeroguard-pi-sentinel/pi_sentinel.py",
                "heartbeatPath": "~/zeroguard-pi-sentinel/state/heartbeat.json",
            },
            {
                "id": "rvpi-b",
                "host": "rvpi-b.local",
                "lastObservedIpv4": rvpi_b.get("expectedWifiIpv4"),
                "ethernetIpv4": rvpi_b.get("ethernetIpv4"),
                "status": rvpi_b.get("status", "not_reached"),
                "identityVerified": rvpi_b.get("identityVerified") is True,
                "edgeApiReady": rvpi_b.get("edgeApiReady") is True,
                "tcpFromRvpiA": rvpi_b.get("tcpFromRvpiA"),
                "safeRole": rvpi_b.get("safeRole", "standby_evidence_cache_when_authorized"),
            },
        ]
    return [
        {
            "id": "rvpi-a",
            "host": "rvpi-a.local",
            "lastObservedIpv4": "192.168.1.111",
            "sshUser": "ari",
            "status": "reachable_over_wifi",
            "eth0": "down_until_cable_or_static_config",
            "memoryGiB": 3.7,
            "rootDiskGiB": 116,
            "safeRole": "sentinel_probe_and_evidence_cache",
            "sentinelScript": "~/zeroguard-pi-sentinel/pi_sentinel.py",
            "heartbeatPath": "~/zeroguard-pi-sentinel/state/heartbeat.json",
        },
        {
            "id": "rvpi-b",
            "host": "rvpi-b.local",
            "status": "not_reached_this_run",
            "safeRole": "standby_evidence_cache_when_online",
        },
    ]


def _pi_mesh_readiness(snapshot: dict[str, Any]) -> dict[str, Any]:
    if snapshot.get("status") != "loaded":
        return {
            "status": "snapshot_not_loaded",
            "clusterReady": False,
            "blockers": ["run_rv_pi_mesh_snapshot"],
            "telegramSendsEnabled": False,
        }
    cluster = snapshot.get("cluster") or {}
    blockers = list(cluster.get("blockers") or [])
    return {
        "status": "cluster_ready" if cluster.get("clusterReady") else "cluster_partial",
        "clusterReady": cluster.get("clusterReady") is True,
        "primaryReachable": cluster.get("primaryReachable") is True,
        "ethernetCarrierReady": cluster.get("ethernetCarrierReady") is True,
        "peerEthernetReachable": cluster.get("peerEthernetReachable") is True,
        "peerIdentityVerified": cluster.get("peerIdentityVerified") is True,
        "edgeApiReady": cluster.get("edgeApiReady") is True,
        "blockers": blockers,
        "recommendedAction": cluster.get("recommendedAction"),
        "telegramSendsEnabled": False,
    }


def _router_model_catalog_not_checked() -> dict[str, Any]:
    return {
        "status": "not_checked",
        "networkCallMade": False,
        "modelsUrl": ROUTER_MODELS_URL,
        "preferredModelAvailable": None,
        "preferredModel": None,
        "note": "Call /api/0g/private-computer?live=1 for a no-auth Router model catalog readback.",
    }


def _read_router_model_catalog(*, timeout_seconds: float) -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    try:
        response = requests.get(ROUTER_MODELS_URL, timeout=timeout_seconds)
        response.raise_for_status()
        payload = response.json()
        models = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(models, list):
            raise ValueError("Router /v1/models returned no data list")
        preferred = next(
            (item for item in models if isinstance(item, dict) and item.get("id") == MODEL_ID),
            None,
        )
        return {
            "status": "ok",
            "networkCallMade": True,
            "modelsUrl": ROUTER_MODELS_URL,
            "modelCount": len(models),
            "preferredModelAvailable": preferred is not None,
            "preferredModel": _public_model_fields(preferred) if preferred else None,
            "checkedAt": started.isoformat(),
        }
    except Exception as exc:  # pragma: no cover - live network dependent
        return {
            "status": "degraded",
            "networkCallMade": True,
            "modelsUrl": ROUTER_MODELS_URL,
            "preferredModelAvailable": None,
            "preferredModel": None,
            "error": f"{type(exc).__name__}: {exc}",
            "checkedAt": started.isoformat(),
        }


def _public_model_fields(model: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": model.get("id"),
        "ownedBy": model.get("owned_by"),
        "type": model.get("type"),
        "contextLength": model.get("context_length"),
        "maxCompletionTokens": model.get("max_completion_tokens"),
        "inputModalities": ((model.get("architecture") or {}).get("input_modalities") or []),
        "supportedParameters": model.get("supported_parameters") or [],
        "supportedFormats": model.get("supported_formats") or [],
        "pricingNeuronPerToken": model.get("pricing") or {},
        "pricingUsdPerToken": model.get("pricing_usd") or {},
        "verifiability": model.get("verifiability"),
        "teeAttested": model.get("tee_attested"),
        "teeType": model.get("tee_type"),
        "providerCount": model.get("provider_count"),
    }


def _peer_message(peer: dict[str, Any], risk: dict[str, Any], channel: str) -> str:
    evidence = risk.get("evidence")
    if isinstance(evidence, list):
        evidence_text = ", ".join(str(item) for item in evidence[:4])
    else:
        evidence_text = "operator evidence attached"
    return "\n".join(
        [
            "ZeroGuard peer-protection draft",
            f"Peer: {peer.get('id') or peer.get('address') or 'unknown'}",
            f"Risk: {risk.get('title', 'node risk review')}",
            f"Severity: {risk.get('severity', 'review')}",
            f"Evidence: {evidence_text}",
            f"Proposed channel: {channel}",
            "Action: please review your node health and verify the cited evidence before acting.",
            "Delivery: preview only; no Telegram, email, or blockchain message was sent.",
        ]
    )


def _public_contact(contact: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in {
            "label": contact.get("label"),
            "telegramUsername": contact.get("telegramUsername"),
            "evmAddress": contact.get("evmAddress"),
            "email": contact.get("email"),
            "source": contact.get("source"),
            "optInConfirmed": bool(contact.get("optInConfirmed")),
        }.items()
        if value not in {None, ""}
    }


def _dict_value(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _sha256_hex(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safety(*, live_network_calls: bool) -> dict[str, Any]:
    return {
        "readOnly": True,
        "networkCalls": live_network_calls,
        "privateKeysReturned": False,
        "secretsReturned": False,
        "walletSignaturesEnabled": False,
        "transactionBroadcastingEnabled": False,
        "moneyMovementEnabled": False,
        "telegramSendsEnabled": False,
        "externalMessagesEnabled": False,
        "workbenchCanTriggerLiveActions": False,
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
