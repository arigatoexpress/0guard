"""Read-only peer protection, 0G Private Computer, and Pi mesh plans."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any

from guard0.da_node import build_storage_node_status

PRIVATE_COMPUTER_SCHEMA = "0guard.0g_private_computer_integration.v1"
PEER_PROTECTION_SCHEMA = "0guard.peer_protection_plan.v1"
PEER_OUTREACH_PREVIEW_SCHEMA = "0guard.peer_outreach_preview.v1"
PI_MESH_SCHEMA = "0guard.pi_mesh_plan.v1"

MODEL_ID = "0GM-1.0-35B-A3B"
MODEL_HF_REPO = "0G-AI/0GM-1.0-35B-A3B-0427"
ROUTER_BASE_URL = "https://router-api.0g.ai/v1"
CHAT_COMPLETIONS_URL = f"{ROUTER_BASE_URL}/chat/completions"
MODEL_URL = "https://pc.0g.ai/models/0GM-1.0-35B-A3B"
API_REFERENCE_URL = "https://pc.0g.ai/api-reference/0GM-1.0-35B-A3B"
MODEL_BLOG_URL = "https://0g.ai/blog/0gm-1-0-35b-a3b"
PRIVATE_COMPUTER_BLOG_URL = "https://0g.ai/blog/0g-private-computer"


def build_0g_private_computer_integration() -> dict[str, Any]:
    """Return the current 0G model integration posture without calling paid inference."""

    api_key_configured = bool(os.getenv("ZG_0G_PC_API_KEY") or os.getenv("ZERO_G_API_KEY"))
    return {
        "schema": PRIVATE_COMPUTER_SCHEMA,
        "generatedAt": _now(),
        "mode": "capability_manifest_no_inference_call",
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
            "routerBaseUrl": ROUTER_BASE_URL,
            "chatCompletionsUrl": CHAT_COMPLETIONS_URL,
            "modelUrl": MODEL_URL,
            "apiReferenceUrl": API_REFERENCE_URL,
            "apiKeyConfigured": api_key_configured,
            "apiKeyEnv": ["ZG_0G_PC_API_KEY", "ZERO_G_API_KEY"],
            "sampleRequest": {
                "model": MODEL_ID,
                "messages": [{"role": "user", "content": "Summarize this risk packet."}],
                "verify_tee": True,
                "stream": False,
            },
        },
        "currentPublishedPricing": {
            "routerReadbackOgPerMillionInput": 0.3100,
            "routerReadbackOgPerMillionOutput": 1.9100,
            "blogUsdPerMillionInput": 0.16,
            "blogUsdPerMillionOutput": 0.96,
            "blogUsdPerMillionCache": 0.05,
            "pricingCanDrift": True,
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
            "Do not call paid inference unless an operator-configured API key is present.",
            "Require verify_tee=true for production risk-review calls when the provider supports it.",
            "Keep model output advisory; policy decisions still come from deterministic guard code.",
        ],
        "sources": [
            MODEL_BLOG_URL,
            API_REFERENCE_URL,
            PRIVATE_COMPUTER_BLOG_URL,
        ],
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


def build_pi_mesh_plan() -> dict[str, Any]:
    """Return the Raspberry Pi edge-compute plan for ZeroGuard operations."""

    return {
        "schema": PI_MESH_SCHEMA,
        "generatedAt": _now(),
        "mode": "lan_snapshot_plus_bootstrap_plan",
        "observedNodes": [
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
        ],
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
