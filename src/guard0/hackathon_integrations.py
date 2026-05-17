"""Next-hackathon integration plans for 0guard.

The plans in this module are intentionally executable-roadmap surfaces, not
claims that 0guard has already deployed into each ecosystem. They keep the
project 0G-first while making Arbitrum and MetaMask/agent-wallet work concrete
enough for APIs, docs, and judges to inspect.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from guard0.crosschain import cross_chain_catalog
from guard0.external_guardrails import evaluate_external_guardrail
from guard0.native_preflight import build_native_preflight

NEXT_HACKATHON_PLAN_SCHEMA = "0guard.next_hackathon_plan.v1"
ARBITRUM_INTEGRATION_PLAN_SCHEMA = "0guard.arbitrum_integration_plan.v1"
ARBITRUM_OPEN_HOUSE_BUILDATHON_SCHEMA = "0guard.arbitrum_open_house_buildathon_plan.v1"
METAMASK_INTEGRATION_PLAN_SCHEMA = "0guard.metamask_integration_plan.v1"
METAMASK_1SHOT_COOKOFF_SCHEMA = "0guard.metamask_1shot_cookoff_plan.v1"
METAMASK_1SHOT_PERMISSION_PREVIEW_SCHEMA = "0guard.metamask_1shot_permission_preview.v1"


def next_hackathon_plan() -> dict[str, Any]:
    """Return chronological, source-cited hackathon targets and build slices."""
    opportunities = [
        {
            "rank": 1,
            "id": "metamask_smart_accounts_1shot_api_dev_cookoff",
            "name": "MetaMask Smart Accounts Kit x 1Shot API Dev Cook Off",
            "status": "active",
            "timing": {
                "registrationWindow": "2026-05-15 03:00 to 2026-06-15 10:59",
                "submissionWindow": "2026-05-15 03:00 to 2026-06-15 10:59",
                "rewardAnnouncement": "2026-06-22 10:59",
            },
            "primaryTrackFit": "permissioned_agentic_x402",
            "why0guardFits": (
                "0guard can become the permission firewall that evaluates "
                "MetaMask Smart Accounts Kit Advanced Permissions, ERC-7710 "
                "delegations, and 1Shot/x402 payment intents before an agent "
                "requests authority or calls a paid API."
            ),
            "buildNow": [
                "Make MetaMask Smart Accounts Kit the main demo flow, not a footnote.",
                "Use ERC-7715 Advanced Permissions or Smart Accounts Kit delegation in the working video.",
                "Preflight x402 payment requirements, facilitator scope, pay-to address, max amount, and expiry before ERC-7710 redemption.",
                "Show 1Shot API use only when API credentials, server wallet funding, and testnet boundaries are explicit.",
                "Keep 0G as the private inference/proof layer for risk explanations and receipts.",
            ],
            "doNotClaimYet": [
                "No live 1Shot transaction, x402 settlement, or MetaMask signature is performed by this repo state.",
                "No production Snap, wallet custody, or MetaMask partnership is claimed.",
                "No mainnet token transfer is required for the hackathon proof until the exact recipient and action are confirmed.",
            ],
            "officialSources": [
                "https://www.hackquest.io/hackathons/MetaMask-Smart-Accounts-Kit-x-1Shot-API-Dev-Cook-Off",
                "https://docs.metamask.io/smart-accounts-kit/guides/advanced-permissions/execute-on-metamask-users-behalf/",
                "https://docs.metamask.io/smart-accounts-kit/guides/x402/overview/",
                "https://docs.metamask.io/smart-accounts-kit/guides/x402/buyer/delegations/",
                "https://docs.metamask.io/smart-accounts-kit/guides/x402/seller/",
                "https://docs.1shotapi.com/x402/index.html",
                "https://docs.1shotapi.com/api/api.html",
                "https://0g.ai/blog/0gm-1-0-35b-a3b",
            ],
        },
        {
            "rank": 2,
            "id": "arbitrum_open_house_london_online_buildathon",
            "name": "Arbitrum Open House London Online Buildathon",
            "status": "active",
            "timing": {
                "registrationDeadline": "2026-05-25",
                "submissionDeadline": "2026-06-14",
                "rewardAnnouncement": "2026-06-17",
            },
            "primaryTrackFit": "agentic_wallet_and_l2_security",
            "why0guardFits": (
                "0guard can become an Arbitrum Agent Safety Pack: pre-signer "
                "intent review, simulation-ready verdict receipts, and L2 config "
                "guardrails before upgrades, retryables, Stylus deploys, or Orbit "
                "admin actions reach a wallet."
            ),
            "buildNow": [
                "Expose Arbitrum One, Nova, and Sepolia as read-only catalog targets.",
                "Review Arbitrum intents through native-preflight before any deploy/admin wallet prompt.",
                "Use Arbitrum Sepolia for proof-contract demos; keep 0G as the durable receipt/provenance anchor.",
            ],
            "doNotClaimYet": [
                "No live Arbitrum deployment is performed by these routes.",
                "No Robinhood Chain chain id or RPC is included until official docs are re-read.",
                "No bridge, deposit, withdrawal, or sequencer endpoint is called by 0guard.",
            ],
            "officialSources": [
                "https://www.hackquest.io/hackathons/Arbitrum-Open-House-London-Online-Buildathon",
                "https://openhouse.arbitrum.io/",
                "https://docs.arbitrum.io/build-decentralized-apps/reference/node-providers",
                "https://docs.arbitrum.io/stylus/quickstart",
            ],
        },
        {
            "rank": 3,
            "id": "ethglobal_new_york_2026_metamask_wallet_security",
            "name": "ETHGlobal New York 2026 / MetaMask wallet-safety lane",
            "status": "upcoming",
            "timing": {
                "eventDates": "2026-06-12 to 2026-06-14",
            },
            "primaryTrackFit": "wallet_security_and_agent_permissions",
            "why0guardFits": (
                "The MetaMask lane should be a wrapper/Snap concept that gates "
                "transactions, typed-data signatures, and delegation permissions "
                "through 0guard before MetaMask is invoked."
            ),
            "buildNow": [
                "Add a MetaMask Connect wrapper example around eth_sendTransaction and signTypedData.",
                "Design a Snap transaction/signature-insights handoff that displays 0guard receipts.",
                "Inspect Smart Accounts Kit advanced-permission caveats before a delegated execution runs.",
            ],
            "doNotClaimYet": [
                "0guard is not a wallet, custodian, or MetaMask partner.",
                "No extension/Snap publishing occurs without operator review.",
                "No delegated execution is redeemed by the repo.",
            ],
            "officialSources": [
                "https://ethglobal.com/events/newyork2026",
                "https://docs.metamask.io/metamask-connect/",
                "https://docs.metamask.io/snaps/features/transaction-insights/",
                "https://docs.metamask.io/snaps/features/signature-insights/",
                "https://docs.metamask.io/smart-accounts-kit/",
            ],
        },
        {
            "rank": 4,
            "id": "nanda_hack_ai_agent_trust",
            "name": "NANDA Hack / AI-agent trust and safety lane",
            "status": "upcoming",
            "timing": {
                "challengeDeadline": "2026-06-13",
                "liveEventDate": "2026-07-11",
            },
            "primaryTrackFit": "agent_identity_reputation_and_verifiable_safety",
            "why0guardFits": (
                "0guard can be framed as a verifiable guardrail that agent "
                "frameworks call before accepting wallet, payment, or signing tasks."
            ),
            "buildNow": [
                "Turn native-preflight into a tiny agent middleware recipe.",
                "Return receipts, source ids, and expiration/TTL so agents can explain decisions.",
                "Keep unsafe actions blocked outside the agent runtime rather than hidden in prompts.",
            ],
            "doNotClaimYet": [
                "No autonomous agent is allowed to sign or move assets.",
                "No identity/reputation claim is made without source-backed evidence.",
            ],
            "officialSources": [
                "https://nandahack.media.mit.edu/",
                "https://eips.ethereum.org/EIPS/eip-8004",
            ],
        },
    ]
    return {
        "schema": NEXT_HACKATHON_PLAN_SCHEMA,
        "generatedAt": _now(),
        "guidingPrinciple": "0G-first receipts, native-chain context, no bridge-first product story.",
        "sourceCheckedAt": "2026-05-16",
        "opportunityCount": len(opportunities),
        "opportunities": opportunities,
        "oodaLoop": {
            "observe": "Read live source/data readiness, chain heads, and adapter evidence.",
            "orient": "Map the action to the native ecosystem: 0G, Arbitrum, MetaMask, TON, or agent framework.",
            "decide": "Return allow/review/deny with cited evidence, TTL, and receipt hash.",
            "act": "Only the caller proceeds; 0guard itself never signs, broadcasts, posts, bridges, or settles.",
        },
        "nextShipSequence": [
            "Add real polling snapshots before any websocket/SSE promise.",
            "Land Arbitrum read-only profiles and intent guardrails.",
            "Land MetaMask wrapper/Snap architecture and delegation caveat checks.",
            "Only then add richer live connectors behind credentials and explicit retention terms.",
        ],
        "safety": _safety(),
    }


def arbitrum_integration_plan() -> dict[str, Any]:
    """Return the Arbitrum-specific safe build plan."""
    catalog = cross_chain_catalog()
    targets = [
        target
        for target in catalog["targets"]
        if str(target.get("id", "")).startswith("arbitrum_")
    ]
    return {
        "schema": ARBITRUM_INTEGRATION_PLAN_SCHEMA,
        "generatedAt": _now(),
        "positioning": "Arbitrum Agent Safety Pack for pre-signer L2 and Orbit/Stylus operations.",
        "networks": targets,
        "routeMap": [
            {
                "path": "/api/integrations/arbitrum",
                "mode": "plan_and_catalog",
                "sideEffects": False,
            },
            {
                "path": "/api/integrations/cross-chain/readiness?live=1&include_non_default=1",
                "mode": "optional_read_only_rpc_heads",
                "sideEffects": False,
            },
            {
                "path": "/api/native-preflight",
                "mode": "pre_signer_intent_review",
                "examplePayload": {
                    "surface": "arbitrum_sepolia",
                    "operation": "upgrade_proxy",
                    "chain": "eip155:421614",
                    "config": {"nativePreflightReceipt": "required_before_wallet_prompt"},
                },
            },
            {
                "path": "/api/integrations/external-guardrails/evaluate",
                "mode": "arbitrum_config_and_action_review",
                "examplePayload": {
                    "target_id": "arbitrum_orbit",
                    "action": "update_dac_config",
                    "config": {"liveTransaction": True},
                },
            },
        ],
        "riskRules": {
            "deny": [
                "private key, mnemonic, signed transaction blob, or eth_sendRawTransaction request",
                "bridge, deposit, withdrawal, or retryable execution as an autonomous side effect",
                "sequencer endpoint mutation or Orbit chain-owner/DAC mutation without operator review",
            ],
            "review": [
                "retryable tickets, sendTxToL1, proxy upgrades, role grants, Stylus deploy/activation, Orbit config changes",
                "Arbiscan/Etherscan keyed enrichment before API terms and cache TTL are configured",
            ],
            "allow": [
                "eth_chainId, eth_blockNumber, eth_call, eth_estimateGas, eth_getCode, eth_getBalance, transaction receipt lookup",
                "read-only explorer links, derived receipt summaries, and 0G proof-root context",
            ],
        },
        "demoPath": [
            "Read Arbitrum Sepolia chain head.",
            "Submit a risky approval/upgrade intent to native-preflight.",
            "Show 0guard review/deny receipt and 0G proof context.",
            "Only after operator approval, manually deploy or verify an Arbitrum Sepolia proof contract if needed for the hackathon.",
        ],
        "officialSources": [
            "https://docs.arbitrum.io/build-decentralized-apps/reference/node-providers",
            "https://docs.arbitrum.io/build-decentralized-apps/how-to-estimate-gas",
            "https://docs.arbitrum.io/build-decentralized-apps/nodeinterface/reference",
            "https://docs.arbitrum.io/stylus/quickstart",
            "https://docs.arbitrum.io/launch-arbitrum-chain/arbitrum-chain-sdk-introduction",
        ],
        "safety": _safety(),
    }


def arbitrum_open_house_buildathon_plan() -> dict[str, Any]:
    """Return the active Arbitrum Open House London submission plan."""
    return {
        "schema": ARBITRUM_OPEN_HOUSE_BUILDATHON_SCHEMA,
        "generatedAt": _now(),
        "sourceCheckedAt": "2026-05-17",
        "name": "ZeroGuard Arbitrum Agent Safety Pack",
        "positioning": (
            "A deployed Arbitrum proof lane for agent-wallet risk receipts: "
            "ZeroGuard preflights the action offchain, then writes or verifies "
            "a compact policy receipt on Arbitrum Sepolia, Arbitrum One, "
            "Robinhood Chain, or another qualifying Arbitrum chain."
        ),
        "hackathon": {
            "host": "Arbitrum Foundation",
            "mode": "online",
            "registrationWindow": "2026-03-24 16:54 to 2026-05-25 15:54",
            "submissionWindow": "2026-03-24 16:54 to 2026-06-14 16:00",
            "rewardAnnouncement": "2026-06-17 15:54",
            "techStack": ["Solidity", "Rust", "Stylus", "Orbit"],
            "participantsSeenOnSource": "331+",
            "prizePoolUsd": 115000,
            "targetTracks": [
                {
                    "id": "overall_prize",
                    "amountUsdc": 70000,
                    "breakdown": {"first": 40000, "second": 20000, "third": 10000},
                    "fit": "stretch",
                },
                {
                    "id": "best_agentic_project",
                    "amountUsdc": 15000,
                    "breakdown": {"first": 7000, "second": 5000, "third": 3000},
                    "fit": "primary",
                },
                {
                    "id": "follow_on_grants",
                    "amountUsdc": 30000,
                    "fit": "operator_follow_up",
                },
            ],
        },
        "qualification": {
            "mustDeployOnArbitrumChain": True,
            "eligibleChains": [
                "Arbitrum Sepolia",
                "Arbitrum One",
                "Robinhood Chain",
                "custom Orbit chain",
            ],
            "judgingCriteria": [
                "smart contract quality",
                "product-market fit",
                "innovation and creativity",
                "real problem solving",
            ],
            "strategicNote": "At least one overall prize is reserved for Robinhood Chain and at least one for Arbitrum according to the HackQuest page.",
        },
        "buildNow": [
            "Ship a tiny Solidity receipt registry on Arbitrum Sepolia first.",
            "Write one receipt hash from /api/native-preflight for a denied or reviewed agent wallet action.",
            "Read the receipt back into the ZeroGuard workbench and docs.",
            "Keep the MetaMask x 1Shot permission firewall as the product story, then use Arbitrum as the deployable proof contract lane.",
            "Add a Stylus/Rust verifier only if Solidity proof is already green.",
        ],
        "contractScope": {
            "minimumViableContract": "PolicyReceiptRegistry",
            "stores": ["receiptHash", "decision", "surface", "createdAt", "operator"],
            "doesNotStore": [
                "private keys",
                "raw prompts",
                "raw exploit payloads",
                "Telegram identifiers",
                "personal data",
            ],
            "securityPosture": [
                "append-only receipt events",
                "small audited surface",
                "OpenZeppelin Ownable or AccessControl only if admin mutation is needed",
                "no custody, token transfer, bridge, swap, or signer logic",
            ],
        },
        "demoFlow": [
            "Run an agent-wallet or permission request through /api/native-preflight.",
            "Show the allow/review/deny receipt and why it was produced.",
            "Anchor the compact receipt hash on Arbitrum Sepolia.",
            "Read back the explorer transaction and contract event.",
            "Use the same receipt inside the MetaMask x 1Shot demo as proof that the permission firewall is portable.",
        ],
        "operatorGates": [
            "Do not deploy until the exact contract source, chain, deployer address, gas estimate, and rollback note are reviewed.",
            "Use testnet first; mainnet Arbitrum One is optional only after the Sepolia proof is green.",
            "Robinhood Chain is attractive but should not be claimed until its live docs/RPC/faucet path is verified.",
        ],
        "officialSources": [
            "https://www.hackquest.io/hackathons/Arbitrum-Open-House-London-Online-Buildathon",
            "https://docs.arbitrum.io/welcome/get-started",
            "https://docs.arbitrum.io/for-devs/quickstart-solidity-hardhat",
            "https://docs.arbitrum.io/stylus/quickstart",
            "https://docs.robinhood.com/",
            "https://bridge.arbitrum.io/",
        ],
        "safety": _safety(),
    }


def metamask_integration_plan() -> dict[str, Any]:
    """Return the MetaMask/agent-wallet integration plan."""
    return {
        "schema": METAMASK_INTEGRATION_PLAN_SCHEMA,
        "generatedAt": _now(),
        "positioning": (
            "0guard is a pre-signer guard for MetaMask-connected dapps and "
            "agent wallets; it is not a wallet, custodian, Snap publisher, or "
            "delegation redeemer in this repo state."
        ),
        "integrationLayers": [
            {
                "id": "connect_wrapper",
                "status": "build_next",
                "whereItRuns": "dapp or agent frontend before window.ethereum.request",
                "gatedMethods": [
                    "eth_sendTransaction",
                    "personal_sign",
                    "eth_signTypedData_v4",
                    "wallet_requestPermissions",
                ],
                "guardRoute": "/api/native-preflight",
                "value": "Blocks or explains risky prompts before the wallet UI appears.",
            },
            {
                "id": "snap_transaction_signature_insights",
                "status": "architecture_ready_operator_review_required",
                "whereItRuns": "MetaMask Snaps insights surfaces",
                "guardRoute": "/api/native-preflight",
                "value": "Show source-cited 0guard verdicts inside transaction and signature reviews.",
            },
            {
                "id": "smart_accounts_advanced_permissions",
                "status": "docs_verified_design_lane",
                "whereItRuns": "Smart Accounts Kit / Delegation Toolkit permission grants and delegated execution",
                "gatedMethods": [
                    "requestExecutionPermissions",
                    "sendTransactionWithDelegation",
                    "sendUserOperationWithDelegation",
                ],
                "guardRoute": "/api/integrations/external-guardrails/evaluate",
                "value": "Reject unbounded delegated authority; require expiry, max spend, caveats, and a 0guard receipt before execution.",
            },
        ],
        "minimumControls": [
            "Every spending or delegation request needs expiry and scoped max amount.",
            "Every execution must carry a native-preflight receipt hash before wallet prompt.",
            "Raw typed-data and transaction payloads are hashed/redacted in public artifacts.",
            "Publishing a Snap or extension is operator-only after manual review.",
        ],
        "agentFit": [
            "Agents can ask 0guard for a verdict before proposing a wallet action.",
            "Receipts give users a compact reason without trusting an LLM explanation alone.",
            "Delegated authority can be bounded by source-cited policy instead of broad unlimited approvals.",
        ],
        "officialSources": [
            "https://docs.metamask.io/metamask-connect/",
            "https://docs.metamask.io/metamask-connect/evm/reference/json-rpc-api/",
            "https://docs.metamask.io/snaps/features/transaction-insights/",
            "https://docs.metamask.io/snaps/features/signature-insights/",
            "https://docs.metamask.io/smart-accounts-kit/",
            "https://docs.metamask.io/smart-accounts-kit/get-started/supported-advanced-permissions/",
        ],
        "safety": _safety(),
    }


def metamask_1shot_cookoff_plan() -> dict[str, Any]:
    """Return the active MetaMask x 1Shot hackathon build plan."""
    return {
        "schema": METAMASK_1SHOT_COOKOFF_SCHEMA,
        "generatedAt": _now(),
        "sourceCheckedAt": "2026-05-17",
        "name": "ZeroGuard Permission Firewall for MetaMask Smart Accounts + 1Shot Agents",
        "positioning": (
            "A no-custody agent-wallet guard that checks Advanced Permissions, "
            "ERC-7710 delegation payments, and 1Shot/x402 automation before "
            "a user grants authority or an agent calls a paid onchain API."
        ),
        "hackathon": {
            "host": "MetaMask Developer",
            "mode": "online",
            "registrationWindow": "2026-05-15 03:00 to 2026-06-15 10:59",
            "submissionWindow": "2026-05-15 03:00 to 2026-06-15 10:59",
            "rewardAnnouncement": "2026-06-22 10:59",
            "prizePoolUsd": 10000,
            "targetTracks": [
                {
                    "id": "best_x402_erc7710",
                    "amountUsd": 3000,
                    "fit": "primary",
                    "requiredProof": "Use MetaMask Smart Accounts or Advanced Permissions to do x402 calls using ERC-7710.",
                },
                {
                    "id": "best_agent",
                    "amountUsd": 3000,
                    "fit": "primary",
                    "requiredProof": "Main flow uses Smart Accounts Kit and shows useful agent behavior.",
                },
                {
                    "id": "best_a2a_coordination",
                    "amountUsd": 3000,
                    "fit": "stretch",
                    "requiredProof": "Redelegation or agent-to-agent handoff with scoped permissions.",
                },
            ],
        },
        "mainDemoFlow": [
            "User connects MetaMask and views a paid ZeroGuard threat-packet API request.",
            "The app receives x402 payment requirements with ERC-7710 delegation metadata.",
            "ZeroGuard preflights pay-to, facilitator, asset, max amount, expiry, resource hash, and requested agent scope.",
            "Only a bounded Smart Accounts Kit Advanced Permission or Smart Account delegation reaches MetaMask.",
            "A 1Shot-backed relay/payment step is shown in testnet or explicitly marked prepared-not-live until credentials are configured.",
            "0G Private Computer generates the private risk explanation and ZeroGuard emits a receipt hash.",
        ],
        "whyThisIsBetterThanSubmissionOne": [
            "Start from sponsor requirements and one main video path instead of a broad ecosystem tour.",
            "Make the judged integration visible in the first minute: Smart Accounts Kit before wallet authority.",
            "Use 0G as proof and sealed-inference infrastructure, not a competing narrative.",
            "Expose deterministic API evidence that judges can curl before watching the video.",
            "Keep every unsafe action testnet, preview-only, or explicitly operator-gated.",
        ],
        "routeMap": [
            {"method": "GET", "path": "/api/hackathons/metamask-1shot", "mode": "active_plan"},
            {
                "method": "GET/POST",
                "path": "/api/hackathons/metamask-1shot/permission-preview",
                "mode": "no_sign_no_settle_demo_packet",
            },
            {"method": "POST", "path": "/api/native-preflight", "mode": "shared_pre_signer_guard"},
            {
                "method": "POST",
                "path": "/api/integrations/external-guardrails/evaluate",
                "mode": "metamask_x402_guardrail_checks",
            },
        ],
        "0gIntegration": {
            "privateComputer": "Use 0GM-1.0-35B-A3B for private natural-language risk explanations once the pc.0g.ai API key and funding are configured.",
            "storageNode": "Keep the current 0G storage node as a proof and telemetry backdrop; it is not the payment wallet.",
            "proofReceipt": "Hash every permission preview and optionally anchor/upload after operator approval.",
        },
        "fundingGate": {
            "send25OgNow": False,
            "recommendedTarget": "The wallet/account actually connected to pc.0g.ai or the 0G Private Computer funding flow, not the storage miner.",
            "reason": "0G Compute/Private Computer token spend belongs with the provider/app account. Miner funding is separate node operations capital.",
            "confirmationNeeded": "Confirm the exact 0G recipient address and purpose before any 25 0G transfer is broadcast.",
        },
        "officialSources": [
            "https://www.hackquest.io/hackathons/MetaMask-Smart-Accounts-Kit-x-1Shot-API-Dev-Cook-Off",
            "https://docs.metamask.io/smart-accounts-kit/guides/x402/overview/",
            "https://docs.metamask.io/smart-accounts-kit/guides/x402/buyer/delegations/",
            "https://docs.metamask.io/smart-accounts-kit/guides/advanced-permissions/execute-on-metamask-users-behalf/",
            "https://docs.1shotapi.com/x402/index.html",
            "https://docs.1shotapi.com/",
            "https://0g.ai/blog/0gm-1-0-35b-a3b",
        ],
        "safety": _safety(),
    }


def metamask_1shot_permission_preview(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a deterministic no-sign preview for the cook-off main flow."""
    body = payload or {}
    if not isinstance(body, dict):
        raise ValueError("payload must be an object")

    network = str(body.get("network") or body.get("chain") or "eip155:84532")
    chain_id = _chain_id(network) or 84532
    token_address = str(body.get("tokenAddress") or "0x0000000000000000000000000000000000000000")
    pay_to = str(body.get("payTo") or "0x1111111111111111111111111111111111111111")
    facilitator = str(body.get("facilitator") or "0x2222222222222222222222222222222222222222")
    session_account = str(body.get("sessionAccount") or "0x3333333333333333333333333333333333333333")
    delegator = str(body.get("delegator") or "0x4444444444444444444444444444444444444444")
    resource = str(body.get("resource") or "GET /api/threat-packets/permission-risk")
    price = str(body.get("price") or "$0.01")
    max_amount = str(body.get("maxAmount") or "10000")
    expiry = int(body.get("expiry") or 1_783_987_200)  # 2026-07-15T00:00:00Z.
    live_settlement = _truthy(body.get("liveSettlement"))

    content_hash = _hash_json(
        {
            "resource": resource,
            "network": network,
            "payTo": pay_to,
            "maxAmount": max_amount,
            "purpose": "zeroguard permission-risk packet",
        }
    )
    nonce = _hash_json({"resource": resource, "delegator": delegator, "network": network})[:24]
    provisional_receipt = f"preview:{content_hash[:16]}"

    permission_request = {
        "standard": "erc7715_advanced_permissions",
        "kitAction": "walletClient.requestExecutionPermissions",
        "chainId": chain_id,
        "expiry": expiry,
        "to": session_account,
        "permission": {
            "type": "erc20-token-periodic",
            "data": {
                "tokenAddress": token_address,
                "periodAmount": max_amount,
                "periodDuration": 86400,
                "justification": "Allow a ZeroGuard agent to pay bounded x402 threat-packet API fees.",
            },
        },
    }
    x402_requirement = {
        "scheme": "exact",
        "network": network,
        "price": price,
        "amount": max_amount,
        "asset": token_address,
        "payTo": pay_to,
        "resource": resource,
        "contentHash": content_hash,
        "nonce": nonce,
        "extra": {
            "assetTransferMethod": "erc7710",
            "facilitators": [facilitator],
        },
    }
    delegation_payload_shape = {
        "x402Version": 2,
        "accepted": x402_requirement,
        "payload": {
            "delegationManager": "0x5555555555555555555555555555555555555555",
            "permissionContext": "0x<encoded-delegation-chain>",
            "delegator": delegator,
        },
    }

    bounded_preflight = build_native_preflight(
        {
            "surface": "metamask_smart_accounts",
            "operation": "requestExecutionPermissions",
            "chain": network,
            "target": pay_to,
            "valueEth": 0,
            "intentText": "Bounded MetaMask Advanced Permission for ERC-7710 x402 threat-packet payments.",
            "config": {
                "method": "requestExecutionPermissions",
                "expiry": expiry,
                "maxAmount": max_amount,
                "nativePreflightReceipt": provisional_receipt,
                "chain": network,
            },
        }
    )
    delegation_execution_preflight = build_native_preflight(
        {
            "surface": "metamask_delegation",
            "operation": "sendTransactionWithDelegation",
            "chain": network,
            "target": pay_to,
            "valueEth": 0,
            "intentText": "Redeem an ERC-7710 delegation for one x402 API payment after ZeroGuard review.",
            "config": {
                "method": "sendTransactionWithDelegation",
                "expiry": expiry,
                "maxAmount": max_amount,
                "nativePreflightReceipt": bounded_preflight["receipt"]["hash"],
                "chain": network,
            },
        }
    )
    unsafe_variant = build_native_preflight(
        {
            "surface": "metamask_delegation",
            "operation": "requestExecutionPermissions",
            "chain": network,
            "target": pay_to,
            "intentText": "Unsafe agent asks for unbounded delegation without expiry or 0guard receipt.",
            "config": {"method": "requestExecutionPermissions"},
        }
    )
    x402_guardrail = evaluate_external_guardrail(
        {
            "target_id": "x402",
            "action": "settle" if live_settlement else "prepare_payment",
            "intent_text": "Use 1Shot/x402 for a paid ZeroGuard threat-packet API call.",
            "config": {
                "networkId": network,
                "token": token_address,
                "amount": max_amount,
                "payTo": pay_to,
                "contentHash": content_hash,
                "nonce": nonce,
                "liveSettlement": live_settlement,
                "rawPayloadResale": False,
            },
        }
    )

    packet = {
        "schema": METAMASK_1SHOT_PERMISSION_PREVIEW_SCHEMA,
        "generatedAt": _now(),
        "mode": "no_sign_no_settle_preview",
        "hackathonTrack": "best_x402_erc7710",
        "network": network,
        "metaMask": {
            "usesSmartAccountsKit": True,
            "standards": ["ERC-7715", "ERC-7710"],
            "permissionRequest": permission_request,
            "delegationPayloadShape": delegation_payload_shape,
        },
        "oneShot": {
            "mode": "prepared_not_live",
            "requires": [
                "1Shot API account",
                "API key and secret stored outside repo",
                "server wallet provisioned and funded with gas on the target network",
                "x402-compatible token method imported, such as transferWithAuthorization",
            ],
            "x402Requirement": x402_requirement,
            "guardrail": x402_guardrail,
        },
        "zeroGuard": {
            "boundedPermissionPreflight": bounded_preflight,
            "delegationExecutionPreflight": delegation_execution_preflight,
            "unsafeVariantPreflight": unsafe_variant,
            "receiptHash": _hash_json(
                {
                    "permissionRequest": permission_request,
                    "x402Requirement": x402_requirement,
                    "boundedReceipt": bounded_preflight["receipt"]["hash"],
                    "delegationReceipt": delegation_execution_preflight["receipt"]["hash"],
                }
            ),
        },
        "demoAssertions": [
            "The app can prove a bounded permission path before asking MetaMask.",
            "The app can deny an unbounded delegation request deterministically.",
            "The 1Shot/x402 leg is prepared and source-cited but not settled unless liveSettlement is explicitly enabled by an operator.",
        ],
        "safety": _safety(),
    }
    packet["safety"]["x402SettlementEnabled"] = live_settlement
    return packet


def _safety() -> dict[str, bool]:
    return {
        "readOnly": True,
        "transactionSigningEnabled": False,
        "broadcastingEnabled": False,
        "bridgingEnabled": False,
        "swappingEnabled": False,
        "moneyMovementEnabled": False,
        "externalAgentLaunchEnabled": False,
        "socialPostingEnabled": False,
        "rawPayloadsReturned": False,
    }


def _chain_id(network: str) -> int:
    if network.startswith("eip155:"):
        try:
            return int(network.split(":", 1)[1])
        except ValueError:
            return 0
    return 0


def _hash_json(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "enabled"}
    return bool(value)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
