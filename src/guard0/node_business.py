"""Read-only 0G node business, economics, and capacity packets."""

from __future__ import annotations

import os
import time
from typing import Any, Callable

import requests

from guard0.da_node import build_storage_node_status

NODE_BUSINESS_SCHEMA = "0guard.0g_node_business.v1"
ALIGNMENT_NODE_STATUS_SCHEMA = "0guard.0g_alignment_node_status.v1"
VALIDATOR_CAPACITY_SCHEMA = "0guard.0g_validator_capacity.v1"
NODE_BUSINESS_TELEGRAM_PREVIEW_SCHEMA = "0guard.telegram_node_business_preview.v1"

ZG_MAINNET_RPC = "https://evmrpc.0g.ai"
ALIGNMENT_GRAPHQL_URL = "https://alignment-node-subgraph.0g.ai/subgraphs/name/alignment-node"
ALIGNMENT_NFT_CONTRACT = "0x18e56e7b120c7CBD06117A36E94E61a932A5A302"
ALIGNMENT_CLAIM_CONTRACT = "0x6a9c6b5507e322aa00eb9c45e80c07ab63acabb6"
ALIGNMENT_MANAGER_CONTRACT = "0x7BDc2aECC3CDaF0ce5a975adeA1C8d84Fd9Be3D9"
STORAGESCAN_STATS_REWARD = "https://storagescan.0g.ai/api/stats/reward"
STORAGESCAN_STATS_MINER = "https://storagescan.0g.ai/api/stats/miner"

DEFAULT_OBSERVED_STORAGE_DAILY_REWARD_OG = 0.09865019747528021
DEFAULT_OBSERVED_STORAGE_ACTIVE_MINERS = 19.5
DEFAULT_OG_USD_REFERENCE = 0.50098
DEFAULT_ALIGNMENT_OWNER_ADDRESSES = (
    "0x885b0892D241Cb5033C9995e09cA521d54f936b5",
    "0xf5c1c3Eb88c262ADb451C1CE3b1c391f7D968ecd",
)

GraphqlReader = Callable[[str, dict[str, Any], float], dict[str, Any]]
StorageEconomicsReader = Callable[[float], dict[str, Any]]


def build_alignment_node_status(
    *,
    live: bool = False,
    owner_addresses: list[str] | None = None,
    token_ids: list[str] | None = None,
    timeout_seconds: float = 5.0,
    graphql_reader: GraphqlReader | None = None,
) -> dict[str, Any]:
    """Build a no-secret Alignment Node license/operator readiness packet."""

    owners = owner_addresses if owner_addresses is not None else _alignment_owner_addresses()
    tokens = token_ids if token_ids is not None else _alignment_token_ids()
    licenses: list[dict[str, Any]] = []
    query_status = "not_checked"
    query_error = None

    if live:
        try:
            licenses = _read_alignment_licenses(
                owners=owners,
                token_ids=tokens,
                timeout_seconds=timeout_seconds,
                graphql_reader=graphql_reader or _graphql_post,
            )
            query_status = "ok"
        except Exception as exc:  # pragma: no cover - live network dependent
            query_status = "degraded"
            query_error = f"{type(exc).__name__}: {exc}"

    blockers: list[str] = []
    if not live:
        blockers.append("alignment_license_not_checked")
    elif query_status != "ok":
        blockers.append("alignment_license_read_failed")
    elif not licenses:
        blockers.append("alignment_license_not_found_for_configured_wallets")
    blockers.append("kyc_and_wallet_signature_required")

    active_licenses = [license for license in licenses if license["isRunning"]]
    return {
        "schema": ALIGNMENT_NODE_STATUS_SCHEMA,
        "generatedAt": _utc_now(),
        "mode": "live_subgraph_read_only" if live else "configured_snapshot",
        "network": {
            "chain": "0G Mainnet",
            "chainId": 16661,
            "rpc": ZG_MAINNET_RPC,
            "subgraph": ALIGNMENT_GRAPHQL_URL,
        },
        "contracts": {
            "nft": ALIGNMENT_NFT_CONTRACT,
            "claim": ALIGNMENT_CLAIM_CONTRACT,
            "alignmentManager": ALIGNMENT_MANAGER_CONTRACT,
        },
        "configuredLookup": {
            "ownerAddresses": owners,
            "tokenIds": tokens,
        },
        "query": {
            "status": query_status,
            "error": query_error,
            "licenseCount": len(licenses),
            "activeLicenseCount": len(active_licenses),
        },
        "licenses": licenses,
        "economics": {
            "minimumTotalPerLicenseOg": 854.7,
            "part1OwnerOnlyOg": 282.05,
            "part2OperatorEligibleOg": 572.65,
            "part2ApproxDailyOg": 0.52,
            "rewardRequiresActiveOperation": True,
            "kycRequiredForClaims": True,
            "source": (
                "https://0g.ai/blog/ai-alignment-node-rewards-distribution-schedule-eligibility"
            ),
        },
        "readiness": {
            "status": "operator_action_required" if blockers else "ready_to_register_operator",
            "blockedBy": blockers,
            "canRunBinary": True,
            "operatorRegistrationReady": not blockers,
            "requiresWalletPrivateKey": True,
            "requiresWalletSignature": True,
            "requiresKyc": True,
            "safeAutonomousNextStep": "stage_binary_only" if blockers else "prepare_operator_review",
        },
        "safety": _safety(live=live),
    }


def build_validator_capacity_status() -> dict[str, Any]:
    """Return the current Windows host validator fit without overclaiming WSL RAM."""

    hardware = {
        "host": os.getenv("ZG_VALIDATOR_HOST", "DESKTOP-HFCK6U9"),
        "motherboard": os.getenv("ZG_VALIDATOR_BOARD", "ASUS ROG STRIX B850-A GAMING WIFI"),
        "cpu": os.getenv("ZG_VALIDATOR_CPU", "AMD Ryzen 9 9900X3D 12-Core Processor"),
        "physicalMemoryBytes": int(os.getenv("ZG_VALIDATOR_PHYSICAL_MEMORY_BYTES", "66203176960")),
        "physicalMemoryGiB": float(os.getenv("ZG_VALIDATOR_PHYSICAL_MEMORY_GIB", "61.66")),
        "wslMemoryLimitGbDecimal": float(os.getenv("ZG_VALIDATOR_WSL_MEMORY_LIMIT_GB", "60")),
        "wslReportedMemoryGiB": float(os.getenv("ZG_VALIDATOR_WSL_MEMORY_GIB", "58")),
        "wslSwapGbDecimal": float(os.getenv("ZG_VALIDATOR_WSL_SWAP_GB", "32")),
        "physicalCores": int(os.getenv("ZG_VALIDATOR_PHYSICAL_CORES", "12")),
        "logicalProcessors": int(os.getenv("ZG_VALIDATOR_LOGICAL_PROCESSORS", "24")),
        "diskFreeTb": float(os.getenv("ZG_VALIDATOR_DISK_FREE_TB", "1.7")),
        "boardMaxMemoryGb": int(os.getenv("ZG_VALIDATOR_BOARD_MAX_MEMORY_GB", "256")),
    }
    requirements = {
        "mainnet": {
            "memoryGb": 64,
            "cpuCores": 8,
            "diskTb": 1,
            "bandwidthMbpsUpDown": 800,
            "source": "https://docs.0g.ai/run-a-node/validator-node",
        },
        "testnet": {
            "memoryGb": 64,
            "cpuCores": 8,
            "diskTb": 4,
            "bandwidthMbpsUpDown": 800,
            "source": "https://docs.0g.ai/run-a-node/validator-node",
        },
    }
    checks = {
        "cpuPass": hardware["physicalCores"] >= requirements["mainnet"]["cpuCores"],
        "mainnetDiskPass": hardware["diskFreeTb"] >= requirements["mainnet"]["diskTb"],
        "testnetDiskPass": hardware["diskFreeTb"] >= requirements["testnet"]["diskTb"],
        "physicalMemoryPass": hardware["physicalMemoryBytes"] >= 64_000_000_000,
        "wslUsableMemoryPass": hardware["wslReportedMemoryGiB"] >= 64,
        "bandwidthVerified": False,
    }
    validator_ready = (
        checks["cpuPass"]
        and checks["mainnetDiskPass"]
        and checks["wslUsableMemoryPass"]
        and checks["bandwidthVerified"]
    )
    return {
        "schema": VALIDATOR_CAPACITY_SCHEMA,
        "generatedAt": _utc_now(),
        "hardware": hardware,
        "requirements": requirements,
        "checks": checks,
        "readiness": {
            "status": "not_recommended_in_wsl" if not validator_ready else "ready_for_operator_review",
            "validatorReady": validator_ready,
            "reason": (
                "CPU and mainnet disk are strong, but WSL exposes about 58 GiB usable RAM "
                "and bandwidth has not been proven at validator grade."
            ),
            "bestCurrentUse": "storage_node_plus_alignment_node_plus_zeroguard_monitoring",
        },
        "workarounds": [
            {
                "id": "bare_metal_linux",
                "label": "Boot bare-metal Linux",
                "impact": "Likeliest way to expose the full installed RAM to validator processes.",
                "tradeoff": "Requires physical/boot access and careful key migration.",
            },
            {
                "id": "ram_upgrade",
                "label": "Install more DDR5",
                "impact": "The board supports up to 256 GB, so 96-128 GB would clear the validator margin.",
                "tradeoff": "Requires hardware purchase and physical access.",
            },
            {
                "id": "cloud_validator",
                "label": "Use a validator VPS",
                "impact": "Meets official 64 GB RAM and bandwidth guidance cleanly.",
                "tradeoff": "Adds monthly hosting cost and operational key management.",
            },
            {
                "id": "keep_current_host_specialized",
                "label": "Keep RV host specialized",
                "impact": "Best ROI today: storage sync, Alignment Node if licensed, ZeroGuard telemetry.",
                "tradeoff": "Does not become a consensus validator until RAM/bandwidth are solved.",
            },
        ],
        "safety": _safety(live=False),
    }


def build_0g_node_business_plan(
    *,
    live: bool = False,
    timeout_seconds: float = 5.0,
    alignment_status: dict[str, Any] | None = None,
    validator_capacity: dict[str, Any] | None = None,
    storage_status: dict[str, Any] | None = None,
    storage_economics_reader: StorageEconomicsReader | None = None,
) -> dict[str, Any]:
    """Build the business-facing node strategy packet for ZeroGuard."""

    alignment = alignment_status or build_alignment_node_status(
        live=live,
        timeout_seconds=timeout_seconds,
    )
    validator = validator_capacity or build_validator_capacity_status()
    storage = storage_status or build_storage_node_status(live=live, timeout_seconds=timeout_seconds)
    storage_economics = _storage_economics(
        live=live,
        timeout_seconds=timeout_seconds,
        reader=storage_economics_reader,
    )
    return {
        "schema": NODE_BUSINESS_SCHEMA,
        "generatedAt": _utc_now(),
        "mode": "live_read_only" if live else "configured_snapshot",
        "valueProposition": (
            "ZeroGuard turns 0G node operations into a verifiable safety and uptime layer: "
            "it watches storage, DA, Alignment, and validator readiness before agents or "
            "operators touch wallets."
        ),
        "lanes": [
            {
                "id": "storage_node",
                "status": (storage.get("readiness") or {}).get("status"),
                "businessRole": "Mainnet proof-of-infrastructure and telemetry source.",
                "monthlyRewardEstimateOg": storage_economics["perActiveMinerMonthlyOg"],
                "currentEconomicQuality": storage_economics["quality"],
                "nextStep": "Keep syncing and surface proofs; do not add large hot-wallet funds yet.",
            },
            {
                "id": "alignment_node",
                "status": (alignment.get("readiness") or {}).get("status"),
                "businessRole": "Highest published passive node reward path if we own a license.",
                "monthlyRewardEstimateOg": round(
                    alignment["economics"]["part2ApproxDailyOg"] * 30,
                    4,
                ),
                "currentEconomicQuality": "license_dependent",
                "nextStep": "Find/verify the wallet or token id holding an Alignment Node license.",
            },
            {
                "id": "validator",
                "status": (validator.get("readiness") or {}).get("status"),
                "businessRole": "Future consensus/reputation lane once RAM and bandwidth are official-grade.",
                "monthlyRewardEstimateOg": None,
                "currentEconomicQuality": "apr_not_confirmed",
                "nextStep": "Use bare-metal Linux, more RAM, or a validator VPS before staking.",
            },
            {
                "id": "zeroguard_product",
                "status": "buildable_now",
                "businessRole": "Sell monitoring, proof receipts, pre-signing policy, and node-readiness reports.",
                "monthlyRewardEstimateOg": None,
                "currentEconomicQuality": "service_revenue_not_protocol_yield",
                "nextStep": "Package node health, wallet-risk preview, and proof receipts as an operator API.",
            },
        ],
        "monetization": [
            "Operator subscription for 0G node health, balance, sync, and proof telemetry.",
            "Pre-signing wallet-risk API for AI agents and Telegram Mini Apps.",
            "0G proof receipt export for hackathon, grant, and customer due-diligence packets.",
            "Managed monitoring for Alignment Node owners who do not want to run full ops.",
        ],
        "currentReadiness": {
            "alignment": alignment["readiness"],
            "validator": validator["readiness"],
            "storage": storage.get("readiness"),
            "storageEconomics": storage_economics,
        },
        "operatorGates": [
            "KYC and wallet signature for Alignment Node claims or delegation.",
            "Proof that the wallet owns an Alignment Node NFT before registering an operator.",
            "No 100 0G storage-miner funding until storage sync and node-originated activity are proven.",
            "No validator staking until RAM/bandwidth are validator-grade and rollback is documented.",
        ],
        "safety": _safety(live=live),
    }


def build_telegram_node_business_preview(
    business_plan: dict[str, Any] | None = None,
    *,
    live: bool = False,
    opt_in_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a Telegram-safe business/node digest without sending it."""

    plan = business_plan or build_0g_node_business_plan(live=live)
    readiness = plan.get("currentReadiness") or {}
    storage_economics = readiness.get("storageEconomics") or {}
    lines = [
        "ZeroGuard 0G node business update",
        f"Storage: {(readiness.get('storage') or {}).get('status', 'unknown')}",
        f"Alignment: {(readiness.get('alignment') or {}).get('status', 'unknown')}",
        f"Validator: {(readiness.get('validator') or {}).get('status', 'unknown')}",
        f"Storage est: {storage_economics.get('perActiveMinerMonthlyOg')} OG/month per active miner",
        "Action: package telemetry and proof receipts; keep signing/funding gated.",
        "Delivery: preview only; no Telegram message was sent.",
    ]
    return {
        "schema": NODE_BUSINESS_TELEGRAM_PREVIEW_SCHEMA,
        "delivery": "preview_no_send",
        "telegram_send": False,
        "network_calls": bool((plan.get("safety") or {}).get("networkCalls")),
        "opt_in_status": (opt_in_record or {}).get("status", "not_attached"),
        "record_id": (opt_in_record or {}).get("record_id"),
        "message": "\n".join(lines),
        "businessPlan": plan,
        "safety": {
            "telegramSendsEnabled": False,
            "workbenchCanSend": False,
            "transactionSigningEnabled": False,
            "moneyMovementEnabled": False,
            "privateKeyRequired": False,
        },
    }


def _read_alignment_licenses(
    *,
    owners: list[str],
    token_ids: list[str],
    timeout_seconds: float,
    graphql_reader: GraphqlReader,
) -> list[dict[str, Any]]:
    filters: list[str] = []
    variables: dict[str, Any] = {}
    if owners:
        variables["owners"] = [owner.lower() for owner in owners]
        filters.append("owner_in: $owners")
    if token_ids:
        variables["tokenIds"] = [str(token_id) for token_id in token_ids]
        filters.append("id_in: $tokenIds")
    if not filters:
        return []
    query = (
        "query($owners: [String!], $tokenIds: [String!]) { "
        f"nfts(first: 100, where: {{ {', '.join(filters)} }}) "
        "{ id owner { id } operator { id } delegatedTime approvedTime "
        "undelegatedTime totalReward lastUpdatedTime } }"
    )
    payload = graphql_reader(query, variables, timeout_seconds)
    raw_licenses = ((payload.get("data") or {}).get("nfts") or []) if isinstance(payload, dict) else []
    return [_normalize_alignment_license(item) for item in raw_licenses if isinstance(item, dict)]


def _normalize_alignment_license(raw: dict[str, Any]) -> dict[str, Any]:
    delegated_time = _int_or_none(raw.get("delegatedTime"))
    approved_time = _int_or_none(raw.get("approvedTime"))
    undelegated_time = _int_or_none(raw.get("undelegatedTime"))
    is_running = (
        undelegated_time is None
        or bool(delegated_time and delegated_time > undelegated_time)
        or bool(approved_time and approved_time > undelegated_time)
    )
    return {
        "tokenId": str(raw.get("id") or ""),
        "owner": ((raw.get("owner") or {}).get("id") if isinstance(raw.get("owner"), dict) else None),
        "operator": (
            (raw.get("operator") or {}).get("id") if isinstance(raw.get("operator"), dict) else None
        ),
        "delegatedTime": delegated_time,
        "approvedTime": approved_time,
        "undelegatedTime": undelegated_time,
        "lastUpdatedTime": _int_or_none(raw.get("lastUpdatedTime")),
        "totalRewardWei": str(raw.get("totalReward") or "0"),
        "totalRewardOg": _wei_to_og(raw.get("totalReward")),
        "isRunning": is_running,
    }


def _storage_economics(
    *,
    live: bool,
    timeout_seconds: float,
    reader: StorageEconomicsReader | None,
) -> dict[str, Any]:
    if live:
        try:
            return (reader or _read_storage_economics)(timeout_seconds)
        except Exception as exc:  # pragma: no cover - live network dependent
            return {
                "status": "degraded",
                "quality": "unavailable",
                "error": f"{type(exc).__name__}: {exc}",
                "perActiveMinerMonthlyOg": None,
            }
    per_day = DEFAULT_OBSERVED_STORAGE_DAILY_REWARD_OG / DEFAULT_OBSERVED_STORAGE_ACTIVE_MINERS
    return {
        "status": "snapshot",
        "quality": "tiny_current_protocol_yield",
        "source": "StorageScan live snapshot captured 2026-05-17",
        "networkDailyRewardOg": DEFAULT_OBSERVED_STORAGE_DAILY_REWARD_OG,
        "activeMiners": DEFAULT_OBSERVED_STORAGE_ACTIVE_MINERS,
        "perActiveMinerDailyOg": round(per_day, 8),
        "perActiveMinerMonthlyOg": round(per_day * 30, 6),
        "perActiveMinerMonthlyUsdReference": round(per_day * 30 * DEFAULT_OG_USD_REFERENCE, 4),
    }


def _read_storage_economics(timeout_seconds: float) -> dict[str, Any]:
    reward = requests.get(
        STORAGESCAN_STATS_REWARD,
        params={"skip": 0, "limit": 7, "intervalType": "day", "sort": "desc"},
        timeout=timeout_seconds,
    )
    miner = requests.get(
        STORAGESCAN_STATS_MINER,
        params={"skip": 0, "limit": 7, "intervalType": "day", "sort": "desc"},
        timeout=timeout_seconds,
    )
    reward.raise_for_status()
    miner.raise_for_status()
    reward_rows = ((reward.json().get("data") or {}).get("list") or [])[1:]
    miner_rows = ((miner.json().get("data") or {}).get("list") or [])[1:]
    daily_rewards = [_wei_to_og(row.get("rewardNew")) for row in reward_rows if row.get("rewardNew")]
    active_miners = [float(row.get("minerActive") or 0) for row in miner_rows if row.get("minerActive")]
    if not daily_rewards or not active_miners:
        raise ValueError("StorageScan returned insufficient reward/miner rows")
    avg_daily_reward = sum(daily_rewards) / len(daily_rewards)
    avg_active_miners = sum(active_miners) / len(active_miners)
    per_day = avg_daily_reward / avg_active_miners if avg_active_miners else 0
    return {
        "status": "ok",
        "quality": "tiny_current_protocol_yield",
        "source": "https://storagescan.0g.ai/",
        "networkDailyRewardOg": round(avg_daily_reward, 8),
        "activeMiners": round(avg_active_miners, 2),
        "perActiveMinerDailyOg": round(per_day, 8),
        "perActiveMinerMonthlyOg": round(per_day * 30, 6),
        "perActiveMinerMonthlyUsdReference": round(per_day * 30 * DEFAULT_OG_USD_REFERENCE, 4),
    }


def _graphql_post(query: str, variables: dict[str, Any], timeout_seconds: float) -> dict[str, Any]:
    response = requests.post(
        ALIGNMENT_GRAPHQL_URL,
        json={"query": query, "variables": variables},
        timeout=timeout_seconds,
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("errors"):
        raise ValueError(payload["errors"])
    return payload


def _alignment_owner_addresses() -> list[str]:
    raw = os.getenv("ZG_ALIGNMENT_OWNER_ADDRESSES", "")
    if raw.strip():
        return [item.strip() for item in raw.split(",") if item.strip()]
    return list(DEFAULT_ALIGNMENT_OWNER_ADDRESSES)


def _alignment_token_ids() -> list[str]:
    raw = os.getenv("ZG_ALIGNMENT_TOKEN_IDS", "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _wei_to_og(value: Any) -> float:
    try:
        return int(value or 0) / 10**18
    except (TypeError, ValueError):
        return 0.0


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safety(*, live: bool) -> dict[str, Any]:
    return {
        "readOnly": True,
        "networkCalls": bool(live),
        "privateKeyRequired": False,
        "privateKeysReturned": False,
        "signingEnabled": False,
        "broadcastingEnabled": False,
        "moneyMovementEnabled": False,
        "telegramSendsEnabled": False,
    }


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
