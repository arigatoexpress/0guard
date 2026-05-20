"""Public-safe 0G storage-node and Pi mesh readiness proof rail.

This module verifies a recorded operator snapshot. It does not SSH, probe the
LAN, restart services, sign, broadcast, move funds, or read secrets.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

NODE_PI_READINESS_PROOF_SCHEMA = "0guard.node_pi_readiness_proof.v1"
NODE_PI_READINESS_PROOF_STATUS_SCHEMA = "0guard.node_pi_readiness_proof_status.v1"
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_NODE_PI_READINESS_PROOF_PATH = (
    REPO_ROOT / "docs" / "hackathon-0g" / "node-pi-readiness-proof.json"
)


def build_node_pi_readiness_proof_status(
    proof_path: str | Path | None = DEFAULT_NODE_PI_READINESS_PROOF_PATH,
) -> dict[str, Any]:
    """Return public-safe verification status for recorded node/Pi evidence."""

    return verify_node_pi_readiness_proof(
        _load_proof(proof_path) if proof_path else None,
        proof_path=proof_path,
    )


def verify_node_pi_readiness_proof(
    proof: dict[str, Any] | None,
    *,
    proof_path: str | Path | None = None,
) -> dict[str, Any]:
    """Validate a redacted 0G storage-node and Pi mesh readiness proof."""

    if not isinstance(proof, dict):
        return _missing_status("node_pi_readiness_proof_file_missing", proof_path=proof_path)

    storage = proof.get("storageNode") if isinstance(proof.get("storageNode"), dict) else {}
    peer = proof.get("peerDiagnostics") if isinstance(proof.get("peerDiagnostics"), dict) else {}
    pi_mesh = proof.get("piMesh") if isinstance(proof.get("piMesh"), dict) else {}
    safety = proof.get("safety") if isinstance(proof.get("safety"), dict) else {}
    storage_connected_peers = _int_or_none(storage.get("connectedPeers"))
    peer_connected_peers = _int_or_none(peer.get("connectedPeers"))
    sync_gap = _int_or_none(storage.get("syncGapBlocks"))
    checks = {
        "schema": proof.get("schema") == NODE_PI_READINESS_PROOF_SCHEMA,
        "storageSnapshotPresent": storage.get("snapshotPresent") is True,
        "storageRpcOk": storage.get("rpcOk") is True,
        "storageProcessRunning": storage.get("zgsRunning") is True,
        "storageRelayTcpOpen": storage.get("relayTcpOpen") is True,
        "storagePeerDepthReady": storage_connected_peers is not None
        and storage_connected_peers >= int(storage.get("targetPeers") or 8),
        "storageSyncReady": sync_gap is not None and sync_gap <= int(storage.get("maxSyncGapBlocks") or 8),
        "onlyPriorTestFundingObserved": storage.get("onlyPriorTestFundingObserved") is True,
        "hundredOgTransferSent": storage.get("hundredOgTransferSent") is False,
        "peerDiagnosticsPresent": peer.get("snapshotPresent") is True,
        "peerDiagnosticsConsistent": (
            peer_connected_peers is not None
            and storage_connected_peers is not None
            and peer_connected_peers == storage_connected_peers
        ),
        "piSnapshotPresent": pi_mesh.get("snapshotPresent") is True,
        "piClusterReady": pi_mesh.get("clusterReady") is True,
        "rawSnapshotsStored": proof.get("rawSnapshotsStored") is False,
        "privateKeysReturned": safety.get("privateKeysReturned") is False,
        "privateKeysRead": safety.get("privateKeysRead") is False,
        "transactionSigningEnabled": safety.get("transactionSigningEnabled") is False,
        "transactionBroadcastingEnabled": safety.get("transactionBroadcastingEnabled") is False,
        "moneyMovementEnabled": safety.get("moneyMovementEnabled") is False,
        "telegramSendsEnabled": safety.get("telegramSendsEnabled") is False,
    }
    ready = all(checks.values())
    blockers = _blockers(checks, storage=storage, peer=peer, pi_mesh=pi_mesh)
    return {
        "schema": NODE_PI_READINESS_PROOF_STATUS_SCHEMA,
        "generatedAt": _now(),
        "status": "ready" if ready else "blocked",
        "verified": all(checks.values()),
        "proofPresent": True,
        "proofPath": str(proof_path) if proof_path else proof.get("proofPath"),
        "recordedAt": proof.get("recordedAt"),
        "ready": ready,
        "blockers": blockers,
        "storageNode": {
            "snapshotPresent": storage.get("snapshotPresent") is True,
            "snapshotGeneratedAt": storage.get("snapshotGeneratedAt"),
            "zgsRunning": storage.get("zgsRunning") is True,
            "rpcOk": storage.get("rpcOk") is True,
            "relayTcpOpen": storage.get("relayTcpOpen") is True,
            "connectedPeers": storage_connected_peers,
            "targetPeers": int(storage.get("targetPeers") or 8),
            "syncGapBlocks": sync_gap,
            "maxSyncGapBlocks": int(storage.get("maxSyncGapBlocks") or 8),
            "activeMinerBalanceOg": storage.get("activeMinerBalanceOg"),
            "onlyPriorTestFundingObserved": storage.get("onlyPriorTestFundingObserved") is True,
            "hundredOgTransferSent": storage.get("hundredOgTransferSent") is True,
        },
        "peerDiagnostics": {
            "snapshotPresent": peer.get("snapshotPresent") is True,
            "connectedPeers": peer_connected_peers,
            "targetPeers": int(peer.get("targetPeers") or 8),
            "peerDepthReady": peer.get("peerDepthReady") is True,
            "hypothesisIds": peer.get("hypothesisIds") or [],
        },
        "piMesh": {
            "snapshotPresent": pi_mesh.get("snapshotPresent") is True,
            "snapshotGeneratedAt": pi_mesh.get("snapshotGeneratedAt"),
            "clusterReady": pi_mesh.get("clusterReady") is True,
            "blockers": pi_mesh.get("blockers") or [],
            "primaryReachable": pi_mesh.get("primaryReachable") is True,
            "peerEthernetReachable": pi_mesh.get("peerEthernetReachable") is True,
            "edgeApiReady": pi_mesh.get("edgeApiReady") is True,
        },
        "checks": checks,
        "safety": {
            "readOnly": True,
            "networkCalls": False,
            "proofVerificationOnly": True,
            "rawSnapshotsStored": False,
            "privateKeysRead": False,
            "privateKeysReturned": False,
            "transactionSigningEnabled": False,
            "transactionBroadcastingEnabled": False,
            "moneyMovementEnabled": False,
            "telegramSendsEnabled": False,
        },
    }


def _blockers(
    checks: dict[str, bool],
    *,
    storage: dict[str, Any],
    peer: dict[str, Any],
    pi_mesh: dict[str, Any],
) -> list[str]:
    blockers: list[str] = []
    if not checks["storageSnapshotPresent"]:
        blockers.append("storage_soak_snapshot_missing")
    if not checks["storageRpcOk"]:
        blockers.append("storage_rpc_not_ok")
    if not checks["storageProcessRunning"]:
        blockers.append("zgs_not_running")
    if not checks["storageRelayTcpOpen"]:
        blockers.append("storage_public_relay_not_open")
    if not checks["storagePeerDepthReady"]:
        blockers.append("connected_peers_below_target_8")
    if not checks["storageSyncReady"]:
        blockers.append("storage_log_sync_gap_too_large")
    if not checks["peerDiagnosticsPresent"]:
        blockers.append("peer_diagnostics_snapshot_missing")
    if not checks["peerDiagnosticsConsistent"]:
        blockers.append("peer_diagnostics_inconsistent")
    if not checks["piSnapshotPresent"]:
        blockers.append("pi_mesh_snapshot_missing")
    if not checks["piClusterReady"]:
        blockers.extend(str(item) for item in pi_mesh.get("blockers") or ["pi_mesh_cluster_not_ready"])
    if storage.get("hundredOgTransferSent") is True:
        blockers.append("unexpected_large_0g_transfer_observed")
    if storage.get("onlyPriorTestFundingObserved") is not True:
        blockers.append("funding_state_requires_review")
    for key in (
        "rawSnapshotsStored",
        "privateKeysRead",
        "privateKeysReturned",
        "transactionSigningEnabled",
        "transactionBroadcastingEnabled",
        "moneyMovementEnabled",
        "telegramSendsEnabled",
    ):
        if checks.get(key) is not True:
            blockers.append(f"safety_{key}_not_false")
    return _dedupe(blockers)


def build_node_pi_readiness_proof(
    *,
    storage_snapshot: dict[str, Any] | None,
    peer_diagnostics: dict[str, Any] | None,
    pi_snapshot: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build a redacted proof from already collected local snapshots."""

    storage = storage_snapshot if isinstance(storage_snapshot, dict) else {}
    peer = peer_diagnostics if isinstance(peer_diagnostics, dict) else {}
    pi = pi_snapshot if isinstance(pi_snapshot, dict) else {}
    storage_rpc = storage.get("storageRpc") if isinstance(storage.get("storageRpc"), dict) else {}
    sync = storage.get("sync") if isinstance(storage.get("sync"), dict) else {}
    health = storage.get("health") if isinstance(storage.get("health"), dict) else {}
    funding = storage.get("funding") if isinstance(storage.get("funding"), dict) else {}
    diagnosis = peer.get("diagnosis") if isinstance(peer.get("diagnosis"), dict) else {}
    peer_rpc = peer.get("storageRpc") if isinstance(peer.get("storageRpc"), dict) else {}
    pi_cluster = pi.get("cluster") if isinstance(pi.get("cluster"), dict) else {}
    return {
        "schema": NODE_PI_READINESS_PROOF_SCHEMA,
        "recordedAt": _now(),
        "mode": "redacted_local_snapshot_proof",
        "storageNode": {
            "snapshotPresent": storage.get("schema") == "0guard.rv_0g_storage_soak_snapshot.v1",
            "snapshotGeneratedAt": storage.get("generatedAt"),
            "zgsRunning": health.get("zgsRunning") is True,
            "rpcOk": health.get("rpcOk") is True or storage_rpc.get("status") == "ok",
            "relayTcpOpen": health.get("relayTcpOpen") is True,
            "connectedPeers": storage_rpc.get("connectedPeers"),
            "targetPeers": 8,
            "syncGapBlocks": sync.get("syncGapBlocks"),
            "maxSyncGapBlocks": 8,
            "latestMainnetBlock": sync.get("latestMainnetBlock"),
            "logSyncHeight": sync.get("logSyncHeight"),
            "activeMinerBalanceOg": funding.get("activeMinerBalanceOg"),
            "onlyPriorTestFundingObserved": funding.get("onlyPriorTestFundingObserved"),
            "hundredOgTransferSent": funding.get("hundredOgTransferSent"),
            "largeTransferDetected": funding.get("largeTransferDetected"),
            "recommendedAction": funding.get("recommendedAction"),
            "blockers": health.get("expansionBlockers") or [],
        },
        "peerDiagnostics": {
            "snapshotPresent": peer.get("schema") == "0guard.rv_0g_peer_diagnostics.v1",
            "snapshotGeneratedAt": peer.get("generatedAt"),
            "connectedPeers": peer_rpc.get("connectedPeers") or diagnosis.get("connectedPeers"),
            "targetPeers": diagnosis.get("targetPeers") or 8,
            "peerDepthReady": diagnosis.get("peerDepthReady") is True,
            "hypothesisIds": [
                item.get("id")
                for item in diagnosis.get("hypotheses", [])
                if isinstance(item, dict) and item.get("id")
            ],
            "blockers": diagnosis.get("blockedBy") or [],
        },
        "piMesh": {
            "snapshotPresent": pi.get("schema") == "0guard.rv_pi_mesh_snapshot.v1",
            "snapshotGeneratedAt": pi.get("generatedAt"),
            "clusterReady": pi_cluster.get("clusterReady") is True,
            "blockers": pi_cluster.get("blockers") or [],
            "primaryReachable": pi_cluster.get("primaryReachable") is True,
            "ethernetCarrierReady": pi_cluster.get("ethernetCarrierReady") is True,
            "peerEthernetReachable": pi_cluster.get("peerEthernetReachable") is True,
            "peerIdentityVerified": pi_cluster.get("peerIdentityVerified") is True,
            "edgeApiReady": pi_cluster.get("edgeApiReady") is True,
            "recommendedAction": pi_cluster.get("recommendedAction"),
        },
        "rawSnapshotsStored": False,
        "safety": {
            "readOnly": True,
            "networkCalls": False,
            "privateKeysRead": False,
            "privateKeysReturned": False,
            "transactionSigningEnabled": False,
            "transactionBroadcastingEnabled": False,
            "moneyMovementEnabled": False,
            "telegramSendsEnabled": False,
        },
    }


def _load_proof(path: str | Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _missing_status(reason: str, *, proof_path: str | Path | None = None) -> dict[str, Any]:
    return {
        "schema": NODE_PI_READINESS_PROOF_STATUS_SCHEMA,
        "generatedAt": _now(),
        "status": "missing",
        "verified": False,
        "proofPresent": False,
        "proofPath": str(proof_path) if proof_path else "",
        "reason": reason,
        "ready": False,
        "blockers": ["node_pi_readiness_proof_missing"],
        "safety": {
            "readOnly": True,
            "networkCalls": False,
            "proofVerificationOnly": True,
            "rawSnapshotsStored": False,
            "privateKeysRead": False,
            "privateKeysReturned": False,
            "transactionSigningEnabled": False,
            "transactionBroadcastingEnabled": False,
            "moneyMovementEnabled": False,
            "telegramSendsEnabled": False,
        },
    }


def _int_or_none(value: Any) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            deduped.append(value)
    return deduped


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
