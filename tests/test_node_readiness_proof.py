"""Tests for the public-safe 0G storage-node/Pi readiness proof rail."""

from guard0.node_readiness_proof import (
    build_node_pi_readiness_proof,
    build_node_pi_readiness_proof_status,
    verify_node_pi_readiness_proof,
)


def test_node_pi_readiness_proof_status_is_missing_for_absent_artifact(tmp_path):
    status = build_node_pi_readiness_proof_status(tmp_path / "missing.json")

    assert status["schema"] == "0guard.node_pi_readiness_proof_status.v1"
    assert status["status"] == "missing"
    assert status["verified"] is False
    assert status["ready"] is False
    assert status["safety"]["proofVerificationOnly"] is True
    assert status["safety"]["transactionSigningEnabled"] is False
    assert status["safety"]["moneyMovementEnabled"] is False


def test_node_pi_readiness_proof_records_blocked_redacted_snapshot():
    proof = build_node_pi_readiness_proof(
        storage_snapshot=_storage_snapshot(connected_peers=0, sync_gap_blocks=1),
        peer_diagnostics=_peer_diagnostics(connected_peers=0, peer_depth_ready=False),
        pi_snapshot=_pi_snapshot(cluster_ready=False, blockers=["rvpi_a_not_reachable"]),
    )

    status = verify_node_pi_readiness_proof(proof, proof_path="proof.json")

    assert proof["schema"] == "0guard.node_pi_readiness_proof.v1"
    assert proof["rawSnapshotsStored"] is False
    assert "host" not in proof["storageNode"]
    assert "private_key" not in str(proof)
    assert "mnemonic" not in str(proof)
    assert status["status"] == "blocked"
    assert status["verified"] is False
    assert status["ready"] is False
    assert "connected_peers_below_target_8" in status["blockers"]
    assert "rvpi_a_not_reachable" in status["blockers"]
    assert status["storageNode"]["connectedPeers"] == 0
    assert status["storageNode"]["syncGapBlocks"] == 1
    assert status["safety"]["privateKeysRead"] is False
    assert status["safety"]["transactionBroadcastingEnabled"] is False
    assert status["safety"]["moneyMovementEnabled"] is False


def test_node_pi_readiness_proof_can_verify_ready_redacted_snapshot():
    proof = build_node_pi_readiness_proof(
        storage_snapshot=_storage_snapshot(connected_peers=8, sync_gap_blocks=1),
        peer_diagnostics=_peer_diagnostics(connected_peers=8, peer_depth_ready=True),
        pi_snapshot=_pi_snapshot(cluster_ready=True, blockers=[]),
    )

    status = verify_node_pi_readiness_proof(proof)

    assert status["status"] == "ready"
    assert status["verified"] is True
    assert status["ready"] is True
    assert status["blockers"] == []
    assert status["peerDiagnostics"]["connectedPeers"] == 8
    assert status["piMesh"]["clusterReady"] is True
    assert status["safety"]["telegramSendsEnabled"] is False


def _storage_snapshot(*, connected_peers: int, sync_gap_blocks: int) -> dict:
    return {
        "schema": "0guard.rv_0g_storage_soak_snapshot.v1",
        "generatedAt": "2026-05-20T02:30:00+00:00",
        "health": {
            "zgsRunning": True,
            "rpcOk": True,
            "relayTcpOpen": True,
            "expansionBlockers": [],
        },
        "storageRpc": {"status": "ok", "connectedPeers": connected_peers},
        "sync": {
            "latestMainnetBlock": 33767267,
            "logSyncHeight": 33767266,
            "syncGapBlocks": sync_gap_blocks,
        },
        "funding": {
            "activeMinerBalanceOg": 0.25,
            "onlyPriorTestFundingObserved": True,
            "hundredOgTransferSent": False,
            "largeTransferDetected": False,
            "recommendedAction": "continue_read_only_soak",
        },
    }


def _peer_diagnostics(*, connected_peers: int, peer_depth_ready: bool) -> dict:
    return {
        "schema": "0guard.rv_0g_peer_diagnostics.v1",
        "generatedAt": "2026-05-20T02:31:00+00:00",
        "storageRpc": {"connectedPeers": connected_peers},
        "diagnosis": {
            "connectedPeers": connected_peers,
            "targetPeers": 8,
            "peerDepthReady": peer_depth_ready,
            "blockedBy": [] if peer_depth_ready else ["connected_peers_below_target_8"],
            "hypotheses": [{"id": "peer_discovery"}],
        },
    }


def _pi_snapshot(*, cluster_ready: bool, blockers: list[str]) -> dict:
    return {
        "schema": "0guard.rv_pi_mesh_snapshot.v1",
        "generatedAt": "2026-05-20T02:32:00+00:00",
        "cluster": {
            "clusterReady": cluster_ready,
            "blockers": blockers,
            "primaryReachable": cluster_ready,
            "ethernetCarrierReady": cluster_ready,
            "peerEthernetReachable": cluster_ready,
            "peerIdentityVerified": cluster_ready,
            "edgeApiReady": cluster_ready,
            "recommendedAction": "continue_read_only_heartbeat",
        },
    }
