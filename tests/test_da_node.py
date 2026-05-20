"""Tests for read-only 0G DA node telemetry."""

from __future__ import annotations

import json

from guard0 import da_node as da_node_module
from guard0.da_node import (
    build_da_node_status,
    build_storage_node_status,
    build_telegram_da_node_preview,
    build_telegram_storage_node_preview,
)


def test_da_node_status_defaults_to_no_secret_configured_snapshot():
    status = build_da_node_status(live=False)

    assert status["schema"] == "0guard.0g_da_node_status.v1"
    assert status["mode"] == "configured_snapshot"
    assert status["node"]["publicSocket"] == "35.254.123.37:34000"
    assert status["node"]["addresses"]["signer"]["address"].startswith("0x6De")
    assert status["rpc"]["status"] == "not_checked"
    assert status["balances"]["signer"]["status"] == "not_checked"
    assert status["readiness"]["status"] == "blocked"
    assert status["readiness"]["blockedBy"] == ["signer_balance_not_checked"]
    assert status["readiness"]["fundingReady"] is False
    assert status["readiness"]["liveStartRecommended"] is False
    assert status["yield"]["estimatedMonthlyOg"] is None
    assert status["yield"]["status"] == "not_claimed_without_reward_source"
    assert status["safety"]["privateKeysReturned"] is False
    assert status["safety"]["signingEnabled"] is False
    assert status["safety"]["moneyMovementEnabled"] is False
    assert "0x" in json.dumps(status)


def test_da_node_status_strips_sensitive_status_file_keys(tmp_path):
    status_path = tmp_path / "da-status.json"
    status_path.write_text(
        json.dumps(
            {
                "status": "loaded",
                "containerStatus": "running",
                "privateKey": "never",
                "nested": {"secretToken": "nope", "safe": "ok"},
            }
        ),
        encoding="utf-8",
    )

    status = build_da_node_status(live=False, status_file=str(status_path))

    assert status["fileStatus"]["containerStatus"] == "running"
    assert status["fileStatus"]["nested"] == {"safe": "ok"}
    encoded = json.dumps(status)
    assert "never" not in encoded
    assert "nope" not in encoded


def test_da_node_live_status_uses_injected_balance_reader(monkeypatch):
    monkeypatch.setenv("ZG_DA_NODE_SIGNER_ADDRESS", "0x1111111111111111111111111111111111111111")
    monkeypatch.setenv("ZG_DA_NODE_MINER_ADDRESS", "0x2222222222222222222222222222222222222222")
    monkeypatch.setattr(
        "guard0.da_node._read_rpc_status",
        lambda cfg, timeout_seconds: {
            "status": "ok",
            "rpc": cfg["rpc"],
            "expectedChainId": cfg["chainId"],
            "observedChainId": cfg["chainId"],
            "latestBlockNumber": 123,
            "latencyMs": 1,
            "error": None,
        },
    )

    def fake_reader(rpc: str, address: str, timeout_seconds: float) -> dict:
        return {
            "address": address,
            "status": "ok",
            "balanceWei": str(31 * 10**18),
            "balanceOg": 31.0,
            "source": "test",
        }

    status = build_da_node_status(live=True, balance_reader=fake_reader)

    assert status["mode"] == "live_rpc_read_only"
    assert status["balances"]["signer"]["balanceOg"] == 31.0
    assert status["readiness"]["fundingReady"] is True
    assert status["safety"]["networkCalls"] is True
    assert status["safety"]["broadcastingEnabled"] is False


def test_telegram_da_node_preview_is_no_send_digest():
    status = build_da_node_status(live=False)
    preview = build_telegram_da_node_preview(status)

    assert preview["schema"] == "0guard.telegram_da_node_preview.v1"
    assert preview["delivery"] == "preview_no_send"
    assert preview["telegram_send"] is False
    assert preview["digestPolicy"]["enabled"] is False
    assert preview["digestPolicy"]["sendOnlyOnStateChange"] is True
    assert preview["safety"]["telegramSendsEnabled"] is False
    assert "Delivery: preview only" in preview["message"]


def test_storage_node_status_defaults_to_no_key_configured_snapshot():
    status = build_storage_node_status(live=False)

    assert status["schema"] == "0guard.0g_storage_node_status.v1"
    assert status["mode"] == "configured_snapshot"
    assert status["node"]["network"] == "0g_mainnet"
    assert status["node"]["publicSocket"] == "35.254.123.37:1234"
    assert status["node"]["config"]["noKeyMode"] is True
    assert status["storageRpc"]["status"] == "not_checked"
    assert status["readiness"]["status"] == "blocked"
    assert status["readiness"]["blockedBy"] == ["storage_rpc_not_checked"]
    assert status["readiness"]["mainnetFundingReady"] is False
    assert status["funding"]["mainnetFundingRecommended"] is False
    assert status["yield"]["estimatedMonthlyOg"] is None
    assert status["safety"]["signingEnabled"] is False
    assert status["safety"]["moneyMovementEnabled"] is False


def test_storage_node_live_status_uses_injected_reader():
    def fake_reader(rpc: str, timeout_seconds: float) -> dict:
        return {
            "status": "ok",
            "rpc": rpc,
            "expectedChainId": 16661,
            "expectedFlowAddress": "0x62d4144db0f0a6fbbaeb6296c785c71b3d57c526",
            "connectedPeers": 4,
            "logSyncHeight": 3041488,
            "logSyncBlock": "0xabc",
            "nextTxSeq": 1,
            "networkIdentity": {
                "chainId": 16661,
                "flowAddress": "0x62d4144db0f0a6fbbaeb6296c785c71b3d57c526",
            },
            "latencyMs": 1,
            "error": None,
        }

    status = build_storage_node_status(live=True, status_reader=fake_reader)

    assert status["mode"] == "live_storage_rpc_read_only"
    assert status["storageRpc"]["connectedPeers"] == 4
    assert status["storageRpc"]["logSyncHeight"] == 3041488
    assert status["readiness"]["status"] == "ready_for_no_key_soak"
    assert status["readiness"]["peerReady"] is True
    assert status["readiness"]["mainnetFundingReady"] is False
    assert status["safety"]["networkCalls"] is True


def test_storage_node_status_loads_rv_funded_soak_snapshot(tmp_path):
    status_path = tmp_path / "rv-soak.json"
    status_path.write_text(
        json.dumps(
            {
                "schema": "0guard.rv_0g_storage_soak_snapshot.v1",
                "generatedAt": "2026-05-17T12:41:00+00:00",
                "storageRpc": {
                    "status": "ok",
                    "connectedPeers": 4,
                    "logSyncHeight": 24345245,
                    "logSyncBlock": "0xabc",
                    "nextTxSeq": 46135,
                    "shardConfig": {"shardId": 0, "numShard": 1},
                    "networkIdentity": {
                        "chainId": 16661,
                        "flowAddress": "0x62d4144db0f0a6fbbaeb6296c785c71b3d57c526",
                    },
                },
                "health": {
                    "zgsRunning": True,
                    "relayTcpOpen": True,
                    "rpcOk": True,
                    "expansionReady": False,
                    "expansionBlockers": [
                        "connected_peers_below_target_8",
                        "storage_log_sync_gap_too_large",
                    ],
                },
                "sync": {
                    "latestMainnetBlock": 33518737,
                    "logSyncHeight": 24345245,
                    "syncGapBlocks": 9173492,
                    "nextTxSeq": 46135,
                },
                "disk": {"dbSizeHuman": "7.7G"},
                "config": {"minerKeyPresent": True, "privateKey": "must_strip"},
                "funding": {
                    "activeMinerAddress": "0xf5c1c3eb88c262adb451c1ce3b1c391f7d968ecd",
                    "activeMinerBalanceOg": 0.25,
                    "onlyPriorTestFundingObserved": True,
                    "hundredOgTransferSent": False,
                    "largeTransferDetected": False,
                },
                "publicRelay": {"tcp1234": {"ok": True}, "tcp34000": {"ok": False}},
            }
        ),
        encoding="utf-8",
    )

    status = build_storage_node_status(live=False, status_file=str(status_path))

    assert status["mode"] == "rv_soak_snapshot_file"
    assert status["source"] == "rv_soak_snapshot_file"
    assert status["status"] == "funded_soak_syncing"
    assert status["processStatus"] == "running"
    assert "connected_peers_below_target_8" in status["blockers"]
    assert status["storageRpc"]["source"] == "rv_soak_snapshot_file"
    assert status["storageRpc"]["connectedPeers"] == 4
    assert status["storageRpc"]["syncGapBlocks"] == 9173492
    assert status["storageRpc"]["shardConfig"] == {"shardId": 0, "numShard": 1}
    assert status["sync"]["latestMainnetBlock"] == 33518737
    assert status["sync"]["shardConfig"] == {"shardId": 0, "numShard": 1}
    assert status["sync"]["dbSizeHuman"] == "7.7G"
    assert status["readiness"]["status"] == "funded_soak_syncing"
    assert status["readiness"]["noKeyMode"] is False
    assert status["funding"]["status"] == "funded_soak_monitoring_only"
    assert status["fundingSummary"]["activeMinerBalanceOg"] == 0.25
    assert status["fundingSummary"]["largeFundingExpansionReady"] is False
    assert status["funding"]["activeMinerBalanceOg"] == 0.25
    assert status["funding"]["hundredOgTransferSent"] is False
    assert status["fundedSoak"]["syncGapBlocks"] == 9173492
    assert status["fundedSoak"]["shardConfig"] == {"shardId": 0, "numShard": 1}
    encoded = json.dumps(status)
    assert "must_strip" not in encoded
    assert status["safety"]["privateKeysReturned"] is False


def test_storage_node_status_falls_back_to_node_pi_proof(monkeypatch, tmp_path):
    missing_status_path = tmp_path / "missing-rv-soak.local.json"
    proof_path = tmp_path / "node-pi-readiness-proof.json"
    proof_path.write_text(
        json.dumps(
            {
                "schema": "0guard.node_pi_readiness_proof.v1",
                "recordedAt": "2026-05-20T06:32:58+00:00",
                "blockers": ["connected_peers_below_target_8"],
                "storageNode": {
                    "snapshotPresent": True,
                    "snapshotGeneratedAt": "2026-05-20T06:29:41.603889+00:00",
                    "zgsRunning": True,
                    "rpcOk": True,
                    "relayTcpOpen": True,
                    "connectedPeers": 0,
                    "targetPeers": 8,
                    "syncGapBlocks": 1,
                    "maxSyncGapBlocks": 8,
                    "latestMainnetBlock": 33785354,
                    "logSyncHeight": 33785353,
                    "nextTxSeq": 107339,
                    "activeMinerBalanceOg": 0.25,
                    "onlyPriorTestFundingObserved": True,
                    "hundredOgTransferSent": False,
                    "largeTransferDetected": False,
                },
                "peerDiagnostics": {
                    "snapshotPresent": True,
                    "connectedPeers": 0,
                    "targetPeers": 8,
                    "peerDepthReady": False,
                },
                "piMesh": {
                    "snapshotPresent": True,
                    "clusterReady": True,
                    "blockers": [],
                },
                "rawSnapshotsStored": False,
                "safety": {
                    "privateKeysRead": False,
                    "privateKeysReturned": False,
                    "transactionSigningEnabled": False,
                    "transactionBroadcastingEnabled": False,
                    "moneyMovementEnabled": False,
                    "telegramSendsEnabled": False,
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        da_node_module,
        "DEFAULT_NODE_PI_READINESS_PROOF_PATH",
        str(proof_path),
    )

    status = build_storage_node_status(live=False, status_file=str(missing_status_path))

    assert status["mode"] == "node_pi_readiness_proof"
    assert status["source"] == "node_pi_readiness_proof"
    assert status["storageRpc"]["connectedPeers"] == 0
    assert status["storageRpc"]["logSyncHeight"] == 33785353
    assert status["sync"]["latestMainnetBlock"] == 33785354
    assert status["sync"]["syncGapBlocks"] == 1
    assert status["readiness"]["status"] == "blocked"
    assert status["readiness"]["processStatus"] == "running"
    assert status["readiness"]["blockedBy"] == ["connected_peers_below_target_8"]
    assert status["fundingSummary"]["activeMinerBalanceOg"] == 0.25
    assert status["fundingSummary"]["onlyPriorTestFundingObserved"] is True
    assert status["fundingSummary"]["hundredOgTransferSent"] is False
    assert status["safety"]["networkCalls"] is False
    assert status["safety"]["privateKeysReturned"] is False


def test_storage_node_peer_only_blocker_is_not_reported_as_syncing(tmp_path):
    status_path = tmp_path / "rv-soak-peer-only.json"
    status_path.write_text(
        json.dumps(
            {
                "schema": "0guard.rv_0g_storage_soak_snapshot.v1",
                "storageRpc": {
                    "status": "ok",
                    "connectedPeers": 2,
                    "logSyncHeight": 33532334,
                    "nextTxSeq": 105577,
                    "networkIdentity": {
                        "chainId": 16661,
                        "flowAddress": "0x62d4144db0f0a6fbbaeb6296c785c71b3d57c526",
                    },
                },
                "health": {
                    "zgsRunning": True,
                    "expansionBlockers": ["connected_peers_below_target_8"],
                },
                "sync": {
                    "latestMainnetBlock": 33532335,
                    "logSyncHeight": 33532334,
                    "syncGapBlocks": 1,
                    "nextTxSeq": 105577,
                },
                "config": {"minerKeyPresent": True},
                "funding": {
                    "activeMinerAddress": "0xf5c1c3eb88c262adb451c1ce3b1c391f7d968ecd",
                    "activeMinerBalanceOg": 0.25,
                    "onlyPriorTestFundingObserved": True,
                    "hundredOgTransferSent": False,
                    "largeTransferDetected": False,
                },
            }
        ),
        encoding="utf-8",
    )

    status = build_storage_node_status(live=False, status_file=str(status_path))

    assert status["status"] == "funded_soak_blocked"
    assert status["sync"]["syncGapBlocks"] == 1
    assert status["blockers"] == ["connected_peers_below_target_8"]


def test_telegram_storage_node_preview_is_no_send_digest():
    status = build_storage_node_status(
        live=True,
        status_reader=lambda rpc, timeout_seconds: {
            "status": "ok",
            "rpc": rpc,
            "expectedChainId": 16661,
            "expectedFlowAddress": "0x62d4144db0f0a6fbbaeb6296c785c71b3d57c526",
            "connectedPeers": 4,
            "logSyncHeight": 3041488,
            "logSyncBlock": "0xabc",
            "nextTxSeq": 1,
            "networkIdentity": {"chainId": 16661},
            "latencyMs": 1,
            "error": None,
        },
    )
    preview = build_telegram_storage_node_preview(status)

    assert preview["schema"] == "0guard.telegram_storage_node_preview.v1"
    assert preview["delivery"] == "preview_no_send"
    assert preview["telegram_send"] is False
    assert preview["digestPolicy"]["enabled"] is False
    assert preview["summary"]["connectedPeers"] == 4
    assert "Delivery: preview only" in preview["message"]
