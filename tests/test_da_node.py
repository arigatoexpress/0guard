"""Tests for read-only 0G DA node telemetry."""

from __future__ import annotations

import json

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
