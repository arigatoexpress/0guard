"""Tests for read-only 0G Storage endpoint preflight."""

from guard0 import storage_endpoint_preflight as preflight


def test_endpoint_preflight_ready_when_chain_and_indexer_are_reachable(monkeypatch, tmp_path):
    monkeypatch.setattr(
        preflight,
        "STORAGE_SDK_PACKAGE_PATH",
        tmp_path / "node_modules" / "@0gfoundation" / "0g-storage-ts-sdk",
    )
    preflight.STORAGE_SDK_PACKAGE_PATH.mkdir(parents=True)
    monkeypatch.setattr(preflight.shutil, "which", lambda command: "/usr/bin/node")
    monkeypatch.setattr(
        preflight,
        "_probe_chain_rpc",
        lambda url, expected, timeout: {
            "url": url,
            "method": "eth_chainId",
            "ok": True,
            "blockers": [],
            "expectedChainId": expected,
            "chainId": expected,
            "rawChainId": hex(expected),
        },
    )
    monkeypatch.setattr(
        preflight,
        "_probe_indexer_with_sdk",
        lambda url, timeout, select_nodes, sdk_present: {
            "url": url,
            "ok": True,
            "blockers": [],
            "nodeSelectionAttempted": select_nodes,
            "selectedNodeCount": 2,
            "selectedNodeUrls": ["http://storage-node-a.invalid:5678"],
        },
    )

    result = preflight.build_storage_endpoint_preflight(
        chain_rpc="https://evmrpc-testnet.0g.ai",
        indexer_rpc="https://indexer-storage-testnet-turbo.0g.ai",
    )

    assert result["schema"] == "0guard.0g_storage_endpoint_preflight.v1"
    assert result["status"] == "ready_for_signer_review"
    assert result["readyForSignerReview"] is True
    assert result["blockers"] == []
    assert result["sdkRuntime"]["packagePresent"] is True
    assert result["chainRpc"]["chainId"] == 16602
    assert result["indexerRpc"]["selectedNodeCount"] == 2
    assert result["safety"]["readOnly"] is True
    assert result["safety"]["networkCalls"] is True
    assert result["safety"]["transactionSigningEnabled"] is False
    assert result["safety"]["transactionBroadcastingEnabled"] is False
    assert result["safety"]["moneyMovementEnabled"] is False
    assert result["safety"]["privateKeysRead"] is False


def test_endpoint_preflight_blocks_on_chain_mismatch_and_missing_sdk(monkeypatch, tmp_path):
    monkeypatch.setattr(
        preflight,
        "STORAGE_SDK_PACKAGE_PATH",
        tmp_path / "node_modules" / "@0gfoundation" / "0g-storage-ts-sdk",
    )
    monkeypatch.setattr(preflight.shutil, "which", lambda command: "/usr/bin/node")
    monkeypatch.setattr(
        preflight,
        "_probe_chain_rpc",
        lambda url, expected, timeout: {
            "url": url,
            "method": "eth_chainId",
            "ok": False,
            "blockers": ["chain_id_mismatch"],
            "expectedChainId": expected,
            "chainId": 1,
            "rawChainId": "0x1",
        },
    )

    result = preflight.build_storage_endpoint_preflight(select_nodes=False)

    assert result["status"] == "blocked_endpoint_probe_failed"
    assert result["readyForSignerReview"] is False
    assert "chain_id_mismatch" in result["blockers"]
    assert "storage_sdk_runtime_not_present" in result["blockers"]
    assert result["sdkRuntime"]["packagePresent"] is False
    assert result["indexerRpc"]["nodeSelectionAttempted"] is False
    assert result["safety"]["liveStorageUpload"] is False


def test_chain_rpc_probe_parses_hex_chain_id(monkeypatch):
    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return b'{"jsonrpc":"2.0","id":1,"result":"0x40da"}'

    monkeypatch.setattr(preflight.urllib.request, "urlopen", lambda request, timeout: FakeResponse())

    result = preflight._probe_chain_rpc("https://evmrpc-testnet.0g.ai", 16602, 1)

    assert result["ok"] is True
    assert result["chainId"] == 16602
    assert result["blockers"] == []

