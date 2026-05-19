"""Tests for public-safe storage peer diagnostic loading."""

from __future__ import annotations

import json

from guard0.storage_peer_diagnostics import build_storage_peer_diagnostics


def test_storage_peer_diagnostics_missing_file_is_safe(tmp_path):
    result = build_storage_peer_diagnostics(str(tmp_path / "missing.json"))

    assert result["schema"] == "0guard.rv_0g_peer_diagnostics.v1"
    assert result["status"] == "not_loaded"
    assert result["summary"]["peerDepthReady"] is False
    assert result["safety"]["privateKeysRead"] is False
    assert result["safety"]["moneyMovementEnabled"] is False


def test_storage_peer_diagnostics_loads_summary_and_strips_sensitive_keys(tmp_path):
    status_path = tmp_path / "peer.json"
    status_path.write_text(
        json.dumps(
            {
                "schema": "0guard.rv_0g_peer_diagnostics.v1",
                "storageRpc": {"connectedPeers": 2},
                "diagnosis": {
                    "peerDepthReady": False,
                    "blockedBy": ["connected_peers_below_target_8"],
                    "hypotheses": [{"id": "shallow_peer_discovery"}],
                    "nextChecks": ["watch peer count"],
                },
                "privateKey": "do-not-return",
                "nested": {"token": "nope", "safe": "ok"},
                "safety": {"readOnly": True},
            }
        ),
        encoding="utf-8",
    )

    result = build_storage_peer_diagnostics(str(status_path))
    encoded = json.dumps(result)

    assert result["status"] == "loaded"
    assert result["summary"]["connectedPeers"] == 2
    assert result["summary"]["blockedBy"] == ["connected_peers_below_target_8"]
    assert result["summary"]["hypothesisIds"] == ["shallow_peer_discovery"]
    assert "do-not-return" not in encoded
    assert "nope" not in encoded
    assert result["nested"] == {"safe": "ok"}
