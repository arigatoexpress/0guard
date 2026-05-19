"""Tests for the read-only RV 0G storage peer diagnostic collector."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "rv_0g_peer_diagnostics.py"
sys.path.insert(0, str(SCRIPT_PATH.parent))
SPEC = importlib.util.spec_from_file_location("rv_0g_peer_diagnostics", SCRIPT_PATH)
assert SPEC and SPEC.loader
diagnostics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostics)


def test_sanitize_redacts_secret_like_values():
    text = (
        "miner_key = 0x"
        + "a" * 64
        + " token = abc password=secret private_key=0x"
        + "b" * 64
    )

    sanitized = diagnostics.sanitize(text)

    assert "a" * 64 not in sanitized
    assert "b" * 64 not in sanitized
    assert "abc" not in sanitized
    assert "secret" not in sanitized
    assert "<redacted" in sanitized


def test_peer_diagnosis_blocks_shallow_peer_depth_and_udp_uncertainty():
    result = diagnostics.diagnose_peer_depth(
        connected_peers=2,
        config={"entries": ["network_enr_address = '35.254.123.37'"]},
        sockets={"entries": ["udp UNCONN 0 0 0.0.0.0:1234 0.0.0.0:*"]},
        logs={"entries": ["connected peer"]},
        process={"running": True},
        frp={"entries": ["type = 'tcp'", "remote_port = 1234"]},
    )

    assert result["peerDepthReady"] is False
    assert result["connectedPeers"] == 2
    assert "connected_peers_below_target_8" in result["blockedBy"]
    assert [item["id"] for item in result["hypotheses"]] == [
        "shallow_peer_discovery",
        "udp_relay_not_confirmed",
        "bootnode_visibility_unknown",
    ]
    assert any("UDP" in check for check in result["nextChecks"])


def test_peer_diagnosis_ready_when_depth_and_core_networking_are_visible():
    result = diagnostics.diagnose_peer_depth(
        connected_peers=9,
        config={
            "entries": [
                "network_enr_address = '35.254.123.37'",
                "boot_nodes = ['enr:test']",
            ]
        },
        sockets={"entries": ["tcp LISTEN 0 128 0.0.0.0:1234 0.0.0.0:*"]},
        logs={"entries": []},
        process={"running": True},
        frp={"entries": ["type = 'tcp'", "type = 'udp'"]},
    )

    assert result["peerDepthReady"] is True
    assert result["blockedBy"] == []
    assert result["hypotheses"] == []
