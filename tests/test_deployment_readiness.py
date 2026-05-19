"""Tests for the deployment-readiness promotion packet."""

from __future__ import annotations

import requests

from guard0.deployment_readiness import (
    CLOUD_RUN_BASE_URL,
    GITHUB_PAGES_ROOT_URL,
    HACKATHON_PROOF_HUB_URL,
    MAINNET_PROOF_JSON_URL,
    build_deployment_readiness,
)


class FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None, text: str = "ok"):
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.headers = {"content-type": "application/json" if payload is not None else "text/html"}

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def test_deployment_readiness_default_is_non_networked_and_safe():
    def boom_getter(*args, **kwargs):
        raise AssertionError("live probe should not run")

    payload = build_deployment_readiness(
        live=False,
        http_get=boom_getter,
        local_readiness=_sample_local_readiness(),
    )

    assert payload["schema"] == "0guard.deployment_readiness.v1"
    assert payload["status"] == "promotion_review"
    assert payload["liveProbes"]["mode"] == "not_requested"
    assert payload["safety"]["networkCalls"] is False
    assert payload["safety"]["transactionSigningEnabled"] is False
    assert payload["safety"]["moneyMovementEnabled"] is False
    assert payload["safety"]["secretDisplayEnabled"] is False
    assert _gate(payload, "storage_peer_depth")["status"] == "review"
    assert _command(payload, "cloud_run_deploy_after_clean_revision")["safeNow"] is False
    assert _command(payload, "github_pages_redeploy_current_main")["safeNow"] is True


def test_deployment_readiness_live_probe_flags_stale_hosted_schema():
    responses = {
        GITHUB_PAGES_ROOT_URL: FakeResponse(200, None, "<html></html>"),
        HACKATHON_PROOF_HUB_URL: FakeResponse(200, None, "<html></html>"),
        MAINNET_PROOF_JSON_URL: FakeResponse(
            200,
            {
                "schema": "0guard.mainnet_proof.v1",
                "chain_id": 16661,
                "contract_address": "0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc",
            },
        ),
        f"{CLOUD_RUN_BASE_URL}/api/healthz": FakeResponse(
            200,
            {
                "schema": "0guard.healthz.v1",
                "ok": True,
                "read_only": True,
                "telegram_sends_enabled": False,
                "money_movement_enabled": False,
            },
        ),
        f"{CLOUD_RUN_BASE_URL}/api/readyz": FakeResponse(
            200,
            {
                "schema": "0guard.readyz.v1",
                "ok": False,
                "status": None,
                "hardGates": None,
            },
        ),
    }

    def fake_get(url, timeout):
        return responses[url]

    payload = build_deployment_readiness(
        live=True,
        http_get=fake_get,
        local_readiness=_sample_local_readiness(storage_ok=True),
    )

    assert payload["liveProbes"]["mode"] == "live_http_readback"
    assert _gate(payload, "pages_public_proof_reachable")["status"] == "ok"
    assert _gate(payload, "hosted_api_reachable")["status"] == "ok"
    assert _gate(payload, "hosted_api_schema_current")["status"] == "review"
    assert payload["safety"]["networkCalls"] is True
    assert payload["safety"]["liveHttpReadbackOnly"] is True


def test_deployment_readiness_live_probe_handles_network_errors():
    def fake_get(url, timeout):
        raise requests.ConnectTimeout("timeout")

    payload = build_deployment_readiness(
        live=True,
        http_get=fake_get,
        local_readiness=_sample_local_readiness(storage_ok=True),
    )

    assert _gate(payload, "pages_public_proof_reachable")["status"] == "review"
    assert _gate(payload, "hosted_api_reachable")["status"] == "review"
    target = payload["liveProbes"]["targets"]["cloudRunHealthz"]
    assert target["ok"] is False
    assert "ConnectTimeout" in target["error"]


def _sample_local_readiness(*, storage_ok: bool = False) -> dict:
    return {
        "schema": "0guard.readyz.v1",
        "generatedAt": "2026-05-17T00:00:00+00:00",
        "ok": False,
        "status": "production_review",
        "reviewCount": 2,
        "hardGates": ["storage_node_funded_soak", "telegram_live_identity"],
        "checks": [
            {
                "id": "storage_node_funded_soak",
                "status": "ok" if storage_ok else "review",
                "detail": {"connectedPeers": 1, "blockedBy": ["connected_peers_below_target_8"]},
            },
            {
                "id": "telegram_live_identity",
                "status": "review",
                "detail": {"botTokenConfigured": False},
            },
            {
                "id": "storage_upload_readback",
                "status": "review",
                "detail": {"liveStorageUpload": False},
            },
            {
                "id": "private_compute_paid_smoke",
                "status": "review",
                "detail": {"inferenceExecuted": False},
            },
            {
                "id": "x402_settlement_path",
                "status": "review",
                "detail": {"settlementEnabled": False},
            },
        ],
    }


def _gate(payload: dict, gate_id: str) -> dict:
    for gate in payload["promotionGates"]:
        if gate["id"] == gate_id:
            return gate
    raise AssertionError(f"missing gate {gate_id}")


def _command(payload: dict, command_id: str) -> dict:
    for command in payload["commands"]:
        if command["id"] == command_id:
            return command
    raise AssertionError(f"missing command {command_id}")
