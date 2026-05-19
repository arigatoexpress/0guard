"""Public-safe 0G storage peer-depth diagnostic status."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STORAGE_PEER_DIAGNOSTICS_SCHEMA = "0guard.rv_0g_peer_diagnostics.v1"
DEFAULT_STORAGE_PEER_DIAGNOSTICS_PATH = "content/rv_0g_peer_diagnostics.local.json"
SENSITIVE_KEY_RE = re.compile(r"(private|secret|mnemonic|token|password|miner_key)", re.IGNORECASE)


def build_storage_peer_diagnostics(
    status_file: str | None = DEFAULT_STORAGE_PEER_DIAGNOSTICS_PATH,
) -> dict[str, Any]:
    """Load the latest peer diagnostic snapshot without exposing secrets."""

    if not status_file:
        return _not_loaded("status_file_not_configured")
    path = Path(status_file)
    if not path.exists():
        return _not_loaded("snapshot_file_missing", path=path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return _not_loaded(f"{type(exc).__name__}: {exc}", path=path)
    if not isinstance(payload, dict):
        return _not_loaded("snapshot_not_object", path=path)

    sanitized = _strip_sensitive(payload)
    if sanitized.get("schema") != STORAGE_PEER_DIAGNOSTICS_SCHEMA:
        return _not_loaded("schema_mismatch", path=path)

    diagnosis = sanitized.get("diagnosis") or {}
    storage_rpc = sanitized.get("storageRpc") or {}
    health = sanitized.get("health") or {}
    return {
        **sanitized,
        "status": "loaded",
        "path": str(path),
        "summary": {
            "connectedPeers": storage_rpc.get("connectedPeers")
            or diagnosis.get("connectedPeers"),
            "peerDepthReady": diagnosis.get("peerDepthReady") is True,
            "blockedBy": diagnosis.get("blockedBy") or health.get("blockedBy") or [],
            "hypothesisIds": [
                item.get("id")
                for item in diagnosis.get("hypotheses", [])
                if isinstance(item, dict) and item.get("id")
            ],
            "nextChecks": diagnosis.get("nextChecks") or [],
        },
        "safety": {
            **(sanitized.get("safety") or {}),
            "readOnly": True,
            "privateKeysRead": False,
            "privateKeysReturned": False,
            "moneyMovementEnabled": False,
        },
    }


def _not_loaded(reason: str, *, path: Path | None = None) -> dict[str, Any]:
    return {
        "schema": STORAGE_PEER_DIAGNOSTICS_SCHEMA,
        "generatedAt": _utc_now(),
        "status": "not_loaded",
        "reason": reason,
        "path": str(path) if path else None,
        "summary": {
            "connectedPeers": None,
            "peerDepthReady": False,
            "blockedBy": ["peer_diagnostics_snapshot_missing"],
            "hypothesisIds": [],
            "nextChecks": [
                "./scripts/rv_0g_peer_diagnostics.py --out content/rv_0g_peer_diagnostics.local.json"
            ],
        },
        "safety": {
            "readOnly": True,
            "privateKeysRead": False,
            "privateKeysReturned": False,
            "moneyMovementEnabled": False,
        },
    }


def _strip_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _strip_sensitive(item)
            for key, item in value.items()
            if not SENSITIVE_KEY_RE.search(str(key))
        }
    if isinstance(value, list):
        return [_strip_sensitive(item) for item in value]
    return value


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
