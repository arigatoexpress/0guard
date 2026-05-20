#!/usr/bin/env python3
"""Record a public-safe 0G storage-node/Pi readiness proof.

This recorder consumes already-collected local snapshots and emits a redacted
proof artifact. It does not SSH, probe the LAN, read keys, restart services,
sign, broadcast, move funds, or send messages.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from guard0.node_readiness_proof import (
    build_node_pi_readiness_proof,
    verify_node_pi_readiness_proof,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Record a redacted node/Pi readiness proof")
    parser.add_argument(
        "--storage-snapshot",
        default="content/rv_0g_storage_soak.local.json",
        help="Local RV 0G storage soak snapshot",
    )
    parser.add_argument(
        "--peer-diagnostics",
        default="content/rv_0g_peer_diagnostics.local.json",
        help="Local RV 0G peer diagnostics snapshot",
    )
    parser.add_argument(
        "--pi-snapshot",
        default="content/rv_pi_mesh.local.json",
        help="Local Raspberry Pi mesh snapshot",
    )
    parser.add_argument(
        "--out",
        default="docs/hackathon-0g/node-pi-readiness-proof.json",
        help="Proof JSON output path",
    )
    parser.add_argument(
        "--operator-reviewed-public-safe",
        action="store_true",
        help="Required acknowledgement that the proof is public-safe and redacted",
    )
    args = parser.parse_args()

    if not args.operator_reviewed_public_safe:
        raise SystemExit("--operator-reviewed-public-safe is required")

    proof = build_node_pi_readiness_proof(
        storage_snapshot=_read_json(Path(args.storage_snapshot)),
        peer_diagnostics=_read_json(Path(args.peer_diagnostics)),
        pi_snapshot=_read_json(Path(args.pi_snapshot)),
    )
    verification = verify_node_pi_readiness_proof(proof, proof_path=args.out)
    safety = verification.get("safety") or {}
    if (
        safety.get("privateKeysReturned") is not False
        or safety.get("transactionSigningEnabled") is not False
        or safety.get("transactionBroadcastingEnabled") is not False
        or safety.get("moneyMovementEnabled") is not False
    ):
        raise SystemExit("proof failed safety verification")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(f"{out_path.suffix}.tmp")
    tmp_path.write_text(json.dumps(proof, sort_keys=True, indent=2), encoding="utf-8")
    tmp_path.replace(out_path)
    print(
        json.dumps(
            {
                "schema": "0guard.node_pi_readiness_proof_record.v1",
                "out": str(out_path),
                "verification": verification,
            },
            sort_keys=True,
        )
    )
    return 0 if verification.get("ready") is True else 2


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


if __name__ == "__main__":
    raise SystemExit(main())
