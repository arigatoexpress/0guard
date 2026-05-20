#!/usr/bin/env python3
"""Record a reviewed 0G Private Computer paid smoke proof.

The actual paid inference must happen outside this script in a server-side,
operator-controlled environment. This recorder only writes public-safe hashes,
bounded-cost metadata, and explicit no-secret/no-raw-payload flags. It does not
call the Router, read API keys, execute prompts, sign, broadcast, settle, or
move funds.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guard0.peer_protection import CHAT_COMPLETIONS_URL, MODEL_ID, ROUTER_BASE_URL
from guard0.private_compute_adapter import (
    PRIVATE_COMPUTE_PAID_SMOKE_PROOF_SCHEMA,
    verify_private_compute_paid_smoke_proof,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Record a public-safe 0G Private Computer proof")
    parser.add_argument("--prompt-hash", required=True, help="sha256 of the scrubbed/approved prompt")
    parser.add_argument("--request-hash", required=True, help="sha256 of the exact Router request body")
    parser.add_argument("--response-hash", required=True, help="sha256 of the model response body")
    parser.add_argument("--router-receipt-hash", required=True, help="sha256 of Router receipt/billing metadata")
    parser.add_argument("--budget-usd", required=True, help="Reviewed budget for this smoke")
    parser.add_argument("--cost-usd", required=True, help="Observed cost for this smoke")
    parser.add_argument("--model", default=MODEL_ID)
    parser.add_argument("--router-base-url", default=ROUTER_BASE_URL)
    parser.add_argument("--chat-completions-url", default=CHAT_COMPLETIONS_URL)
    parser.add_argument(
        "--out",
        default="docs/hackathon-0g/0g-private-compute-paid-smoke-proof.json",
        help="Proof JSON output path",
    )
    parser.add_argument(
        "--operator-reviewed-budget",
        action="store_true",
        help="Required acknowledgement that the smoke budget and cost were reviewed",
    )
    parser.add_argument(
        "--prompt-safe-for-inference",
        action="store_true",
        help="Required acknowledgement that the prompt passed the ZeroGuard scrubber",
    )
    parser.add_argument(
        "--paid-inference-performed-externally",
        action="store_true",
        help="Required acknowledgement that inference was performed outside ZeroGuard",
    )
    parser.add_argument("--raw-prompt-not-stored", action="store_true")
    parser.add_argument("--raw-response-not-stored", action="store_true")
    parser.add_argument("--api-key-not-returned", action="store_true")
    args = parser.parse_args()

    required_flags = {
        "--operator-reviewed-budget": args.operator_reviewed_budget,
        "--prompt-safe-for-inference": args.prompt_safe_for_inference,
        "--paid-inference-performed-externally": args.paid_inference_performed_externally,
        "--raw-prompt-not-stored": args.raw_prompt_not_stored,
        "--raw-response-not-stored": args.raw_response_not_stored,
        "--api-key-not-returned": args.api_key_not_returned,
    }
    missing = [flag for flag, present in required_flags.items() if not present]
    if missing:
        raise SystemExit(f"missing required acknowledgement flag(s): {', '.join(missing)}")

    proof: dict[str, Any] = {
        "schema": PRIVATE_COMPUTE_PAID_SMOKE_PROOF_SCHEMA,
        "recordedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "model": args.model,
        "routerBaseUrl": args.router_base_url,
        "chatCompletionsUrl": args.chat_completions_url,
        "promptHash": args.prompt_hash,
        "requestHash": args.request_hash,
        "responseHash": args.response_hash,
        "routerReceiptHash": args.router_receipt_hash,
        "budgetUsd": str(args.budget_usd),
        "costUsd": str(args.cost_usd),
        "operatorReviewedBudget": True,
        "promptSafeForInference": True,
        "paidInferencePerformedExternally": True,
        "rawPromptStored": False,
        "rawPromptReturned": False,
        "rawResponseStored": False,
        "rawResponseReturned": False,
        "apiKeyReturned": False,
        "privateKeysReturned": False,
        "paymentHeadersStored": False,
        "transactionSigningByZeroGuard": False,
        "transactionBroadcastingByZeroGuard": False,
        "moneyMovementByZeroGuard": False,
        "safety": {
            "recorderNetworkCalls": False,
            "recorderReadApiKey": False,
            "recorderStoredRawPrompt": False,
            "recorderStoredRawResponse": False,
            "recorderReadPrivateKeys": False,
            "recorderSignedTransactions": False,
            "recorderBroadcastTransactions": False,
            "recorderMovedFunds": False,
        },
    }

    out_path = Path(args.out)
    verification = verify_private_compute_paid_smoke_proof(proof, proof_path=out_path)
    if verification.get("verified") is not True:
        print(json.dumps(verification, sort_keys=True), flush=True)
        raise SystemExit("0G Private Computer paid smoke proof metadata failed verification")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = out_path.with_suffix(f"{out_path.suffix}.tmp")
    tmp_path.write_text(json.dumps(proof, sort_keys=True, indent=2), encoding="utf-8")
    tmp_path.replace(out_path)
    print(
        json.dumps(
            {
                "schema": "0guard.0g_private_compute_paid_smoke_proof_record.v1",
                "out": str(out_path),
                "verification": verification,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
