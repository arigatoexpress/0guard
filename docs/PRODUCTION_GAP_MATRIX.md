# Production Gap Matrix

This is the live honesty layer for ZeroGuard. It answers the question judges,
operators, and future customers will ask first: what is real, what is local,
what is only source-ready, and what is still demo fixture material?

Machine-readable routes:

```bash
curl -s http://127.0.0.1:8109/api/production/gaps | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/product/strategy-review | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/model/training-roadmap | python3 -m json.tool
curl -s 'http://127.0.0.1:8109/api/model/incident-eval-set?limit=3' | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/reputation/backfill/status | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/0g/storage-upload/manifest | python3 -m json.tool
curl -s -i http://127.0.0.1:8109/api/x402/dry-run/wallet-preflight
curl -s http://127.0.0.1:8109/api/0g/private-computer/smoke-preview | python3 -m json.tool
```

The routes are read-only. They do not fetch live vendor feeds, call paid
inference, send Telegram messages, sign transactions, broadcast transactions,
settle x402 payments, or move funds.

`/api/product/strategy-review` is the opinionated layer on top of this matrix:
it narrows the product to pre-wallet risk receipts, lists what should be
deferred, and orders the next production gates.

## Current Classification

| Class | Meaning | Current examples |
| --- | --- | --- |
| `live_real_data` | Evidence-backed data that exists now and is safe to claim. | 28-incident corpus, 0G mainnet receipt anchor, Pi mesh snapshot. |
| `local_only` | Real operator telemetry or state, but not yet production-hosted or externally durable. | RV Windows storage-node soak, local JSON Telegram opt-in store, local app runtime. |
| `source_ready_live_pending` | The source, contract, SDK, or API path is identified, but production ingestion or settlement is not live. | 0G Storage upload/readback, 0G Private Computer, x402 settlement, TRM/Chainalysis. |
| `mock_fixture_only` | Useful for demos/tests but not customer intelligence. | Workbench samples, MetaMask x 1Shot permission preview payload, peer outreach demo contact. |

## Real Now

- Validated April 2026 exploit corpus: 28 incidents, source-linked evidence,
  detector coverage of 28 of 28, and a stable dataset fingerprint.
- 0G mainnet `PolicyReceiptAnchor`: one public deny receipt is anchored and
  verifier routes are wired to the mainnet profile.
- Rights-aware source registry: 34 tracked lanes and explicit raw-payload
  resale prohibition.
- First eval/backfill artifacts: `data/evals/incident_detector_eval.v1.jsonl`
  and `data/backfill/reputation_features/phishdestroy/latest.json`.
- 0G Storage upload manifest: `/api/0g/storage-upload/manifest` hashes the
  public-safe bundle and verifies local hash readback without uploading.
- x402 dry-run route: `/api/x402/dry-run/wallet-preflight` returns stable
  HTTP-402 metadata and accepts only a fixture header with settlement disabled.
- 0G Private Computer smoke contract: `/api/0g/private-computer/smoke-preview`
  scrubs prompts and refuses paid inference unless server-side gates are set.
- RV 0G storage node soak: real local snapshot, process running, only the small
  0.25 0G test funding observed, and no 100 0G transfer sent.
- Pi mesh: rvpi-a and rvpi-b are represented as a real edge snapshot with
  cluster-ready posture.

## Not Production Yet

The hard gates are deliberately explicit:

- Historical feature store: not yet populated beyond the current curated/local
  artifacts.
- Live reputation ingestion: the first open-feed derived artifact exists, but
  a supervisor schedule and credentialed vendor lanes are not live.
- 0G Storage upload/readback: bundle manifest and local hash readback exist,
  but no live 0G Storage upload or gateway proof exists.
- x402 paid routes: product manifest and dry-run HTTP-402 route exist, but no
  facilitator credentials, settlement, or spend-limited paid route is live.
- 0G Private Computer: adapter, prompt scrubber, and no-inference smoke
  contract exist, but this runtime has no server-side Router API key or paid
  inference smoke.
- Telegram: preview and opt-in routes exist, but live identity/webhook proof
  depends on server-side env and sends remain disabled.
- Storage node expansion: the funded soak still needs peer/sync blockers to
  clear before larger funding or production claims.

## Real Data Plan

Priority order:

1. Add an append-only historical feature run from the current incident corpus.
2. Install supervision around the first derived-only reputation worker.
3. Add a small DuckDB or SQLite feature store once JSONL runs are useful.
4. Upload the public-safe manifest bundle to 0G Storage and verify gateway
   readback.
5. Promote the x402 dry-run route to a testnet facilitator with spend limits.
6. Run server-side 0G Private Computer inference only after Router funding,
   API-key handling, prompt scrubber, and budget caps are tested.

## Model And Training Boundary

The model plan is eval-first:

- 0GM-1.0 should summarize, dedupe, draft, and explain deterministic packets.
- It must not approve transactions, override `deny`, send Telegram messages, or
  recommend funding while node expansion blockers remain.
- Eval data should come from deterministic verdict traces, source-linked
  incidents, derived reputation features, node soak telemetry, and no-send peer
  drafts.
- Do not train on private keys, mnemonics, raw chats, payment headers, raw paid
  feeds, or unreviewed vendor payloads.

The first concrete eval artifact is now generated at
`data/evals/incident_detector_eval.v1.jsonl` with 28 deterministic cases from
the curated incident corpus. Regenerate it with:

```bash
PYTHONPATH=src .venv/bin/python scripts/build_incident_eval_set.py \
  --out data/evals/incident_detector_eval.v1.jsonl
```

The first reputation artifact is generated at
`data/backfill/reputation_features/phishdestroy/latest.json`. Regenerate it
only after reviewing source posture:

```bash
PYTHONPATH=src .venv/bin/python scripts/reputation_backfill_worker.py \
  --source phishdestroy_destroylist \
  --live \
  --out data/backfill/reputation_features/phishdestroy/latest.json
```

The official 0G docs/blog currently describe 0GM-1.0 as Apache-2.0, hosted in
0G Private Computer, and trained on 0G Compute; Private Computer exposes an
OpenAI-compatible Router endpoint; 0G Storage SDKs support upload/download and
proof verification. ZeroGuard should use those surfaces only behind the
operator gates above.

## Sources

- https://0g.ai/blog/0gm-1-0-35b-a3b
- https://0g.ai/blog/0g-private-computer
- https://docs.0g.ai/developer-hub/building-on-0g/storage/sdk
- https://docs.0g.ai/run-a-node/validator-node
