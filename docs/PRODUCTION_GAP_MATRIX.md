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
PYTHONPATH=src .venv/bin/python scripts/reputation_backfill_supervisor_check.py \
  --latest data/backfill/reputation_features/phishdestroy/latest.json
curl -s 'http://127.0.0.1:8109/api/intelligence/cyber-threats?cves=CVE-2024-3094&limit=5' | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/0g/storage-upload/manifest | python3 -m json.tool
curl -s -i http://127.0.0.1:8109/api/x402/dry-run/wallet-preflight
curl -s http://127.0.0.1:8109/api/x402/settlement-proof | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/0g/private-computer/smoke-preview | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/0g/private-computer/smoke-proof | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/0g/node-pi-readiness-proof | python3 -m json.tool
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
- Rights-aware source registry: 36 tracked lanes and explicit raw-payload
  resale prohibition.
- Web2/Web3 threat repository: `/api/intelligence/cyber-threats` composes CISA
  KEV, NVD CVE, MITRE ATT&CK Lazarus/Shai-Hulud context, exact-address OFAC
  screening, and the historical crypto exploit corpus into derived-only
  defensive signals.
- First eval/backfill artifacts: `data/evals/incident_detector_eval.v1.jsonl`
  and `data/backfill/reputation_features/phishdestroy/latest.json`.
- Reputation freshness supervision: `.github/workflows/reputation-backfill-supervisor.yml`
  runs the derived-only PhishDestroy worker in no-write mode every six hours and
  fails closed if the latest artifact is stale or raw-payload flags regress.
  `/api/reputation/backfill/status` exposes `freshWithinTtl`,
  `supervisorInstalled`, and `supervisedFreshnessReady` at the top level so the
  hosted API can be checked without digging through nested manifests.
- 0G Storage upload manifest: `/api/0g/storage-upload/manifest` hashes the
  public-safe bundle, exposes the deterministic upload artifact hash, verifies
  local hash readback without uploading, and now surfaces flat
  `status`/`verified`/`proofPresent`/`bundleRoot` fields for public readback.
- 0G Storage live-proof rail: `scripts/build_0g_storage_bundle.py` writes the
  exact public-safe JSON artifact for an operator-run SDK upload, and
  `scripts/record_0g_storage_live_proof.py` records the externally uploaded
  root/tx/readback hashes without calling a gateway, reading keys, signing, or
  moving funds. A verified `docs/hackathon-0g/0g-storage-live-proof.json`
  artifact is what turns the readiness gate green.
- Historical feature store exports: the latest JSONL alias remains available
  for manifesting, while each writer run also creates an immutable `runs/*.jsonl`
  artifact with a receipt hash.
- x402 dry-run route: `/api/x402/dry-run/wallet-preflight` returns stable
  HTTP-402 metadata and accepts only a fixture header with settlement disabled.
- x402 settlement-proof rail: `/api/x402/settlement-policy` now includes
  proof status, caps/terms hashes, and the external proof recorder command
  template, while `/api/x402/settlement-proof` verifies an externally performed
  Base Sepolia payment using only public receipt fields and hashes.
  `scripts/record_x402_base_sepolia_settlement_proof.py` writes the artifact
  only after caps/terms acknowledgement and never stores raw payment headers.
- Wallet-provider external proof rail: `/api/wallet/provider-proof` verifies a
  real wallet-extension `window.ethereum` proof when recorded. The recorder
  keeps only receipt hashes and public metadata from a throwaway empty wallet
  run; CI's mock-provider smoke remains useful but is not treated as production
  wallet proof.
- 0G Private Computer smoke contract: `/api/0g/private-computer/smoke-preview`
  scrubs prompts and refuses paid inference unless server-side gates are set.
  `/api/0g/private-computer/smoke-proof` verifies a separately performed paid
  smoke using only prompt/request/response hashes, bounded-cost metadata, and
  no-secret/no-raw-payload flags. The recorder
  `scripts/record_0g_private_compute_paid_smoke.py` writes the proof artifact
  only after budget, prompt-safety, and external-inference acknowledgements.
- RV 0G storage node soak: real local snapshot, process running, public storage
  and DA relay sockets restored, only the small 0.25 0G test funding observed,
  and no 100 0G transfer sent.
- Node/Pi readiness proof rail: `/api/0g/node-pi-readiness-proof` verifies a
  public-safe redacted operator artifact for the storage-node soak, peer
  diagnostics, and Pi mesh. The recorder consumes already collected snapshots;
  it does not SSH, probe the LAN, read keys, sign, broadcast, move funds, or
  send messages.
- Pi mesh: rvpi-a and rvpi-b are represented as a real edge snapshot, but the
  current LAN readback may be offline and must not be treated as production
  cluster proof.

## Not Production Yet

The hard gates are deliberately explicit:

- Historical feature store: not yet populated beyond the current curated/local
  artifacts and immutable seed exports.
- Live reputation ingestion: the first open-feed derived artifact and scheduled
  freshness supervisor exist; broader production protection still needs
  additional source families and credentialed/vendor lanes only after terms and
  retention review.
- Sanctions and Web2 vulnerability ingestion: public CISA/NVD/OFAC workers now
  exist, but production blocking still requires source freshness supervision,
  dependency/address matching, retention rules, and vendor/legal review before
  customer compliance claims.
- 0G Storage upload/readback: bundle manifest, deterministic upload artifact,
  offline proof recorder, and recorder command template exist, but no live 0G
  Storage upload or gateway proof has been recorded yet.
- x402 paid routes: product manifest, dry-run HTTP-402 route, caps/terms, and
  settlement-proof recorder/operator packet exist, but no Base Sepolia
  facilitator proof has been recorded in this runtime and no mainnet settlement
  is enabled.
- Wallet-provider protection: hosted guard API, SDK wrapper, and external dapp
  exist, but no real extension/throwaway-wallet proof artifact has been
  recorded yet.
- 0G Private Computer: adapter, prompt scrubber, no-inference smoke contract,
  and paid-smoke proof verifier exist, but this runtime has no server-side
  Router API key or recorded paid inference smoke.
- Telegram: preview and opt-in routes exist, but live identity/webhook proof
  depends on server-side env and sends remain disabled.
- Storage node expansion: the funded soak still needs peer depth to clear before
  larger funding or production claims.
- Node/Pi cluster proof: the recorder and route exist, but readiness remains
  blocked until peer depth, sync posture, and both Pi heartbeat checks are green
  in the redacted proof artifact.

## Real Data Plan

Priority order:

1. Add an append-only historical feature run from the current incident corpus.
2. Install supervision around the first derived-only reputation worker.
3. Add a small DuckDB or SQLite feature store once JSONL runs are useful.
4. Build the deterministic public-safe bundle, upload it with the official 0G
   Storage SDK from a reviewed signer environment, download it back, and record
   `docs/hackathon-0g/0g-storage-live-proof.json` only if the downloaded hash
   equals the uploaded bundle hash.
5. Run one reviewed Base Sepolia x402 payment from a throwaway buyer wallet,
   then record only the tx hash, hashed payment header, response hash, and
   reviewed caps/terms metadata with
   `scripts/record_x402_base_sepolia_settlement_proof.py`.
6. Record `docs/hackathon-0g/node-pi-readiness-proof.json` after the read-only
   storage-node, peer-diagnostics, and Pi-mesh snapshots show green readiness.
7. Run server-side 0G Private Computer inference only after Router funding,
   API-key handling, prompt scrubber, and budget caps are tested; then record
   `docs/hackathon-0g/0g-private-compute-paid-smoke-proof.json` with
   `scripts/record_0g_private_compute_paid_smoke.py`.

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
