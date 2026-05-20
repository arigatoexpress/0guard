# Local Inference, x402, and Historical Backfill

This document is the operator map for weaving local Windows/Pi inference, x402
data products, and historical data backfill into ZeroGuard without weakening the
safety boundary.

## Current Architecture

| Layer | Route | Status |
| --- | --- | --- |
| Local inference mesh | `/api/local-inference/status` | Read-only live probe when `?live=1`; no prompts. |
| Telegram digest | `/api/telegram/local-inference-preview` | Preview-only message body; no Telegram send. |
| 0G Private Computer smoke | `/api/0g/private-computer/smoke-preview`, `/api/0g/private-computer/smoke-proof` | Prompt scrub and no-inference request contract plus proof verification for one externally performed paid smoke; paid calls remain blocked by env/key/budget gates. |
| x402 data products | `/api/x402/data-products`, `/api/x402/dry-run/wallet-preflight`, `/api/x402/settlement-policy`, `/api/x402/settlement-proof` | Product manifest, dry-run HTTP 402, caps/terms hashes, external proof packet, and proof verification; no settlement from the workbench. |
| Historical backfill | `/api/data/backfill-plan`, `/api/reputation/backfill/status` | Backfill schema plus first derived reputation artifact. |
| Production gap matrix | `/api/production/gaps` | Real/local/source-ready/mock classifier; no live fetch. |
| Model training roadmap | `/api/model/training-roadmap` | Eval-first 0GM/local model data plan; no training run. |
| Incident eval set | `/api/model/incident-eval-set` | Deterministic JSONL-ready cases from the real incident corpus. |
| Storage bundle | `/api/0g/storage-upload/manifest` | Public-safe bundle hashes and local readback; no live upload. |

The Windows machine is treated as the future heavy local inference host. The
Raspberry Pis are treated as sentinels and proof caches, not key holders. The
0G Private Computer path remains the attested external inference layer for
sensitive summaries after an operator-funded server-side key exists.

## Telegram Bridge Shape

The Telegram bot should call ZeroGuard routes in this order:

1. Deterministic status and policy routes first.
2. Local inference mesh status second.
3. A model summary only after a local model is loaded and the prompt is scrubbed.
4. 0G Private Computer only after Router funding, API-key storage, and prompt
   minimization are reviewed.
5. The first paid 0G Private Computer smoke should be recorded as hashes and
   bounded-cost metadata only; do not store the raw prompt, raw model response,
   Router API key, private keys, or payment headers.

Allowed Telegram command ideas:

| Command | Backend | Sends? |
| --- | --- | --- |
| `/zg systems` | `/api/local-inference/status?live=1` | Preview only today. |
| `/zg node` | `/api/0g/storage-node/status?snapshot=1` | Preview only today. |
| `/zg risk <address-or-url>` | deterministic reputation/policy routes | Preview only today. |

No route in this repo sends Telegram messages, signs wallet transactions,
broadcasts onchain messages, or executes paid inference from the browser.

## x402 Product Wedge

x402 is useful because it makes defensive intelligence accessible to agents over
ordinary HTTP: a buyer requests a protected route, the server can respond with
`402 Payment Required`, and payment metadata can be settled through a
facilitator. For ZeroGuard, the sellable unit is derived defensive analysis:

| Product | Why someone pays | Raw resale? |
| --- | --- | --- |
| Wallet preflight verdict | Agents can check before requesting a signature. | No |
| Threat packet summary | Wallets get a source-cited explanation. | No |
| Node health snapshot | 0G operators get sync/peer blocker snapshots. | No |
| Reputation shadow digest | Telegram/wallet surfaces get deduped risk features. | No |
| Historical incident features | Builders get pattern features, not raw archives. | No |

Preparation order:

1. Keep `/api/x402/data-products` as a manifest.
2. Use `/api/x402/dry-run/wallet-preflight` as the dry-run protected route
   that returns fixture 402 metadata.
3. Add MetaMask Smart Account / ERC-7710 permission checks for bounded access.
4. Add 1Shot or x402.org facilitator testing on Base Sepolia after spend
   limits are fixed.
5. Record only public receipt metadata with
   `scripts/record_x402_base_sepolia_settlement_proof.py`; never store raw
   `X-PAYMENT` headers, signatures, or private keys.
6. Use `/api/x402/settlement-policy` as the operator packet: it exposes the
   payment requirement, caps hash, terms hash, proof status, and recorder
   command template without calling a facilitator.
7. Use `/x402/v1/wallet-preflight` only on a tagged/no-traffic revision with
   `ZG_X402_ENABLE_SETTLEMENT=1`; public revisions keep this route disabled.
   The route is protected by the official x402 Flask middleware and should be
   exercised first on Base Sepolia for a single `0.01 USDC` proof.
8. Only then consider mainnet settlement for a single low-cost route.

Before the first Base Sepolia settlement proof, check the throwaway buyer
wallet without touching its encrypted keystore:

```bash
PYTHONPATH=src .venv/bin/python scripts/x402_base_sepolia_buyer_status.py \
  --manifest ~/.0guard-secrets/wallets/x402-base-sepolia-buyer-*.public.json \
  --update-manifest
```

The status should become `ready_for_external_x402_settlement_proof` after the
throwaway buyer has at least `10000` atomic USDC (`0.01 USDC`) at
`0x036CbD53842c5426634e7929541eC2318f3dCF7e`. Base Sepolia USDC x402 uses an
EIP-3009-style buyer authorization and facilitator-sponsored settlement gas, so
the buyer does not need native Base Sepolia ETH for this proof path. The script
still reads the native balance as public context, performs only read-only RPC
calls, does not read the keystore, does not request the Keychain passphrase, and
does not call the facilitator.

Sources:

- https://docs.cdp.coinbase.com/x402/welcome
- https://docs.cdp.coinbase.com/x402/network-support
- https://docs.cdp.coinbase.com/x402/bazaar
- https://www.x402.org/

## Backfill Policy

Backfill is how ZeroGuard becomes durable instead of ephemeral. The priority is
historical incident and reputation data first, then node telemetry, then redacted
Telegram opt-in metadata, then future x402 receipts.

Rules:

- Store derived features, source ids, source URLs, timestamps, and hashes.
- Do not store private keys, mnemonics, raw Telegram chats, payment headers, or
  raw paid-feed payloads.
- Keep each backfill run immutable and fingerprinted; latest aliases are for
  operator convenience, not the source of audit truth.
- Separate public-safe artifacts from operator-only local snapshots.
- Put every paid or licensed source behind a rights envelope before it can affect
  a product route.

The current schema is exposed by `/api/data/backfill-plan`, and the first live
derived reputation artifact is exposed by `/api/reputation/backfill/status`.
Regenerate it with:

```bash
PYTHONPATH=src .venv/bin/python scripts/reputation_backfill_worker.py \
  --source phishdestroy_destroylist \
  --live \
  --out data/backfill/reputation_features/phishdestroy/latest.json
```

Implementation should continue with immutable JSONL run artifacts plus a latest
alias, then graduate to DuckDB or SQLite when query volume justifies it.

## Production Gap And Model Roadmap

`/api/production/gaps` is the higher-level truth surface. It joins the source
registry, readiness checks, storage-node snapshot, Pi mesh snapshot, x402 plan,
0G Private Computer manifest, and backfill plan into one machine-readable
matrix. Its job is to keep claims crisp:

- `live_real_data` means we can safely claim it today.
- `local_only` means real operator evidence exists but it is not hosted or
  externally durable yet.
- `source_ready_live_pending` means the API/SDK/source is known but the live
  production path is not active.
- `mock_fixture_only` means the artifact is a demo or test fixture.

`/api/model/training-roadmap` keeps the 0GM/local model loop eval-first. The
allowed model jobs are summarization, dedupe, draft review, and explanation of
deterministic verdict packets. The model is not authority for allow/deny
decisions, money movement, Telegram sends, or node funding.

The first export is `data/evals/incident_detector_eval.v1.jsonl`, generated from
the existing 28 source-linked April 2026 incidents:

```bash
PYTHONPATH=src .venv/bin/python scripts/build_incident_eval_set.py \
  --out data/evals/incident_detector_eval.v1.jsonl
```
