# 0guard Data Flows

## Goal

Turn the incident list into a validated, inspectable data product instead of
loose demo copy.

## Current Pipeline

1. Load `data/april_2026_incidents.json`.
2. Validate required fields:
   - `id`
   - `date`
   - `protocol`
   - `loss_usd`
   - `chain`
   - `attack_vector`
   - `description`
   - `attribution`
   - `lesson`
3. Check dataset invariants:
   - unique integer IDs
   - ISO dates
   - non-empty text fields
   - non-negative integer losses
   - meta incident count equals row count
   - meta total loss equals computed total
4. Compute a SHA-256 dataset fingerprint.
5. Produce summary statistics:
   - total and average loss
   - top losses
   - chain counts
   - attack-vector counts
   - attribution counts
6. Convert incidents into preview-mode detection seeds and run them through the
   signature engine.
7. Explain per-incident signature coverage, detector gaps, and recommended
   rule additions.
8. Maintain a rights-aware OSINT source registry with explicit source owner,
   retrieval mode, TTL, output policy, and caveats.
9. Normalize reviewed external reputation payloads from PhishDestroy,
   CryptoScamDB, Forta labelled datasets, GoPlus, Chainabuse, or Forta GraphQL
   into derived evidence without making public-route network calls or returning
   raw payload dumps.
10. Promote reviewed derived source evidence into per-incident provenance fields
   while keeping unresolved root-cause claims in research/watch mode.
11. Build an evolving detector queue from uncovered incident gaps and expose the
    current 0G Chain, Storage, DA, and Compute proof plan.
12. Convert intent verdicts into wallet-specific alert previews with score,
    dedupe, cooldown, and Telegram no-send message text.
13. Compose a threat case file that stitches policy, signatures, normalized
    adapter evidence, reputation, alert quality, provenance, and 0G-ready
    receipts into one review packet.
14. Rank and preview frontier experiments for 0G Storage/Compute, reputation,
    EVM simulation, TON, and Mira without enabling live side effects.

## API Readbacks

| Route | Purpose |
|---|---|
| `/api/data/summary` | Validation, fingerprint, aggregate stats, top losses. |
| `/api/data/incidents` | Filterable public incident rows. |
| `/api/data/provenance` | Per-incident provenance matrix and optional live DeFiLlama correlation. |
| `/api/data/detection-coverage` | Signature-engine coverage over incident-derived seeds. |
| `/api/data/signature-map` | Per-incident match explanation, gaps, and recommended detectors. |
| `/api/osint/sources` | Rights-aware source registry and output policy. |
| `/api/osint/readiness` | Catalog posture; `?live=1` performs public availability checks. |
| `/api/osint/signals` | Normalized incident/research leads; `?live=1` fetches live public metadata. |
| `/api/intelligence/evolving` | Detector loop, emerging gaps, live-source status, and 0G suite map. |
| `/api/reputation/adapters` | No-network normalization contract for PhishDestroy, CryptoScamDB, Forta labelled datasets, GoPlus, Chainabuse, and Forta GraphQL payload shapes. |
| `/api/reputation/adapters/normalize` | Converts caller-provided upstream payloads into derived evidence and hashes. |
| `/api/0g/proof-ladder` | Builds a Chain, Storage, DA, Compute, and Alignment verifier packet without live uploads, inference, signing, or broadcasts. |
| `/api/wallet/alert-preview` | Wallet-specific alert scoring and digest-only emerging risk notes. |
| `/api/threat-case-file` | Composed proof dossier for one agent intent; no signing, sends, uploads, posts, bridges, swaps, or payments. |
| `/api/experiments/frontier` | Ranked read-only frontier experiment lab. |
| `/api/experiments/run` | Deterministic no-side-effect preview for one frontier experiment. |
| `/api/hackathon/submission-brief` | HackQuest-ready brief, data stats, 0G story, and operator TODOs. |
| `/api/hackathon/submission-packet` | Copy-ready HackQuest form fields and explicit operator placeholders. |
| `/api/hackathon/readiness` | Final HackQuest readiness audit with mainnet proof, demo, and X blockers. |

Example:

```bash
curl -s http://127.0.0.1:8109/api/data/summary | python3 -m json.tool
curl -s 'http://127.0.0.1:8109/api/data/incidents?chain=Ethereum&min_loss_usd=100000&limit=5' | python3 -m json.tool
curl -s 'http://127.0.0.1:8109/api/data/provenance?live=1' | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/data/detection-coverage | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/data/signature-map | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/osint/sources | python3 -m json.tool
curl -s 'http://127.0.0.1:8109/api/osint/signals?live=1&limit=10' | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/intelligence/evolving | python3 -m json.tool
curl -s -X POST http://127.0.0.1:8109/api/wallet/alert-preview \
  -H "Content-Type: application/json" \
  -d '{"address":"0x885b0892D241Cb5033C9995e09cA521d54f936b5","intent":{"action":"read_balance","mode":"simulation","method":"eth_getBalance"}}' \
  | python3 -m json.tool
curl -s -X POST http://127.0.0.1:8109/api/threat-case-file \
  -H "Content-Type: application/json" \
  -d '{"intent":{"action":"approve","mode":"live_transaction","requires_signature":true,"target_contract":"0x02228b0afcdbEdf8180D96Fc181Da3AF5DD1d1ab"}}' \
  | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/experiments/frontier | python3 -m json.tool
curl -s -X POST http://127.0.0.1:8109/api/experiments/run \
  -H "Content-Type: application/json" \
  -d '{"experimentId":"zero_g_storage_receipt_readback"}' \
  | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/hackathon/submission-packet | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/hackathon/readiness | python3 -m json.tool
```

## Provenance

The dataset carries aggregate upstream source URLs in `meta.source_urls`.
It also now carries per-incident `source_urls` and `derived_source_evidence`
for all 28 incidents. New enrichments were promoted from public BlockSec,
SlowMist, Smart Contract Hacking, and corroborating news/timeline sources while
preserving rights boundaries: APIs return links, metadata, hashes, confidence,
and defensive summaries rather than raw article bodies.

`data/osint_sources.json` is the source-rights registry for the next layer of
provenance. Each source records:

- source owner and URL
- retrieval mode and freshness TTL
- license or rights envelope
- output policy
- caveats and disabled/default status

Default outputs are derived metadata, links, hashes, readiness, and defensive
analysis. Raw upstream payloads are not exposed by API routes.

The May 16-17 catalog expansion added disabled-by-default activation
candidates for ThreatFox recent IOCs, the Chainalysis sanctions oracle and
Sanctions API, TRM Wallet Screening, TRM BLOCKINT, and Google Cloud Web Risk,
plus a catalog-only MITRE ATT&CK Lazarus Group context lane. These are tracked
as production-grade lanes only after auth, commercial-use, privacy, and
retention checks are approved; the public product still exposes derived
signals and 0G-ready receipts, not upstream feed dumps.

The provenance matrix uses `data/incident_provenance_cache.json` for a reviewed
derived-evidence cache, so the judge demo remains useful without network access.
It can also correlate canonical incidents against DeFiLlama's public hack index
when `?live=1` is supplied. Both modes return matched source metadata,
confidence, record hashes, and a recommended next step for each incident. This
keeps live source evidence separate from raw upstream payloads, while preserving
the reviewed derived evidence in `data/april_2026_incidents.json`.

As of the source-enrichment pass, the signature engine covers 28 of 28
incident-derived seeds (`1.0` coverage). Added coverage includes negative
amount/accounting invariants, unsafe casts and decimal mismatches, first
depositor vault share inflation, router quote-denomination mismatches,
account-binding and rewards-accounting faults, cross-chain bridge/control
risks, hot-wallet or privileged-key operational-security context, and the
promoted `Quant` EIP-7702 delegated account / permissionless batch-call
access-control failure.

Next durable upgrade:

- Add more protocol-authored postmortem or transaction-level URLs when they
  appear, especially for high-level BlockSec/SlowMist classifications.
- Keep monitoring the `Quant`/`QNT` record for protocol-authored postmortems or
  transaction-level traces that can further sharpen the promoted detector.
- Add `detection_seed` overrides for cases where the generic attack vector is
  too weak to exercise the signature engine.
- Promote detector-gap candidates from `/api/intelligence/evolving` only after
  a reproducible source-backed pattern and regression test exist.
- Promote catalog-only sources with compatible licenses into normalized
  adapters one at a time.
- Store the normalized dataset fingerprint in 0G Storage once live storage
  credentials are configured.
