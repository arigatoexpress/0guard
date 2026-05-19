# Reputation Adapter

0guard should not claim a live global reputation graph until the upstream
source contracts and paid feeds are configured. What is useful today is a
rights-aware adapter contract that accepts domain, counterparty, labels, source
evidence, and intent context, then returns a derived verdict with a 0G-ready
receipt.

## API

```bash
curl -X POST http://127.0.0.1:8109/api/reputation/probe \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://docs.0g.ai.evil.example/claim",
    "address": "0x02228b0afcdbEdf8180D96Fc181Da3AF5DD1d1ab",
    "chain": "eip155:1",
    "sourceEvidence": [
      {"sourceId": "operator_report", "verdict": "phishing", "confidence": 0.91}
    ],
    "intent": {
      "action": "upgrade",
      "mode": "live_transaction",
      "requires_signature": true
    }
  }'
```

Expected result: `deny`, with signals for allowlist suffix spoofing, local IOC
match, source negative vote, and intent policy context.

## What It Uses Today

- Curated allowlist domain matching for official 0G, HackQuest, and GitHub
  surfaces.
- Local IOC matches from the existing 0guard exploit signature module.
- Caller-supplied source votes, converted into derived hashes and labels.
- A first live-derived PhishDestroy backfill artifact at
  `data/backfill/reputation_features/phishdestroy/latest.json`.
- The existing policy engine for signer, calldata, and prompt-risk context.

## Connector Activation Manifest

`GET/POST /api/reputation/connectors` returns the next external connectors as a
no-network, rights-aware manifest. This keeps the roadmap concrete without
pretending that paid or keyed feeds are live.

The manifest now prioritizes PhishDestroy, CryptoScamDB, and Forta labelled
datasets first, then GoPlus, Chainabuse, Forta GraphQL, Scam Sniffer,
ThreatFox, URLhaus, the Chainalysis sanctions oracle, the Chainalysis Sanctions
API, TRM Wallet Screening, TRM BLOCKINT, Google Web Risk, TON Center, TONAPI,
Tenderly, BlockSec Phalcon, LayerZero Scan, and Wormholescan.
Each row includes the use case, docs URL, credential posture, whether it
applies to the submitted subject, and the output/rights boundary.

Example:

```bash
curl -X POST http://127.0.0.1:8109/api/reputation/connectors \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://docs.0g.ai.evil.example/claim",
    "address": "0x02228b0afcdbEdf8180D96Fc181Da3AF5DD1d1ab",
    "chain": "eip155:1"
  }'
```

Expected result: schema `0guard.reputation_connectors.v1`, with `networkCalls`
set to `false`, raw payload return disabled, and open-source phishing/domain
feeds plus EVM reputation, sanctions, AML/vendor intelligence, malware-IOC,
and commercial URL safety connectors marked as relevant activation candidates
for an EVM address/domain subject.

## Derived Backfill Worker

`scripts/reputation_backfill_worker.py` promotes the reviewed PhishDestroy
connector into a persisted feature artifact without returning raw domains or
feed rows. The latest status is exposed at:

```bash
curl http://127.0.0.1:8109/api/reputation/backfill/status
```

Regenerate the artifact after reviewing network/source posture:

```bash
PYTHONPATH=src .venv/bin/python scripts/reputation_backfill_worker.py \
  --source phishdestroy_destroylist \
  --live \
  --out data/backfill/reputation_features/phishdestroy/latest.json
```

Expected result: schema `0guard.reputation_backfill_run.v1`, parsed-domain
count, feed hash, derived evidence hashes, and `rawDomainsReturned=false`.
The worker is not a scheduler yet; `supervisorInstalled=false` stays visible
until a launchd/systemd/cron wrapper is reviewed.

## Adapter Normalization Contract

`GET /api/reputation/adapters` exposes the exact no-network payload families
0guard is ready to normalize first: PhishDestroy, CryptoScamDB, OFAC SLS, Forta
labelled datasets, GoPlus Security, Chainabuse, Forta GraphQL alerts/labels,
DeFiLlama incidents, EVM event indexes, and software advisory/CVE context. This
is a contract, not a fetcher.

`POST /api/reputation/adapters/normalize` accepts a caller-provided upstream
payload from an operator-reviewed worker and returns only derived evidence:
source id, verdict, confidence, labels/categories, evidence hash, reference URL
hash, a recommended probe payload, and a preview reputation decision.

Example:

```bash
curl -X POST http://127.0.0.1:8109/api/reputation/adapters/normalize \
  -H "Content-Type: application/json" \
  -d '{
    "sourceId": "chainabuse",
    "subject": {
      "url": "https://docs.0g.ai.evil.example/claim",
      "address": "0x02228b0afcdbEdf8180D96Fc181Da3AF5DD1d1ab",
      "chain": "eip155:1"
    },
    "payload": {
      "reports": [
        {"checked": true, "confidence_score": 91, "category": "phishing"}
      ]
    }
  }'
```

Expected result: schema `0guard.reputation_adapter_preview.v1`,
`rawPayloadReturned=false`, `networkCalls=false`, and a derived evidence row that
can be passed into `/api/reputation/probe`, `/api/threat-case-file`, wallet
alert previews, or the Telegram Mini App.

Aliases are accepted for the new cyber/sanctions lane:

- `cisa_kev` and `nvd_cve` normalize through `software_advisory_cve`.
- `ofac_sanctions` normalizes through `ofac_sanctions_sls`.

`GET/POST /api/reputation/connectors/live` now has reviewed live workers for
PhishDestroy, CISA KEV, NVD CVE, and OFAC SLS. Live mode is opt-in with
`live=1`; CISA/NVD reduce official public feeds to CVE ids, severity/context,
hashes, links, and derived evidence. OFAC is exact-address oriented and returns
redactions, hashes, counts, and not-legal-advice categories rather than raw SDN
rows or full wallet lists.

## Derived Shadow Cache

`GET/POST /api/reputation/shadow-cache` composes several reviewed adapter
payloads into one reusable local intelligence snapshot. The default `GET`
response uses sanitized PhishDestroy, CryptoScamDB, and Forta-shaped evidence
so the workbench can show the full path without a live fetcher.

Example:

```bash
curl http://127.0.0.1:8109/api/reputation/shadow-cache
```

Expected result: schema `0guard.reputation_shadow_cache.v1`, source-level
verdict counts, a probe preview, activation queue, and a 0G-ready cache receipt.
The route returns source IDs, confidence, categories, evidence hashes, and
reference URL hashes only. It does not return raw upstream feed rows.

## Rights Boundary

The adapter returns derived decisions, source IDs, labels, confidence, hashes,
and redacted addresses. It does not return raw source payloads, scrape private
feeds, custody credentials, or make network calls.

## Where It Fits

- `/api/native-preflight` includes a `reputation_probe` component when the
  caller supplies a domain, counterparty, label, or source evidence.
- `/api/reputation/connectors` shows which external streams should be enabled
  next and under which rights/safety rules.
- `/api/intelligence/cyber-threats` composes CISA/NVD/OFAC connector snapshots,
  MITRE ATT&CK context, and the historical exploit feature set into one
  derived-only Web2/Web3 threat repository.
- `/api/reputation/adapters/normalize` is the bridge between reviewed upstream
  connector workers and public-safe derived evidence.
- `/api/reputation/shadow-cache` gives Telegram, wallet alerts, and 0G receipt
  workflows a stable derived cache between reviewed connector-worker runs.
- `/api/threat-case-file` now surfaces normalized adapter evidence as a
  first-class evidence row without exposing raw payloads.
- `/api/wallet/alert-preview`, `/api/telegram/wallet-alert-preview`, and
  `/api/telegram/miniapp/preview` can promote reputation `deny` or `review`
  into a concise no-send alert even when the base wallet intent is read-only.
- `/api/developer-kit` points adapter builders at the route.
- Telegram and wallet alerts can use this as the next enrichment layer before
  stronger claims about live address reputation.
