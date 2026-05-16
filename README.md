# 🔒 0guard

> **AI Agent Firewall + Signature/Behavioral Detection for Crypto Hacks**  
> Built on [0G](https://0g.ai) decentralized AI infrastructure.

[![CI](https://github.com/arigatoexpress/0guard/actions/workflows/ci.yml/badge.svg)](https://github.com/arigatoexpress/0guard/actions)

---

## One-Sentence Pitch

0guard is a read-only, pre-wallet safety layer that uses source-linked April 2026 exploit intelligence to detect and block crypto hacks before an AI agent ever reaches a signing key.

---

## Problem

- **0guard's source-linked April 2026 dataset covers $635M+ in reported losses across 28 DeFi/DEX incidents.**
- **Public sources attribute the largest loss clusters to North Korea's Lazarus Group** using social engineering, bridge misconfiguration, and admin-key compromise.
- **The two largest exploits involved zero smart-contract bugs**; they were pure operational-security failures.
- AI agents operating on fast L1s/L2s can make wallet mistakes *instantly*; few tools check agent intent before the signer.

## Solution

0guard gives every AI agent a **pre-wallet security copilot**:

1. **Intent Firewall** — Evaluates every action as `allow`, `review`, or `deny` before it reaches a wallet.
2. **Hack Signature Detection** — Built-in IOCs, calldata selectors, and behavioral sequences derived from **source-linked April 2026 incidents** (Drift, Kelp DAO, Wasabi, Rhea, Volo, Giddy, HyperBridge, Aftermath, Sweat Foundation).
3. **0G-Native Proofs** — Reads live 0G status, prepares policy receipt hashes, and includes a public 0G mainnet receipt anchor proof while keeping workbench writes operator-controlled.
4. **0G Proof Ladder** — Builds a Chain, Storage, DA, Compute, and Alignment proof packet for one verdict without uploading, inferring, signing, broadcasting, or operating a node.
5. **OSINT Data Pipeline** — Normalizes rights-aware public source registries, live incident/research leads, source readiness, and signature coverage gaps.
6. **Reputation Probe** — Checks domains, counterparties, labels, caller evidence, and intent context without reselling raw OSINT payloads.
7. **External Guardrail Catalog** — Catalogs read-only EVM networks, x402 posture, Lighter exchange/API intents, DA proof lanes, and bridge-protocol risk lanes; no settlement, orders, bridges, or launches.
8. **Telegram Mira Opt-In** — Provides secure Telegram Mini App registration primitives and Mira response previews without live sends.
9. **Zero Trust by Default** — Refuses signing, raw transactions, bridges, swaps, and approvals unless explicitly cleared.

---

## 0G Integration

| 0G Component | How We Use It | Hackathon Track Fit |
|---|---|---|
| **0G Chain** (EVM-compatible) | Public 0G mainnet `PolicyReceiptAnchor` with one anchored deny receipt; workbench path remains read-only/preflight. | Agentic Infrastructure |
| **0G Storage** (KV + Log) | Deterministic threat-intel payload/root-hash preparation; external writes stay opt-in. | Privacy & Sovereign Infrastructure |
| **0G Compute** (Inference) | Planned 0G Compute scoring adapter; current demo uses deterministic policy/signature checks. | Agentic Infrastructure |
| **Agent ID** (ERC-7857) | Every evaluation is tagged with a persistent agent identity for accountability. | Agentic Economy |

### Smart Contract

`contracts/PolicyReceiptAnchor.sol` — A minimal 0G Chain contract that stores `(receipt_hash, decision, severity, agent_id, timestamp)` events. Fully auditable and queryable via 0G Explorer.

`contracts/PolicyReceiptAnchorV2.sol` — A prepared upgrade path for explorer-readable logs with `policyVersion`, `datasetFingerprint`, `evidenceRoot`, `storageRoot`, `shortMemo`, and `sourceIds`. It is not the deployed mainnet contract yet.

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   AI Agent      │────▶│  0guard   │────▶│  Wallet / RPC   │
│  (OpenClaw,     │     │  (Intent Eval)   │     │  (only if allow)│
│   LangChain)    │     └──────────────────┘     └─────────────────┘
└─────────────────┘              │
                                 ▼
              ┌──────────────────────────────────────┐
              │  Crypto Hack Guard (Signatures)      │
              │  • IOC blocklist (Lazarus wallets)   │
              │  • Selector analysis (approve,       │
              │    upgradeTo, grantRole, lzReceive)  │
              │  • Behavioral sequences (flash-loan  │
              │    → swap → withdraw)                │
              │  • Social-engineering language       │
              └──────────────────────────────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
         0G Chain         0G Storage          0G Compute
    (Receipt Anchor)   (Threat Intel KV)   (AI Anomaly Model)
```

---

## Quickstart

```bash
git clone https://github.com/arigatoexpress/0guard.git
cd 0guard
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e '.[dev]'
python3 -m guard0.app
```

Open `http://127.0.0.1:8109` for the dashboard.

## Judge Fast Path

For the 0G APAC Hackathon, the fastest review path is:

1. Open the dashboard and run a risky intent through the Intent Firewall.
2. Check `/api/0g/status` for live, read-only 0G RPC proof.
3. Run `/api/evaluate` with `enable_0g_anchor` and `enable_0g_storage` to see
   receipt preflight plus a Storage-ready root hash.
4. Run `/api/data/provenance` to see the reviewed derived-evidence cache, then
   `/api/data/provenance?live=1` for live source correlation when the network
   path is healthy.
5. Use `docs/hackathon-0g/` for the submission copy, demo walkthrough, market
   intel, and mainnet gap register.
6. Use `docs/NEXT_HACKATHON_ROADMAP.md` for the post-0G sequence across
   MetaMask Smart Accounts Kit x 1Shot API, Arbitrum Open House London, and
   Injective Solo AI Builder Sprint.

Current submission proof is captured in `docs/hackathon-0g/`, including the
public X post URL, final demo video URL, HackQuest readback, and 0G mainnet
contract/explorer proof. Run
`scripts/submission_readiness.py --format markdown` for the current
final-submit audit.

---

## CLI

```bash
# Evaluate an intent
python3 -m guard0.cli evaluate \
  --intent-json '{"action":"swap","mode":"live_transaction","value_eth":0.05,"requires_signature":true}'

# Run hack-signature check only
python3 -m guard0.cli hack-check \
  --intent-json '{"action":"approve","calldata":"0x095ea7b3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}'

# Run the native preflight gate used by SDK/CI integrations
python3 -m guard0.cli native-preflight \
  --payload-json '{"surface":"evm","operation":"read_status","chain":"eip155:8453"}'

# Normalize reviewed upstream reputation evidence without fetching
python3 -m guard0.cli normalize-reputation-adapter \
  --payload-json '{"sourceId":"phishdestroy_destroylist","payload":{"active_domains":[{"domain":"docs.0g.ai.evil.example","site_status":"alive"}]}}'

# Build a reusable derived reputation shadow cache without fetching
python3 -m guard0.cli reputation-shadow-cache

# Build a no-side-effect 0G proof ladder packet
python3 -m guard0.cli proof-ladder \
  --payload-json '{"chain":"eip155:16661","intent":{"action":"approve","mode":"live_transaction","requires_signature":true}}'

# Start API server
python3 -m guard0.cli serve --port 8109
```

---

## API

| Method | Path | Purpose |
|--------|------|---------|
| `GET`  | `/api/health` | Service health + 0G config |
| `GET`  | `/api/readyz` | No-side-effect operational readiness profile for mainnet verifier config, data coverage, shadow cache, Telegram store posture, and safety |
| `GET`  | `/api/0g/status` | Live read-only 0G RPC proof, chain ID, latest block, and receipt-anchor config |
| `GET`  | `/api/0g/receipt?receipt_hash=...` | Read-only receipt-anchor lookup when `ZGG_RECEIPT_CONTRACT` is configured |
| `GET/POST` | `/api/0g/proof-ladder` | Chain, Storage, DA, Compute, and Alignment proof packet; no live uploads, inference, signing, broadcasts, or node operation |
| `GET`  | `/api/data/summary` | Validated incident dataset summary, aggregate stats, and dataset fingerprint |
| `GET`  | `/api/data/incidents` | Filterable public incident records by chain, vector, loss, and limit |
| `GET`  | `/api/data/provenance` | Per-incident provenance matrix from canonical dataset evidence; add `?live=1` to correlate against live DeFiLlama hack records |
| `GET`  | `/api/data/detection-coverage` | Runs incident-derived seeds through the signature engine and reports coverage |
| `GET`  | `/api/data/signature-map` | Explains per-incident signature matches, coverage gaps, and recommended detector additions |
| `GET`  | `/api/osint/sources` | Rights-aware OSINT source registry with owners, URLs, retrieval modes, TTLs, and caveats |
| `GET`  | `/api/osint/readiness` | Source-readiness posture; add `?live=1` for public availability checks |
| `GET`  | `/api/osint/signals` | Normalized public OSINT leads; add `?live=1&limit=10` for live metadata pulls |
| `GET`  | `/api/intelligence/evolving` | Current detector loop, emerging signature gaps, source status, and 0G Chain/Storage/DA/Compute map |
| `GET`  | `/api/intelligence/data-streams` | Ranked data-stream plan with free/paid source options, rights posture, and integration phases |
| `GET`  | `/api/product/brief` | Plain-English map of what 0guard is, what is live, honest limits, proof links, and next builds |
| `GET`  | `/api/roadmap` | No-bridge ecosystem roadmap for 0G, Telegram/TON, EVM L2s, Solana, Hyperliquid, and agent distribution |
| `GET`  | `/api/experiments/frontier` | Ranked frontier experiment lab for 0G Storage/Compute, reputation, simulation, TON, and Mira activation |
| `POST` | `/api/experiments/run` | Deterministic no-side-effect preview for one frontier experiment; no live upload, inference, signing, send, post, bridge, or payment |
| `POST` | `/api/threat-case-file` | Composed proof dossier for one risky agent intent across policy, signatures, reputation, wallet alerts, provenance, and 0G-ready receipts |
| `GET/POST` | `/api/wallet/alert-preview` | Read-only wallet alert preview with quality gates, dedupe keys, cooldowns, and no sends |
| `GET`  | `/tonconnect-manifest.json` | TON Connect manifest for presentation-only wallet context |
| `GET`  | `/api/ton/status` | TON/Telegram wallet integration posture, supported networks, and no-sign safety flags |
| `GET`  | `/api/ton/risk-rules` | Source-cited TON risk passport rules |
| `POST` | `/api/ton/wallet-risk-preview` | Read-only TON wallet risk passport; no tonProof, signature, send, or bridge |
| `GET`  | `/api/integrations/cross-chain` | Source-cited integration catalog for 0G, Virtuals/Base, x402, EVM expansion networks, Lighter exchange/API, bridge protocol guardrails, and Celestia/TIA |
| `GET`  | `/api/integrations/cross-chain/readiness` | Read-only cross-chain readiness; add `?live=1` for safe EVM RPC probes plus supported non-EVM status probes |
| `GET`  | `/api/integrations/virtuals-facilitator` | Prepared Virtuals/Base `0guard Facilitator` manifest; no live launch |
| `GET`  | `/api/integrations/ika` | Source-cited Ika, Encrypt, Ikavery, MPCKit, and OdWS integration manifest |
| `POST` | `/api/integrations/ika/evaluate` | Read-only dWallet signing preflight before MPCKit/OdWS/Ikavery; no key import or signing |
| `GET/POST` | `/api/reputation/probe` | Rights-aware domain, counterparty, label, source-evidence, and intent reputation probe; raw payloads are not returned |
| `GET/POST` | `/api/reputation/connectors` | No-network activation manifest for PhishDestroy, CryptoScamDB, Forta, GoPlus, Chainabuse, TON, simulation, and cross-chain intelligence feeds |
| `GET`  | `/api/reputation/adapters` | No-network normalization contract for PhishDestroy, CryptoScamDB, Forta labelled datasets, GoPlus, Chainabuse, and Forta GraphQL payload shapes |
| `POST` | `/api/reputation/adapters/normalize` | Converts caller-provided external reputation payloads into derived source evidence without echoing raw source payloads |
| `GET/POST` | `/api/reputation/shadow-cache` | Composes multiple reviewed adapter payloads into a reusable derived intelligence snapshot; no live fetches or raw source resale |
| `POST` | `/api/native-preflight` | Unified 0G-ready preflight across policy, Ika/dWallet, TON, and external guardrails before any signer or payment surface |
| `GET`  | `/api/hackathon/strategy` | Source-cited 0G-first roadmap for the current submission and next hackathon targets |
| `GET`  | `/api/developer-kit` | Machine-readable SDK, CI, wallet, x402, Telegram/TON, and dWallet adapter recipes for calling native preflight |
| `GET/POST` | `/api/integrations/external-guardrails` + `/evaluate` | Active read-only guardrail catalog and evaluator for x402, Virtuals/Base, Lighter, CCIP, LayerZero, Wormhole, and Celestia intents/configs |
| `GET`  | `/api/hackathon/submission-brief` | HackQuest-ready project brief, data stats, 0G story, manual TODOs, and claims to avoid |
| `GET`  | `/api/hackathon/submission-packet` | Copy-ready HackQuest form fields, required links, X commands, and remaining operator placeholders |
| `GET`  | `/api/hackathon/readiness` | Read-only final submission audit with mainnet proof, demo video, X post, and operator blockers |
| `GET`  | `/api/hackathon/threat-passport` | Judge proof drill with sample intent, verdict receipt, source evidence, detector coverage, and 0G proof slots |
| `GET`  | `/telegram` | Mobile Telegram Mini App wallet-alert surface; browser preview outside Telegram |
| `GET`  | `/api/telegram/status` | Telegram/Mira registration posture, Mini App auth support, and no-send safety flags |
| `POST` | `/api/telegram/registrations` | Create a local HMAC registration challenge; no Telegram send |
| `POST` | `/api/telegram/opt-ins` | Complete a local redacted Telegram opt-in record from a verified challenge |
| `POST` | `/api/telegram/webapp/verify` | Validate Telegram Mini App `initData` server-side when `TELEGRAM_BOT_TOKEN` is configured |
| `GET`  | `/api/telegram/miniapp/contract` | Mini App selectors, routes, Telegram Web App posture, and no-send safety contract |
| `POST` | `/api/telegram/miniapp/session` | Detect browser preview versus Telegram launch and validate raw `initData` when present |
| `POST` | `/api/telegram/miniapp/preview` | Combined wallet-alert + Mira preview for the Mini App; no Telegram send |
| `POST` | `/api/telegram/miniapp/ton-preview` | Telegram-safe TON risk passport plus Mira claim preview; no Telegram send |
| `POST` | `/api/telegram/webhook` | Inbound `/start`, `/stop`, and Mira preview handling with Telegram secret-header verification; no send |
| `POST` | `/api/telegram/mira-preview` | Build a Telegram-safe Mira security response preview; no send |
| `POST` | `/api/mira/claim-preview` | Deterministic Mira Verify-ready claim packet with evidence hashes; no external Mira call |
| `POST` | `/api/telegram/wallet-alert-preview` | Build a Telegram Mini App wallet alert message preview; no send |
| `GET`  | `/api/frontend-contract` | Browser smoke contract, selectors, and safety posture |
| `GET`  | `/api/external-action-contracts` | Dry-run/default contract for X, Telegram, deploy, and signing paths |
| `POST` | `/api/evaluate` | Full intent evaluation |
| `POST` | `/api/hack-check` | Hack signature check only |
| `GET`  | `/api/domain?url=...` | Domain allowlist check |

### Example: Evaluate Intent

```bash
curl -X POST http://127.0.0.1:8109/api/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "intent": {
      "action": "approve",
      "calldata": "0x095ea7b3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "mode": "live_transaction",
      "requires_signature": true
    },
    "enable_0g_storage": true,
    "agent_id": "agent-7857-0xabc..."
  }'
```

**Response:**
```json
{
  "decision": "deny",
  "severity": "high",
  "action": "approve",
  "mode": "live_transaction",
  "blockers": [
    "Unlimited ERC-20 approval (max uint256) detected.",
    "Intent requires a wallet signature in non-simulation mode."
  ],
  "warnings": [],
  "receipt_hash": "a1b2c3...",
  "zero_g": {
    "chain_anchor": {
      "status": "preflight",
      "chain_id": 16602
    },
    "storage_receipt": {
      "stored": false,
      "storage_mode": "receipt_only_no_live_upload",
      "root_hash": "..."
    }
  },
  "generated_at": "2026-05-03T17:45:00+00:00"
}
```

Check live 0G RPC proof without any private key:

```bash
curl -s http://127.0.0.1:8109/api/0g/status | python3 -m json.tool
curl -s 'http://127.0.0.1:8109/api/0g/receipt?receipt_hash=0x0000000000000000000000000000000000000000000000000000000000000000' | python3 -m json.tool
```

### Incident Data Flow

The incident dataset is loaded from `data/april_2026_incidents.json`, validated
against a required schema, fingerprinted, summarized, and run through the
signature engine as detection-coverage seeds. Canonical per-incident source
evidence is embedded for all 28 records, while
`data/incident_provenance_cache.json` remains a reviewed fallback so the judge
demo remains useful offline.

```bash
curl -s http://127.0.0.1:8109/api/data/summary | python3 -m json.tool
curl -s 'http://127.0.0.1:8109/api/data/provenance?live=1' | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/data/detection-coverage | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/data/signature-map | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/hackathon/threat-passport | python3 -m json.tool
```

The validator fails on bad totals, duplicate IDs, malformed dates, missing
required fields, invalid losses, or malformed provenance fields. It reports
provenance warnings when records lack per-incident source URLs; the current
dataset is fully source-linked at the incident level.

The signature engine currently covers 28 of 28 incident-derived detection
seeds (`1.0` coverage). Newly promoted source-backed categories include
Denaria unsafe-cast math, REVLoans/Juicebox accounting-source spoofing,
Thetanuts first-depositor vault inflation, Kipseli router quote mismatch,
Purrlend key compromise, Scallop accounting/index injection, Singularity fee
tier/oracle misconfiguration, JUDAO access control, and Syndicate bridge
control risk. The latest promoted `Quant` row uses SlowMist-syndicated public
reporting on an EIP-7702 delegated account / permissionless batch-call
access-control failure.

### OSINT Pipeline

The source registry lives in `data/osint_sources.json` and records source owner,
URL, retrieval mode, TTL, rights envelope, output policy, and caveats for each
adapter. Default routes return derived metadata, links, hashes, and defensive
analysis only; they do not return raw payload dumps.

```bash
curl -s http://127.0.0.1:8109/api/osint/sources | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/osint/readiness | python3 -m json.tool
curl -s 'http://127.0.0.1:8109/api/osint/readiness?live=1' | python3 -m json.tool
curl -s 'http://127.0.0.1:8109/api/osint/signals?live=1&limit=10' | python3 -m json.tool
curl -s 'http://127.0.0.1:8109/api/intelligence/evolving?limit=10' | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/hackathon/submission-brief | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/hackathon/submission-packet | python3 -m json.tool
```

Current default source families include DeFiLlama Hacks, BlockSec, Smart
Contract Hacking, Chainalysis RSS, Forta labelled datasets, CryptoScamDB, Rekt
News, SlowMist, CISA KEV, OFAC, URLhaus, Chainabuse, GoPlus, Scam Sniffer, and
MetaMask phishing data. Sources with credential, license, or redistribution
caveats stay catalog-only or disabled until explicitly reviewed.

### Telegram Mira Opt-In Preview

Create a local registration challenge, complete a redacted opt-in record, and
build a Mira response preview. These calls do not contact Telegram or send any
message.

```bash
curl -s -X POST http://127.0.0.1:8109/api/telegram/registrations \
  -H "Content-Type: application/json" \
  -d '{"user_label":"demo-operator","scopes":["mira_alerts","security.digest"]}' \
  | python3 -m json.tool

curl -s http://127.0.0.1:8109/api/telegram/status | python3 -m json.tool

curl -s -X POST http://127.0.0.1:8109/api/telegram/wallet-alert-preview \
  -H "Content-Type: application/json" \
  -d '{"address":"0x885b0892D241Cb5033C9995e09cA521d54f936b5","intent":{"action":"approve","mode":"live_transaction","requires_signature":true,"calldata":"0x095ea7b3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}}' \
  | python3 -m json.tool
```

For a real Telegram Mini App, send `window.Telegram.WebApp.initData` to
`/api/telegram/webapp/verify`; the backend validates Telegram's signed init
data with `TELEGRAM_BOT_TOKEN` before trusting user identity.

See also:
- `docs/DATA_FLOWS.md`
- `docs/TELEGRAM_MIRA_INTEGRATION.md`
- `docs/MARKET_POSITIONING.md`

---

## Real-World Signatures Built-In

| April 2026 Incident | Signature in 0guard |
|---|---|
| **Drift Protocol** ($285M) — Durable nonce social engineering | `durable_nonce_admin_transfer` blocker |
| **Kelp DAO** ($293M) — LayerZero 1-of-1 DVN bridge forgery | `single_dvn_bridge` warning |
| **Wasabi Protocol** ($5M) — UUPS upgrade via compromised deployer | `sequence_grant_upgrade` blocker |
| **Rhea Finance** ($18.4M) — Flash-loan + fake collateral | `sequence_flash_swap_withdraw` warning |
| **Giddy Finance** ($1.3M) — EIP-712 signature replay | `critical_selector` on malformed `approve` |
| **HyperBridge** ($2.5M) — MMR proof replay | `lzReceive` critical selector flag |
| **Aftermath Perps** ($1.14M) — Signedness mismatch | `high_value` + `risk_pair` warnings |
| **Sweat Foundation** ($3.5M) — Refund logic drain | `drain_language` blocker |
| **Volo Protocol** ($3.5M) — Admin key leak | `grantRole`/`transferOwnership` critical flags |

---

## Tests

```bash
pytest -q
python3 -m compileall src scripts
ruff check src tests scripts
python3 scripts/browser_smoke.py
gitleaks detect --no-git --source . --redact --verbose
```

---

## Safety Boundary

- **No private keys** in this repo.
- **No transaction signing** or broadcasting.
- **No real fund movements** — read-only and evaluative only.
- Live mode calls public HTTP endpoints and read-only RPC methods.
- X and Telegram posting CLIs default to dry-run unless the operator supplies
  the exact live confirmation flag.
- Telegram/Mira registration and preview routes are local-only by default:
  they validate tokens, redact identifiers, and never send Telegram messages.
- Wallet alert previews are quality-gated and read-only: they can optionally
  run public RPC balance/nonce probes, but they never sign, broadcast, or send.
- The browser workbench cannot trigger external sends, deploys, signatures, or
  transaction broadcasts.

---

## Roadmap

1. ✅ Signature/behavioral detection for April 2026 exploits
2. ✅ Live read-only 0G proof + mainnet receipt anchor
3. ✅ 0G Storage threat-intel payload/root-hash preparation
4. ✅ Telegram Mira secure registration primitives and no-send preview
5. ✅ Evolving threat-intel loop and no-spam wallet alert previews
6. 🔄 Persistent Telegram opt-in registry behind admin auth
7. 🔄 Real-time mempool monitoring via 0G DA subscription
8. 🔄 TEE-sealed inference for private risk scoring
9. 🔄 On-chain bounty program for community-submitted signatures

---

## Team

- **Security / Engineering** — Sapphire Security
- **Product / Strategy** — arigatoexpress

---

## Links

- **Hackathon:** [0G APAC Hackathon on HackQuest](https://hackquest.io/en/hackathons/0G-APAC-Hackathon)
- **0G Docs:** [docs.0g.ai](https://docs.0g.ai)
- **0G Explorer:** [chainscan.0g.ai](https://chainscan.0g.ai)
- **Twitter/X:** `#0GHackathon` `#BuildOn0G`

---

## License

Apache-2.0 — see [LICENSE](LICENSE). Source, data, and generated-media
boundaries are documented in [NOTICE](NOTICE) and
[docs/LEGAL_AND_ASSET_POLICY.md](docs/LEGAL_AND_ASSET_POLICY.md).
