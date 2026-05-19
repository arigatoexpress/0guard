# 0guard Intelligence Stream Plan

This is the current build order for making 0guard evolve beyond the April 2026
incident dataset without pretending raw feeds are ours to resell.

## Priority Streams

| Phase | Stream | Why | Integration | Rights posture |
|---|---|---|---|---|
| 1 | PhishDestroy + CryptoScamDB + Forta labels, then GoPlus / Chainabuse | Highest near-term value for domain, recipient, approval, dApp, and Telegram risk with open-source feeds first. | The live `/api/reputation/probe` contract now feeds `/api/native-preflight`, wallet alerts, and Telegram previews; `/api/reputation/adapters/normalize` converts reviewed upstream payloads into derived evidence. External live fetches stay disabled until keys/terms are reviewed. | Derived verdicts, links, hashes, source ids, and confidence only. |
| 1 | OFAC + Chainalysis Sanctions API/Oracle + TRM Wallet Screening/BLOCKINT | Gives ZeroGuard a credible AML/sanctions lane for exact-address preflight, vendor-backed corroboration, and escalation workflows. | `/api/osint/sources` and `/api/reputation/connectors` now expose disabled-by-default Chainalysis API, Chainalysis Oracle, TRM Wallet Screening, and TRM BLOCKINT candidates. Live calls wait for credentials, terms, caching rules, and operator acceptance. | Sanctions context is not legal advice. TRM/Chainalysis raw payloads are not public outputs; use derived verdicts, redacted addresses, source links, hashes, and receipt metadata. |
| 1 | MITRE ATT&CK Lazarus G0032 + DPRK tradecraft context | Helps explain adversary behavior such as job-lure phishing, infrastructure compromise, credential theft, wipers, and exfiltration without pretending ATT&CK is wallet attribution. | Catalog-only TTP context feeds detector hypotheses, training material, and case-file narratives; wallet blocking still requires direct wallet/domain/transaction/vendor evidence. | Technique IDs, aliases, source links, and defensive mappings only. Do not assert Lazarus attribution from TTP context alone. |
| 1 | CISA KEV + NVD CVE + MITRE Shai-Hulud S9008 | Bridges Web2 vulnerability exposure into wallet protection: compromised dapp frontends, packages, CI/CD secrets, extensions, and browser surfaces can become Web3 loss paths. | `/api/intelligence/cyber-threats` composes CISA/NVD live-derived snapshots, MITRE context, and the crypto incident feature set. CISA/NVD/OFAC live fetches are explicit and derived-only. | Public outputs are CVE ids, hashes, severity/context, source links, and detector hypotheses. Do not publish exploit payloads, raw descriptions, raw sanctions rows, or attribution claims without corroboration. |
| 1 | x402 derived defensive artifacts | Gives agents and wallets a clean paid-access path for ZeroGuard verdicts, threat packets, node snapshots, and backfilled incident features. | `/api/x402/data-products` exposes the product manifest now; settlement stays disabled until a testnet facilitator flow and spend limits are reviewed. | Payment unlocks derived outputs only; no raw upstream payload resale. |
| 1 | Forta labels and attack alerts | Emerging exploit-stage intelligence before it becomes a hard blocker. | Digest-only queue using Forta alert/label metadata; promote to wallet alert only with direct detector/source evidence. | Respect public label attribution and any premium feed terms. |
| 2 | Tenderly or BlockSec simulation | Adds state-change previews for approvals, swaps, and contract calls. | Optional `simulate_intent` adapter returning asset deltas and dangerous calls. | Do not persist/resell full traces unless vendor terms allow it. |
| 2 | TON Center / TONAPI | Makes Telegram wallet alerts native to TON instead of EVM-shaped. | TON account, transaction, Jetton, NFT, and message activity enrichment for risk passports. | Derived activity features only; no raw indexer dumps. |
| 2 | Helius Solana | Adds Solana read-only account/token risk without making a bridge story. | Parsed transaction and SPL-token watchlists feeding alert quality gates. | Vendor terms; derived features and links only. |
| 2 | LayerZero Scan / Wormholescan | Lets 0guard protect cross-chain message risk without initiating transfers. | Read message state, DVN config, VAA status, and stuck-message context. | Derived message metadata only. |
| 3 | Hyperliquid Info/WebSocket APIs | Useful for exposure and fill context while avoiding exchange actions. | Read-only exposure monitor; no order, cancel, transfer, or withdrawal endpoints. | Market context only, not advice or execution. |
| 3 | Dune, Allium, or Bitquery | Backfills behavior features across chains when native adapters are not enough. | Nightly feature store for fan-out, mixer proximity, and new-contract exposure. | Paid terms vary; sell derived features, not raw query exports. |

## What To Buy First

1. Use PhishDestroy / CryptoScamDB / Forta labelled datasets first because they
   can improve phishing and attacker-label coverage without immediate paid
   credentials.
2. Use the Chainalysis Sanctions API and Oracle as the first AML/sanctions
   activation lane because the official API has a direct exact-address lookup
   contract, an OpenAPI document, and a clear backend-only integration model.
3. Keep TRM Wallet Screening and BLOCKINT as the strongest commercial
   escalation lane. Outreach has been sent to TRM asking for the right
   developer, sandbox, pricing, retention, and partner path before any live
   integration claim.
4. GoPlus or Chainabuse only after free/keyed access materially improves alert
   quality or the demo hits rate limits.
5. x402 only after route schemas, spend limits, testnet facilitator proof, and
   MetaMask/1Shot permission boundaries are reviewed.
6. Tenderly or BlockSec simulation once the reputation adapter is already used
   by real product flows.
7. Dune, Allium, or Bitquery only when native adapters cannot cover a chain or
   historical feature quickly enough.

## Outreach And Vendor Path

On May 17, 2026, outreach was sent to TRM Labs and Chainalysis asking about
developer access, sandbox credentials, OpenAPI/SDK material, attribution
requirements, caching/retention limits, and the correct partner path for a
defensive agent preflight product. The public product should describe these as
`source-ready-live-proof-pending` until we have vendor approval and live
readback evidence.

The Chainalysis lane is useful immediately as a design target: the Sanctions
Screening API is an API-key backend lookup for a specific address, and the
public oracle remains a no-key on-chain signal. The TRM lane should be treated
as commercial enrichment for broader risk exposure, entity attribution, wallet
screening, and high-volume intelligence once TRM confirms what we are allowed
to cache and display.

## Current API Proof

- `/api/intelligence/data-streams` exposes this as a source-rights-aware JSON
  roadmap.
- `/api/intelligence/cyber-threats` exposes the new Web2/Web3 repository:
  CISA KEV, NVD CVE, MITRE ATT&CK Lazarus/Shai-Hulud context, exact-address
  OFAC screening when requested, and the existing crypto incident coverage.
- `/api/x402/data-products` exposes the rights-cleared paid-data product shape
  without enabling x402 settlement.
- `/api/data/backfill-plan` defines how historical incident, reputation, node,
  Telegram opt-in, and future x402 receipt metadata become durable feature data.
- `/api/experiments/frontier` turns the roadmap into a ranked lab bench for 0G
  Storage/Compute, reputation, simulation, TON, and Mira.
- `/api/experiments/run` previews one experiment at a time and always reports
  `networkCalls: false`, `liveStorageUpload: false`,
  `liveComputeInference: false`, and `rawPayloadsReturned: false`.
- `/api/osint/sources` now includes the planned stream metadata and keeps those
  adapters disabled by default until terms, keys, and retention rules are clear.
- `/api/reputation/probe` is the first live adapter contract. It accepts local
  or caller-supplied evidence and returns only derived signals, hashes,
  redactions, confidence, and receipt metadata.
- `/api/reputation/connectors` turns the source registry into an activation
  manifest for the subject being checked. It does not call external networks;
  it tells an integrator which open-source phishing, OFAC, Chainalysis, TRM,
  GoPlus, Chainabuse, Forta, TON, simulation, or cross-chain connector applies
  and what rights boundary must be preserved.
- `/api/reputation/adapters` and `/api/reputation/adapters/normalize` are the
  first no-network adapter contracts for PhishDestroy, CryptoScamDB, Forta
  labelled datasets, GoPlus, Chainabuse, and Forta GraphQL. They accept
  caller-provided payloads from a reviewed worker, return only derived evidence,
  and feed the threat case file plus wallet/Telegram previews.
