# 0guard Ecosystem Roadmap

0guard should scale as a native pre-wallet safety layer, not as another bridge
or wrapped-asset story. The common layer is the 0G receipt and provenance trail;
each ecosystem gets its own read-only adapter, simulation surface, or wallet
context.

## Current Wedge

0guard owns the moment before an AI agent touches a signer. Other 0G hackathon
projects show agents, markets, receipts, memory, or contract auditing. Our lane
is narrower and more valuable: prompt + intent + calldata + domain + exploit
intelligence before wallet custody begins.

The live repo already has:

- 0G mainnet deny receipt proof plus read-only 0G status and receipt routes.
- 28/28 source-linked incident detector coverage.
- A threat case file route that composes policy, signatures, reputation, wallet
  alerts, provenance, and 0G-ready receipts into one proof dossier.
- A 0G proof ladder route that builds Chain, Storage, DA, Compute, and
  Alignment verifier packets while keeping every live side effect gated.
- A frontier experiment lab that ranks 0G Storage/Compute, reputation,
  simulation, TON, and Mira activation without live side effects.
- Telegram Mini App preview with server-side `initData` validation support.
- Mira deterministic previews and claim packets.
- Cross-chain guardrails for Base, Arbitrum, Polygon, Abstract, Lighter, CCIP,
  LayerZero, Wormhole, Celestia, TON, Solana, Hyperliquid, Ika, Encrypt, and
  Ikavery lanes.

## Build Phases

| Phase | Timeframe | Goal | Shipping target |
|---|---|---|---|
| 0 | Now | Win the 0G APAC lane with proof-heavy safety. | Keep public proof packet reproducible and honest. |
| 1 | 1-2 weeks | Add constantly updating reputation probes. | Unified `risk_probe` adapter for PhishDestroy, CryptoScamDB, Forta labels, then keyed GoPlus/Chainabuse feeds. |
| 2 | 2-5 weeks | Expand natively without bridges. | TON risk passport, EVM simulation, Abstract wallet context, Solana read-only monitor. |
| 3 | 1-2 months | Become safety middleware for agent frameworks. | AgentKit/Turnkey examples, x402 paid threat packets, Hyperliquid exposure monitor, external Mira adapter. |

## Native Integration Principle

- 0G remains the receipt/provenance anchor.
- Telegram/TON gets a TON Risk Passport, not an EVM bridge workaround.
- EVM L2s get calldata, simulation, domain, and account-abstraction context.
- Solana gets parsed account/token activity and warning receipts.
- Hyperliquid gets read-only exposure/fill context only.
- Cross-chain protocols get message/config guardrails, not transfer execution.
- Ika/Ikavery get pre-signing guardrails and 0G receipts, not key import or
  signing from 0guard.

## New API Proof

- `/api/roadmap` exposes the phase plan and competitive wedge.
- `/api/0g/proof-ladder` exposes the five-stage 0G proof packet without live
  upload, inference, signing, broadcast, or Alignment Node operation.
- `/api/threat-case-file` exposes the composed operator/judge proof dossier.
- `/api/experiments/frontier` and `/api/experiments/run` expose the next
  integrations as safe previews instead of speculative claims.
- `/api/ton/status`, `/api/ton/risk-rules`, `/api/ton/wallet-risk-preview`, and
  `/api/telegram/miniapp/ton-preview` expose the TON/Telegram lane without
  signatures or sends.
- `/api/integrations/ika` and `/api/integrations/ika/evaluate` expose the
  Ika/Ikavery pre-signing lane without key import, dWallet creation, signing,
  sweeps, or broadcasts.
- `/api/native-preflight` composes the core policy engine, Ika/dWallet
  preflight, TON passport posture, and external guardrails into one 0G-ready
  receipt for future hackathon demos.
- `/api/hackathon/strategy` keeps the next builds ordered by timing and fit:
  0G first, then Arbitrum/ETHGlobal-style EVM middleware, then reusable SDK
  examples.
- `/tonconnect-manifest.json` is present for wallet presentation context, but
  the frontend does not request `sendTransaction`, `signData`, or `tonProof`.

## May 16, 2026 Hackathon Sequencing Update

The next external tracks are now documented in
`docs/NEXT_HACKATHON_ROADMAP.md`.

Priority order:

1. MetaMask Smart Accounts Kit x 1Shot API Dev Cook Off.
   Build a permission-aware approval copilot around Advanced Permissions,
   ERC-7710, x402, and agent/A2A coordination.
2. Arbitrum Open House London.
   Build an Arbitrum-native agent safety pack with a small deployed receipt or
   scoring proof on a qualifying Arbitrum chain.
3. Injective Solo AI Builder Sprint.
   Use as a fast repository-quality lane only if the README, hosted demo, video,
   and X post are already clean.

The common product nucleus stays unchanged: 0guard is a native preflight layer
that emits receipt-backed risk decisions before a signer or permission grant is
used. It should not become a bridge, exchange bot, or custody wallet.
