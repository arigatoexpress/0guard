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
- Telegram Mini App preview with server-side `initData` validation support.
- Mira deterministic previews and claim packets.
- Cross-chain guardrails for Base, Arbitrum, Polygon, Abstract, Lighter, CCIP,
  LayerZero, Wormhole, Celestia, TON, Solana, Hyperliquid, Ika, Encrypt, and
  Ikavery lanes.

## Build Phases

| Phase | Timeframe | Goal | Shipping target |
|---|---|---|---|
| 0 | Now | Win the 0G APAC lane with proof-heavy safety. | Keep public proof packet reproducible and honest. |
| 1 | 1-2 weeks | Add constantly updating reputation probes. | Unified `risk_probe` adapter for GoPlus, Chainabuse, and phishing feeds. |
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
- `/api/ton/status`, `/api/ton/risk-rules`, `/api/ton/wallet-risk-preview`, and
  `/api/telegram/miniapp/ton-preview` expose the TON/Telegram lane without
  signatures or sends.
- `/api/integrations/ika` and `/api/integrations/ika/evaluate` expose the
  Ika/Ikavery pre-signing lane without key import, dWallet creation, signing,
  sweeps, or broadcasts.
- `/tonconnect-manifest.json` is present for wallet presentation context, but
  the frontend does not request `sendTransaction`, `signData`, or `tonProof`.
