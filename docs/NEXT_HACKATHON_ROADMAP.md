# 0guard Next Hackathon Roadmap

Updated: May 17, 2026.

This roadmap keeps the 0G submission as the root proof layer while shaping the
next builds for the MetaMask Smart Accounts Kit x 1Shot API Dev Cook Off,
Arbitrum Open House London, and AI-agent trust programs. The product should
stay native-preflight first: no bridges, no custody, no live trading, no hidden
wallet automation.

## Source Snapshot

| Event | Dates | Prize / track signal | Qualification signal | Official source |
| --- | --- | --- | --- | --- |
| MetaMask Smart Accounts Kit x 1Shot API Dev Cook Off | Registration and submission: May 15-Jun 15, 2026. Reward announcement: Jun 22, 2026. | 10,000 USD total: 3,000 USD Best x402 + ERC-7710, 3,000 USD Best Agent, 3,000 USD Best A2A coordination, plus social/feedback awards. | Main demo must use MetaMask Smart Accounts Kit through Smart Accounts or Advanced Permissions. x402 track requires MetaMask Smart Accounts or Advanced Permissions to do x402 calls using ERC-7710; 1Shot use must be shown if included. | https://www.hackquest.io/hackathons/MetaMask-Smart-Accounts-Kit-x-1Shot-API-Dev-Cook-Off |
| Arbitrum Open House London: Online Buildathon | Registration: Mar 24-May 25, 2026. Submission: Mar 24-Jun 14, 2026. Reward announcement: Jun 17, 2026. | 115,000 USD total: 70,000 USDC overall, 15,000 USDC Best Agentic Project, 30,000 USDC grants. | Must deploy on an Arbitrum chain such as Arbitrum Sepolia, Arbitrum One, Robinhood Chain, or another Arbitrum chain. Judging emphasizes smart contract quality, product-market fit, innovation, and real problem solving. | https://www.hackquest.io/hackathons/Arbitrum-Open-House-London-Online-Buildathon |
| ETHGlobal New York 2026 | Jun 12-Jun 14, 2026. | Near-term EVM/security-wallet venue for MetaMask-compatible pre-signer middleware. | Use 0guard as a dapp/agent wrapper before wallet prompts; publish only tested demo claims. | https://ethglobal.com/events/newyork2026 |
| NANDA Hack / AI-agent trust | Challenge through Jun 13, 2026; live event Jul 11, 2026. | Best AI-agent trust/reputation framing target. | Focus on agent preflight receipts and safe delegated authority, not wallet custody. | https://nandahack.media.mit.edu/ |

## Strategic Thesis

0guard should become the pre-signer firewall for agentic wallets.

The durable claim is narrow and strong: before an AI agent, wallet app,
Telegram Mini App, permissioned session, or payment rail asks a signer for
authority, 0guard evaluates intent, calldata, permission scope, domain,
counterparty, reputation, incident evidence, and chain-specific context, then
emits a receipt-backed allow/review/deny packet.

0G remains the provenance and proof root. Other ecosystems get native adapters,
not bridged abstractions.

## Priority Order

1. MetaMask Smart Accounts Kit x 1Shot API Dev Cook Off.
   This is now the cleanest one-month lane because the requirement matches the
   product: agents need scoped permissions before x402 or wallet activity. Aim
   first at Best x402 + ERC-7710 and Best Agent, with A2A redelegation as a
   stretch.
2. Arbitrum Open House London.
   This remains a strong parallel lane and larger prize pool, but it needs an
   Arbitrum-chain deployment and a clean proof contract. Keep it alive without
   letting it dilute the MetaMask main-flow demo.
3. ETHGlobal New York and NANDA Hack.
   Treat these as near-term distribution lanes for the same middleware: one
   EVM/wallet-focused, one AI-agent trust focused.

## Build Plan

### 1. Permission Preflight Core

Ship a reusable permission evaluator that accepts:

- EVM chain id and target account;
- requested permission type;
- token/native asset;
- amount or period cap;
- start and expiry;
- session account;
- delegated caller;
- x402 resource URL and payment metadata when present;
- target contract and calldata summary when present.

Return:

- `allow`, `review`, or `deny`;
- plain-language risk summary;
- caveat failures;
- revocation path;
- 0G-ready receipt hash;
- optional Arbitrum or MetaMask demo adapter payload.

This becomes the shared core for MetaMask Advanced Permissions, ERC-7710,
Arbitrum agent actions, x402 calls, and future agent framework middleware.

### 2. MetaMask Demo Adapter

Minimum demo:

- A MetaMask Smart Accounts Kit flow requests a scoped ERC-7715 Advanced
  Permission or Smart Account delegation.
- 0guard preflights the scope before approval and shows the exact missing
  caveats when a request is unbounded.
- The UI shows why the scope is acceptable, suspicious, or denied before the
  wallet prompt.
- A receipt packet is produced.
- A no-custody, testnet-only Smart Accounts Kit path appears in the main demo
  only after it is actually tested.

Stretch demo:

- x402 resource request calls 0guard before ERC-7710 payment authorization.
- 1Shot API is used only after terms, auth, server-wallet funding, and testnet
  boundaries are clear.
- A2A redelegation is treated as a reviewed sub-scope, not a blanket pass.

Do not claim production MetaMask partnership, live mainnet settlement, Snap
publication, or wallet protection beyond the tested adapter.

### 3. Arbitrum Agent Safety Pack

Target tracks:

- Best Agentic Project;
- overall prize if the onchain proof is crisp.

Minimum demo:

- Deploy a small policy receipt or attestation contract on Arbitrum Sepolia,
  Arbitrum One, Robinhood Chain testnet, or another qualifying Arbitrum chain.
- Add an Arbitrum profile to `/api/native-preflight`.
- Use `/api/integrations/arbitrum` and `/api/integrations/cross-chain/readiness?live=1`
  for source-cited network/readiness proof.
- Show preflight for approvals, upgrades, deployments, bridge-message configs,
  Orbit/Stylus app intents, and agent-controlled calls.
- Read back the Arbitrum receipt in the product UI and proof docs.

Stretch demo:

- A Stylus/Rust verifier or scoring contract that evaluates a compact risk
  vector onchain.
- Shared typed schema between the Python service and the Rust verifier.
- OpenZeppelin Stylus patterns if the contract surface grows beyond a pure
  scoring proof.

Do not position this as a bridge. The point is Arbitrum-native agent safety and
receipt proofs.

Current route evidence:

- `GET /api/hackathons/arbitrum-open-house` returns the active buildathon plan,
  prize mapping, qualification requirements, and the deployable proof-contract
  scope.
- `GET /api/integrations/arbitrum` remains the network/read-only safety-pack
  route for Arbitrum One, Nova, Sepolia, Orbit, and Stylus contexts.

Best positioning:

- MetaMask x 1Shot is the permission-firewall product demo.
- Arbitrum Open House is the onchain proof contract demo.
- The shared asset is the same ZeroGuard receipt hash, first generated by
  native preflight, then read back from an Arbitrum deployment.

### 4. Solo AI Builder Submission

Submit only if the repo is already clean enough by May 31:

- README says exactly how AI is used.
- Hosted demo is live.
- Demo video is under control and does not overclaim.
- X post exists with GitHub and demo link.
- Optional Injective note is honest: onchain integration is future or optional
  unless a real read-only Injective adapter exists.

This lane rewards usability, clarity, code structure, documentation, and future
contribution potential more than deep protocol complexity.

## Competitive Wedge

Arbitrum projects will likely skew toward DeFi, games, RWAs, and consumer apps.
0guard should be the safety layer those projects need once agents and
automation start requesting wallet authority.

MetaMask projects will likely skew toward delegated DeFi, subscriptions,
revocation tools, and automation. 0guard should be the permission-risk copilot
that checks the request before the user grants it.

Solo AI projects will likely skew toward lightweight AI apps and workflows.
0guard should win on being functional, readable, well-documented, and useful
for real users today.

## Data Streams To Add Carefully

Free or open-source first:

- PhishDestroy derived domain evidence;
- Scam Sniffer delayed phishing/drainer evidence if GPL-3.0 raw-feed posture is acceptable;
- CryptoScamDB derived domain/address evidence;
- OFAC Sanctions List Service as a binary compliance context signal, not legal advice;
- Forta labels and alert-shaped payloads;
- Chainabuse public reports where rights allow derived evidence;
- ThreatFox IOC API for domain/IP/hash context;
- public EVM RPC readbacks for contract code, approvals, and logs;
- Arbitrum, Base, Optimism, Polygon, and Ethereum explorer links for operator
  proof;
- TON Center or TONAPI read-only wallet context after terms review.

Affordable or keyed lanes worth reviewing:

- GoPlus risk APIs for token/address/approval enrichment;
- Tenderly or BlockSec simulation for EVM transaction preview;
- Google Cloud Web Risk for URL reputation if terms fit;
- 1Shot API for MetaMask/x402 demo only after keys, funding, and testnet
  boundaries are explicit;
- Envio or similar indexers if a hackathon track specifically rewards indexed
  chain data.

Never resell raw payloads. Normalize into source ids, links, hashes, TTLs,
confidence, and derived risk signals.

## MetaMask x 1Shot Main Flow

Current route evidence:

- `GET /api/hackathons/metamask-1shot` returns the active cook-off plan, track
  mapping, 0G integration, and funding gate.
- `POST /api/hackathons/metamask-1shot/permission-preview` returns a
  no-sign/no-settle demo packet with:
  - ERC-7715 `requestExecutionPermissions` shape;
  - ERC-7710 x402 payment payload shape;
  - 1Shot/x402 prerequisites;
  - bounded permission preflight;
  - delegated execution preflight;
  - unsafe unbounded delegation denial.

The next implementation milestone is a small TypeScript demo shell that uses
Smart Accounts Kit for the real request UI, then calls these 0guard routes
before any wallet prompt. That is the step that turns the route evidence into a
working hackathon video.

## Claims To Avoid

- "prevents all hacks";
- "safe bridge";
- "cross-chain bridge security platform";
- "protects all wallets";
- "live MetaMask integration" before a tested main-flow demo exists;
- "TON wallet integration" before real read-only TON readback is enabled;
- "Solana support" beyond parser/prototype;
- "Hyperliquid trading safety" before authenticated read-only exposure
  monitoring exists;
- "agent custody" or "agent wallet";
- any claim that 0guard signs, settles, bridges, swaps, trades, sends Telegram
  messages, or controls user funds.

Use:

- "pre-signing risk review";
- "read-only safety middleware";
- "agent wallet preflight";
- "permission-aware approval copilot";
- "receipt-backed threat preview";
- "Telegram Mini App risk passport";
- "native chain adapters without bridge dependency";
- "no custody, no live trading, no hidden signing."

## Definition Of Done

MetaMask-ready:

- Permission preflight endpoint and tests.
- Demo path using MetaMask Smart Accounts Kit or Advanced Permissions.
- x402 adapter either real testnet or clearly simulated if keys/funding are not
  ready.
- Social post that tags MetaMaskDev only when the demo is real.

Arbitrum-ready:

- Arbitrum-chain deployment proof.
- Explorer link and readback in docs.
- Contract tests or static verification.
- Native preflight profile with Arbitrum scenarios.
- Demo video showing the Arbitrum proof, not just 0G.

Solo AI-ready:

- README polish.
- Demo/product link.
- Demo video.
- X post.
- No forced chain claims.
