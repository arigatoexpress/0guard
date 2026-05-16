# 0guard Next Hackathon Roadmap

Updated: May 16, 2026.

This roadmap keeps the 0G submission as the root proof layer while shaping the
next builds for Arbitrum Open House London, MetaMask Smart Accounts Kit x 1Shot
API Dev Cook Off, and Injective Solo AI Builder Sprint. The product should stay
native-preflight first: no bridges, no custody, no live trading, no hidden
wallet automation.

## Source Snapshot

| Event | Dates | Prize / track signal | Qualification signal | Official source |
| --- | --- | --- | --- | --- |
| Arbitrum Open House London: Online Buildathon | Registration: Mar 24-May 25, 2026. Submission: Mar 24-Jun 14, 2026. Reward announcement: Jun 17, 2026. | 115,000 USD total: 70,000 USDC overall, 15,000 USDC Best Agentic Project, 30,000 USDC grants. | Must deploy on an Arbitrum chain such as Arbitrum Sepolia, Arbitrum One, Robinhood Chain, or another Arbitrum chain. Judging emphasizes smart contract quality, product-market fit, innovation, and real problem solving. | https://www.hackquest.io/hackathons/Arbitrum-Open-House-London-Online-Buildathon |
| MetaMask Smart Accounts Kit x 1Shot API Dev Cook Off | Registration/submission: May 15-Jun 15, 2026. Reward announcement: Jun 22, 2026. | 10,000 USD total: Best x402 + ERC-7710, Best Agent, Best A2A coordination, social and feedback bounties. | Main flow must use MetaMask Smart Accounts Kit or Advanced Permissions. x402 track requires x402 calls using ERC-7710. A2A track requires redelegation. | https://www.hackquest.io/hackathons/MetaMask-Smart-Accounts-Kit-x-1Shot-API-Dev-Cook-Off |
| Injective Solo AI Builder Sprint | HackQuest schedule: May 7-May 31, 2026 registration/submission. Reward announcement: Jun 8, 2026. | 500 USD total for top 3 projects. | Submit through Typeform, include GitHub, demo/product link, short description, demo video, README explaining AI use and any Injective integration, and an X post. Onchain integration is allowed but not mandatory. | https://www.hackquest.io/hackathons/Injective-Solo-AI-Builder-Sprint |

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
   This is the best technical fit because the event explicitly centers
   Advanced Permissions, ERC-7710, x402, agents, and A2A coordination. 0guard
   can be the missing preflight layer that explains whether a permission grant
   or x402 payment intent is scoped enough before the user approves it.
2. Arbitrum Open House London.
   This is the biggest prize pool and the best continuation of the 0G proof
   story, but it needs an Arbitrum-chain deployment and a clean demo proving
   smart-contract quality. Target Best Agentic Project first, then overall.
3. Injective Solo AI Builder Sprint.
   Treat this as a fast repository-quality lane. Submit only if the README,
   demo video, and hosted product stay crisp without a forced Injective pivot.

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

Target tracks:

- Best Agent;
- Best x402 + ERC-7710;
- stretch: Best A2A coordination.

Minimum demo:

- A user-agent flow requests a scoped permission.
- 0guard preflights the scope before approval.
- The UI shows why the scope is acceptable, suspicious, or denied.
- A receipt packet is produced.
- A no-custody, testnet-only MetaMask Smart Accounts Kit flow appears in the
  main demo path.

Stretch demo:

- x402 resource request calls 0guard before payment authorization.
- 1Shot API is used only after terms, auth, and testnet funding are clear.
- A2A redelegation is treated as a reviewed sub-scope, not a blanket pass.

Do not claim production MetaMask partnership, live mainnet settlement, or wallet
protection beyond the tested adapter.

### 3. Arbitrum Agent Safety Pack

Target tracks:

- Best Agentic Project;
- overall prize if the onchain proof is crisp.

Minimum demo:

- Deploy a small policy receipt or attestation contract on Arbitrum Sepolia,
  Arbitrum One, Robinhood Chain testnet, or another qualifying Arbitrum chain.
- Add an Arbitrum profile to `/api/native-preflight`.
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
- CryptoScamDB derived domain/address evidence;
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

