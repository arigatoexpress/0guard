# 0G APAC Hackathon Market Intel

Snapshot date: May 14, 2026.

## Official Submission Facts

Source: [0G APAC Hackathon on HackQuest](https://www.hackquest.io/hackathons/0G-APAC-Hackathon)

- Final submission deadline: May 16, 2026 at 23:59 UTC+8.
- Denver equivalent: May 16, 2026 at 09:59 MDT.
- Prize pool: $150,000 total, split across grand prizes, excellence awards,
  and community awards.
- Valid submissions need basic project info, a public or judge-accessible
  GitHub repo, 0G integration proof, a demo video of no more than 3 minutes,
  README/docs, and a public X post.
- The 0G proof needs a mainnet contract address and 0G Explorer link showing
  verifiable on-chain activity. Testnet/Galileo proof is useful demo evidence
  but should not be framed as the final mainnet proof.
- The X post is mandatory and must include the project name, a demo screenshot
  or short clip, `#0GHackathon`, `#BuildOn0G`, and tags for `@0G_labs`,
  `@0g_CN`, `@0g_Eco`, and `@HackQuest_`.
- The core risk is proof depth: HackQuest says projects without actual 0G
  integration may be invalid or heavily penalized.

## Track Fit

Primary recommendation: Track 5, Privacy & Sovereign Infrastructure.

0guard is strongest as a verifiable safety/provenance layer for AI agents
before wallet custody begins. That maps cleanly to privacy, security,
sovereign infrastructure, and MEV/front-running-adjacent risk prevention.

Secondary recommendation: Track 1, Agentic Infrastructure & OpenClaw Lab.

Use this only if the final demo emphasizes agent workflows, specialized
skills, and data-processing pipelines more than security proof infrastructure.

## Competitive Pattern

Visible strong submissions package a public proof chain, not just a product
claim. The recurring pattern is:

- live app or CLI;
- public repo with hackathon-period progress;
- contract address or transaction hash;
- storage root or durable proof artifact;
- explorer links;
- judge walkthrough;
- clear statement of what is mainnet, testnet, simulated, or future work.

Examples worth tracking:

- [0G Forge](https://www.hackquest.io/projects/0G-Forge): terminal-native
  agent framework with 0G Compute, Storage, and Chain anchoring.
- [0G Build Proof](https://www.hackquest.io/en/projects/0g-Build-Proof):
  judge-ready evidence passport with repo inspection, Storage roots, and
  Chain anchors.
- [0G Thermidora](https://www.hackquest.io/projects/0G-Thermidora): managed
  agent platform with 0G chain/storage/KV skills and live network data.
- [0G SkillCapsule](https://www.hackquest.io/projects/0g-skillcapsule):
  proof-native AI agent marketplace using Storage, Compute Router, and an
  onchain registry.
- [Synapse](https://www.hackquest.io/projects/Synapse): decentralized agent
  memory with 0G Storage and Galileo hash verification.

## Gap Bridge Intelligence

The strongest competitors mostly package agent frameworks, builder passports,
or memory layers. That leaves a valuable open lane: a pre-wallet policy layer
that other agents and agent markets can call before signing, paying, bridging,
or trading.

Source-backed build implications:

- [0G Mainnet](https://docs.0g.ai/developer-hub/mainnet/mainnet-overview) gives
  this repo a real Chain proof surface: chain ID `16661`, public RPC, and
  ChainScan. 0guard should keep making 0G the audit anchor, not merely a logo.
- [0G Storage SDK](https://docs.0g.ai/developer-hub/building-on-0g/storage/sdk)
  supports upload/download, Merkle roots, and proof-enabled downloads. The next
  production gap is not another mock screen; it is live upload/readback for the
  already-generated threat-intel receipt roots.
- [0G Compute inference](https://docs.0g.ai/developer-hub/building-on-0g/compute-network/inference)
  exposes Router and Direct paths, provider health, pricing, and TEE
  verification modes. 0guard should use this for anomaly scoring only after it
  can cite the provider, model, request hash, response hash, and policy version.
- [x402](https://docs.x402.org/core-concepts/network-and-token-support) uses
  CAIP-2 network IDs and can support any EVM chain with the right facilitator,
  but public production support is facilitator-dependent. The honest claim is:
  Base/Polygon/Arbitrum are prepared first-settlement lanes; 0G-native x402
  needs a configured custom facilitator for `eip155:16661`.
- [Virtuals GAME](https://whitepaper.virtuals.io/developer-documents/game-framework/)
  and ACP are distribution/orchestration lanes, not automatic proof of safety.
  0guard should be a callable evaluator/resource for agents before any live
  Virtuals launch or token action.
- [Lighter](https://docs.lighter.xyz/) is best treated as an exchange/API risk
  surface. Its docs describe verifiable order matching and an API, while
  [LIT utility](https://docs.lighter.xyz/about-lighter/lit-utility) and
  [terms](https://lighter.xyz/terms) make token, staking, fee-credit, and access
  language sensitive. In 0guard copy, say "Lighter exchange/API guardrail"; do
  not conflate Lighter with its LIT token as if it were an EVM chain lane.
- [Celestia Blobstream](https://docs.celestia.org/learn/blobstream/) is the
  useful DA comparison: it lets EVM contracts verify Celestia data publication.
  0guard can mention it as a proof comparator while keeping 0G Storage/Chain as
  the implemented path.
- Cross-chain protocols should be modeled as guardrail lanes:
  [Chainlink CCIP](https://docs.chain.link/ccip) for router/token-pool policy,
  [LayerZero V2](https://docs.layerzero.network/v2/developers/evm/configuration/dvn-executor-config)
  for DVN/executor configuration risk, and
  [Wormhole NTT](https://wormhole.com/docs/products/token-transfers/native-token-transfers/concepts/security/)
  for VAA, transceiver, and supply-invariant risk.

## 0guard Positioning

Do not pitch 0guard as a generic wallet scanner. The best wedge is:

> 0guard is the pre-wallet firewall and provenance layer for AI agents. It
> checks intent, calldata, domain context, and incident intelligence before an
> autonomous agent can reach a signer.

Winning proof sequence:

1. Intent enters `/api/evaluate`.
2. 0guard returns allow/review/deny plus a deterministic receipt hash.
3. `enable_0g_anchor=true` exposes the exact Chain anchor payload in preflight.
4. `enable_0g_storage=true` exposes a Storage-ready threat-intel receipt and
   root hash.
5. `/api/0g/status` proves live, read-only 0G RPC connectivity.
6. `/api/data/provenance?live=1` proves the incident dataset can be correlated
   against live public source records without returning raw upstream payloads.

Clear value proposition:

> 0guard makes autonomous finance safer by moving the security decision before
> the signer. It turns intent, calldata, domain context, and public exploit
> intelligence into a deterministic verdict plus a 0G-verifiable receipt.

The world-class version is not just a bigger dashboard. It is a continuously
updated defensive feature store: incident signatures, bridge/protocol config
checks, x402 metadata controls, exchange/API intent guardrails, and provenance
hashes that can be verified without exposing raw upstream data.

## Current Submission State

- The 0G mainnet `PolicyReceiptAnchor` contract and anchor transaction are
  live and included in the submitted proof packet.
- The final public demo video is ready at
  `https://arigatoexpress.github.io/0guard/hackathon-0g/assets/0guard-hackquest-demo-final.mp4`.
- The submitted X proof URL is
  `https://x.com/rariwrldd/status/2054779961425461542`.
- The public HackQuest project also now surfaces the project X account link:
  `https://x.com/0guard_`.
- A prepared screenshot still exists at
  `docs/hackathon-0g/assets/0guard-workbench-provenance.png`.
- Per-incident source evidence is now promoted for 28 of 28 records.
- Production now exposes 34 source lanes and 20 no-network connector
  candidates. The newest disabled-by-default lanes are ThreatFox, Chainalysis
  sanctions oracle, and Google Cloud Web Risk.
- The detector map covers 28 of 28 incident-derived patterns after promoting
  SlowMist-syndicated public evidence for the `Quant` EIP-7702 delegated
  account / permissionless batch-call access-control failure.
- Remaining production gaps are live 0G Storage upload/readback and 0G Compute
  inference, both documented as future work rather than submitted live claims.

## Demo Advice

Lead with the product and proof trail, not architecture. In three minutes:

1. Show a risky agent wallet intent being denied.
2. Show 0G status readback.
3. Show receipt preflight/root hash.
4. Show provenance/source match counts.
5. Close with the honesty boundary: no keys, no signing, no broadcasts, no
   Telegram sends from the workbench.
