# Arbitrum Open House London Buildathon Plan

Updated: May 17, 2026.

## Thesis

Use Arbitrum as ZeroGuard's deployable proof lane. The product story stays
agent safety: ZeroGuard reviews a risky agent-wallet action, emits a compact
receipt, and proves the receipt on an Arbitrum chain.

## Sponsor Fit

The buildathon requires projects to deploy on an Arbitrum chain such as
Arbitrum Sepolia, Arbitrum One, Robinhood Chain, or a custom Orbit chain.
Judging scores smart contract quality, product-market fit, innovation, and real
problem solving. Best Agentic Project is the cleanest target, with the overall
prize as a stretch.

## Product Shape

Name:
ZeroGuard Arbitrum Agent Safety Pack

Minimum demo:

1. Run an agent-wallet or MetaMask permission intent through
   `/api/native-preflight`.
2. Generate an allow/review/deny receipt hash.
3. Deploy `PolicyReceiptRegistry` on Arbitrum Sepolia.
4. Write one compact receipt event.
5. Read the event and explorer link back into the workbench.
6. Explain how the same receipt can protect MetaMask x 1Shot permissions.

## Contract Scope

Minimum viable contract:
`PolicyReceiptRegistry`

Stores:

- receipt hash;
- decision;
- surface;
- created-at timestamp;
- operator/deployer address.

Does not store:

- private keys;
- raw prompts;
- raw exploit payloads;
- Telegram identifiers;
- personal data.

Security posture:

- append-only event-first design;
- no custody;
- no token transfer;
- no bridge or swap;
- no signer logic;
- OpenZeppelin access control only if admin mutation is required.

## Build Order

1. Solidity receipt registry on Arbitrum Sepolia.
2. Hardhat or Foundry test proving event shape and access expectations.
3. Deployment script with gas estimate and exact chain id.
4. Workbench readback route that verifies the transaction/receipt.
5. Optional Stylus/Rust verifier only after Solidity is green.

## Why It Complements MetaMask x 1Shot

MetaMask x 1Shot proves the agent permission workflow. Arbitrum proves the
onchain receipt. The same ZeroGuard receipt hash appears in both demos, which
lets us submit two sponsor-specific projects without inventing two unrelated
products.

## Sources

- https://www.hackquest.io/hackathons/Arbitrum-Open-House-London-Online-Buildathon
- https://docs.arbitrum.io/
- https://docs.arbitrum.io/stylus
- https://bridge.arbitrum.io/
