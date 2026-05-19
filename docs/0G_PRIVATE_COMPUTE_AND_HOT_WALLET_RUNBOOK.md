# 0G Private Compute And Hot Wallet Runbook

Updated: May 17, 2026.

This is the operator-gated path for using the funded ZeroGuard 0G wallet with
0G Private Computer / Compute Router. It prepares the resources and exact
checks; it does not move funds, expose keys, create API keys, stake, delegate,
or broadcast transactions.

## Current Repo State

| Resource | Status | Safe route |
| --- | --- | --- |
| 0G Compute Router manifest | Prepared | `GET /api/0g/private-computer` |
| Live model catalog readback | Read-only | `GET /api/0g/private-computer?live=1` |
| No-inference smoke contract | Prepared | `GET /api/0g/private-computer/smoke-preview` |
| Hot-wallet resource plan | Prepared | `GET /api/0g/hot-wallet-resources` |
| 0GM-1.0 use case | Explanation and draft review only | Deterministic ZeroGuard policy remains authority |
| Router funding | Not executed | Requires wallet UI and final confirmation |
| Direct provider sub-account | Not recommended by default | Requires provider address, wallet signature, and final confirmation |

## Recommended Path

Use the 0G Compute Router first. Official docs describe it as the simplest
server-side path: one API key, one unified on-chain balance, OpenAI-compatible
requests, automatic provider discovery, billing, and failover.

1. Open `https://pc.0g.ai` with the funded ZeroGuard wallet.
2. Deposit a small mainnet budget into the Router payment contract.
3. Create one API key for this deployment in Dashboard -> API Keys.
4. Store it server-side as `ZG_0G_ROUTER_API_KEY` or `ZG_0G_PC_API_KEY`.
5. Call ZeroGuard through our backend only; never ship the Router key to a
   browser or Mini App.
6. Test with `GET /api/0g/private-computer?live=1`.
7. Review `GET /api/0g/private-computer/smoke-preview`; it should show the
   prompt scrubber, request shape, and blockers without executing inference.
8. Only then run a tiny controlled server-side inference request after a final
   spend confirmation.

## Funding Manifest Template

Fill this before any spend:

```json
{
  "network": "0G mainnet",
  "chainId": 16661,
  "sourceWallet": "0x885b0892D241Cb5033C9995e09cA521d54f936b5",
  "resource": "0G Compute Router deposit",
  "amountOg": "TBD",
  "recipientOrContract": "0xA3b15Bd2aD18BFB6b5f92D8AA9F444Dd59d1cE32",
  "maxFeeOg": "TBD",
  "reason": "Fund ZeroGuard private compute testing",
  "rollback": "Revoke API key and stop using Router balance",
  "finalConfirmation": "required"
}
```

## Direct Mode Boundary

Direct/Advanced mode is useful when we need manual provider selection or
provider-specific TEE verification. It is not the default path because it
requires per-provider sub-account management. Official docs note a minimum
ledger deposit and provider sub-account threshold; treat those as wallet-signed
money movement requiring a separate transaction manifest.

## Verified Contract References

| Network | Router / Payment Layer contract |
| --- | --- |
| Mainnet | `0xA3b15Bd2aD18BFB6b5f92D8AA9F444Dd59d1cE32` |
| Testnet | `0x0AD9690e0b34aB2d493DE02cDF149ee34f6C9939` |

These addresses come from the official Router deposits documentation and are
included here only to make operator review easier. This repo still does not
prepare or broadcast a deposit transaction.

## Safety Rules

- Never print, copy, upload, or commit private keys, mnemonics, API keys, or
  wallet export files.
- Never let a frontend call the 0G Router key directly.
- Never make 0GM output the policy authority. It can explain, summarize, and
  draft; deterministic ZeroGuard checks decide.
- Never send prompts that contain private keys, mnemonics, API keys, JWTs,
  payment headers, raw private chats, or raw paid-feed payloads.
- Never combine storage miner funding, Router deposit, staking, or delegation
  in one approval. Each gets its own exact manifest.
- Revoke the API key immediately if it appears in logs, screenshots, browser
  devtools, or a shared prompt.

## Sources

- 0G Compute Router overview: `https://docs.0g.ai/developer-hub/building-on-0g/compute-network/router/overview`
- 0G Router authentication: `https://docs.0g.ai/developer-hub/building-on-0g/compute-network/router/authentication`
- 0G Router models: `https://docs.0g.ai/developer-hub/building-on-0g/compute-network/router/models`
- 0G Router deposits and billing: `https://docs.0g.ai/developer-hub/building-on-0g/compute-network/router/account/deposits`
- 0G Direct inference: `https://docs.0g.ai/developer-hub/building-on-0g/compute-network/inference`
