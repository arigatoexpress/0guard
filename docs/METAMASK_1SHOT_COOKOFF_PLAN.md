# MetaMask x 1Shot Cook-Off Plan

Updated: May 17, 2026.

## Thesis

ZeroGuard should enter as a permission firewall for agentic onchain actions.
The demo should show one thing clearly: before an AI agent receives delegated
authority, x402 payment capability, or a MetaMask prompt, ZeroGuard checks the
scope and returns a receipt-backed verdict.

## Sponsor Fit

The cook-off requires a working MetaMask Smart Accounts Kit integration in the
main application flow. The x402 + ERC-7710 track specifically wants MetaMask
Smart Accounts or Advanced Permissions to perform x402 calls using ERC-7710.
1Shot API is a strong fit if we show its role in the project rather than merely
mentioning it.

## Product Shape

Name:
ZeroGuard Permission Firewall for MetaMask Smart Accounts + 1Shot Agents

Main flow:

1. User connects MetaMask and starts a paid threat-packet request.
2. The app receives x402 payment requirements.
3. ZeroGuard checks pay-to, facilitator, asset, amount, expiry, resource hash,
   and agent scope.
4. The app requests a bounded ERC-7715 permission or Smart Account delegation
   through MetaMask Smart Accounts Kit.
5. The agent uses the bounded permission to pay for a protected x402 API route
   through 1Shot only in testnet or prepared-not-live mode until credentials and
   funding are ready.
6. 0G Private Computer generates a private risk explanation and the receipt is
   ready for 0G proof anchoring.

## Built-In Route Evidence

- `GET /api/hackathons/metamask-1shot`
- `POST /api/hackathons/metamask-1shot/permission-preview`
- `POST /api/native-preflight`
- `POST /api/integrations/external-guardrails/evaluate`

The preview route intentionally returns both a bounded path and an unsafe
unbounded path. That gives judges something concrete to inspect: the system is
not only a wallet automation demo, it is an actual safety layer.

## 0G Funding Gate

Do not send 25 0G to the storage miner for Private Computer testing. The
compute payment path should fund the wallet or account connected to `pc.0g.ai`
or the specific 0G Private Computer provider flow. Miner funds are node
operations capital; inference funds are app/provider capital.

Before any transfer:

- confirm exact recipient address;
- confirm purpose: Private Computer, storage miner, DA signer, or another node
  role;
- confirm amount and network;
- prepare a tiny test transaction first if the recipient is new.

## This Time We Win By

- making sponsor tech visible in the first minute;
- using one concrete main flow instead of a broad ecosystem collage;
- proving a denial path as well as an allowed/review path;
- keeping 1Shot/x402 honest if credentials are not live yet;
- using 0G as the proof and private-inference layer that makes the product
  differentiated, not as a competing sponsor story.

## Sources

- https://www.hackquest.io/hackathons/MetaMask-Smart-Accounts-Kit-x-1Shot-API-Dev-Cook-Off
- https://docs.metamask.io/smart-accounts-kit/guides/x402/overview/
- https://docs.metamask.io/smart-accounts-kit/guides/x402/buyer/delegations/
- https://docs.metamask.io/smart-accounts-kit/guides/advanced-permissions/execute-on-metamask-users-behalf/
- https://docs.1shotapi.com/x402/index.html
- https://docs.1shotapi.com/api/api.html
- https://0g.ai/blog/0gm-1-0-35b-a3b
