# Agent Swarm Red-Team Prompts

Updated: May 19, 2026.

These prompts are written for Kimi, Claude, or Kimi 2.6-style agent swarms.
They assume read-only auditing first. Do not grant a swarm permission to expose
secrets, send Telegram/X messages, sign or broadcast transactions, settle x402,
call paid inference, upload private data, mutate production data, or move funds.

## 0guard

```text
Read-only red-team /Users/aribs/Code/0guard from current local state. Do not
modify files, print secrets, send Telegram/X, sign, broadcast, settle x402, call
paid inference, upload to 0G Storage, or move funds.

Goal: falsify the claim "0guard is fully live wallet protection." Inspect
wallet-provider origin trust, external dapp/window.ethereum proof, x402 dry-run
vs settlement, 0G Storage manifest vs live upload/readback, 0G Private Computer
paid smoke gates, reputation freshness/supervision, historical feature-store
immutability, storage-node/Pi readiness, and docs overclaims.

Return prioritized findings with file/line refs, one exploit or failure
scenario per finding, exact safe remediation/tests, and a final verdict for:
demo readiness, external-wallet readiness, paid-route readiness, and production
wallet-protection readiness.
```

## Sapphire

```text
Read-only red-team /Users/aribs/Code/Sapphire. Do not edit files, expose
secrets, run live trading, send Telegram, mutate GCP/GitHub, or write artifacts.

Lanes:
1. 0G proof path: verify docs, code, deploy context, og_publish EOF/process
behavior, deployments.json availability inside Cloud Run, and live-proof-pending
honesty.
2. 0guard dashboard: audit /p/0guard and /api/0guard/progress for stale cache,
candidate URL parity, public-safe fields, and raw payload leakage.
3. x402/AgentWiki: compare config/x402_products.json to implemented routes,
mock verifier behavior, receipt durability, source-rights envelopes, and flags
that could imply real settlement.
4. CI/deploy: map which routes/files are covered by unit tests, source guards,
container smoke, and deploy workflow.
5. Docs: find stale dates, branch names, auth defaults, placeholders, and
overclaims.

Return prioritized findings with file/line refs, concrete failure scenario, and
minimal PR plan.
```

## Agent Opportunity Exchange

```text
Read-only red-team /Users/aribs/Code/agent-opportunity-exchange. Do not edit
files, read secrets, send Telegram, deploy, sign transactions, settle payments,
or move money.

Goal: decide whether AOE is ready for real customers or settlement traffic.
Assume it is only allowed to sell rights-cleared derived artifacts, not raw
source payloads or paywall bypass.

Agents:
1. Payment/x402: map every route claiming paid/x402 access. Verify official
x402 vs simulated header, receipts, replay/expiry, refunds, accounting, and
mainnet blocking.
2. Source-rights: inspect source records, rights envelopes, product sourceIds,
artifacts, and live adapters. Flag any yellow/licensed source that can reach
paid output without terms review.
3. Privacy/security: trace buyer inventory, hostnames, wallet/address
commitments, notes, Telegram initData, model prompts, HTML reports, and ledger
writes.
4. Product/docs: compare README, API_CONTRACTS, SAFETY_BOUNDARIES,
X402_TESTNET, CLOUD_RUN_PREVIEW, and route discovery against runtime code.
5. Tests/deploy: inspect package scripts, tests, browser smoke, Dockerfile,
Cloud Build, and gcp-smoke.

Return a ready/not-ready verdict for demos, testnet, real customers, and
mainnet settlement, plus the minimal safe PR plan.
```

## Wildfire Watch

```text
Read-only red-team /Users/aribs/Code/wildfire-watch on the current branch. Do
not edit, deploy, send Telegram, expose secrets, or mutate cloud.

Attack deploy/auth first: trace ADMIN_TOKEN behavior across frontend/app.py,
frontend/cloudbuild.yaml, Dockerfile, and CI. Then verify whether the active
Gunnison mission enforces West Elk/KGUC exclusions in code and docs. Finally
separate simulated readiness from field readiness: captured frames, telemetry,
signed local ingest, dashboard readback, no-send alert preview, detector evals,
flight hours, LOA, and trained model status.

Return prioritized findings with file/line refs, failure scenarios, and a patch
plan that preserves no-send/no-mutation boundaries.
```

## Project Go Forward

```text
Read-only inspect /Users/aribs/Code/Project-Go-Forward on the current branch.
Do not revert or overwrite shared WIP, do not send customer email, do not expose
secrets, and do not mutate production.

Build an ownership manifest of tracked changes, untracked files, ignored
generated artifacts, deleted tho_documents files, and hidden ignored scripts.
Then red-team firebase.json redirects/service routing, canonical production
URLs, CI/deploy gaps, CRM email templates and real send path, mock/random
analytics, RAG corpus/documentation mismatch, and missing Document Center
template preflight.

Return safe PR split recommendations, exact blockers, and regression tests to
add before customer-facing claims.
```
