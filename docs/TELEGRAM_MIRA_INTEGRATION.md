# Telegram MIRA Opt-In Integration

`guard0.telegram_subscriptions` is a local-only registry slice for Telegram
opt-in. It does not import the live Telegram bot, send messages, call Telegram,
read environment variables, or persist secrets.

## Public API

```python
from guard0.telegram_subscriptions import (
    build_opt_in_record,
    build_telegram_registration_challenge,
    ensure_registration_token_not_replayed,
    public_opt_in_status,
    verify_telegram_registration_token,
)

challenge = build_telegram_registration_challenge(
    user_label="operator@example.com",
    secret=app_secret,
)

verified = verify_telegram_registration_token(
    token=challenge["token"],
    secret=app_secret,
)

verified = ensure_registration_token_not_replayed(
    verified,
    consumed_token_ids=already_consumed_token_ids,
)

record = build_opt_in_record(
    verified,
    telegram_user={"id": 123456789, "chat_id": "-1001234567890", "username": "operator"},
    scopes=["mira_alerts"],
)

public_status = public_opt_in_status(record)
```

## Flask Routes

The workbench exposes a demo-safe API surface:

| Method | Route | Behavior |
|---|---|---|
| `GET` | `/telegram` | Mobile-first Telegram Mini App shell. Works inside Telegram or as browser preview. |
| `GET` | `/api/telegram/status` | Reports registration, Mini App auth, Mira preview, and no-send safety posture. |
| `POST` | `/api/telegram/registrations` | Creates a local HMAC challenge and optional `start_payload`. No Telegram send. |
| `POST` | `/api/telegram/opt-ins` | Consumes a token/token id and creates a redacted opt-in record. |
| `POST` | `/api/telegram/webapp/verify` | Validates Telegram Mini App `initData` with `TELEGRAM_BOT_TOKEN`. |
| `GET` | `/api/telegram/miniapp/contract` | Returns required Mini App selectors, routes, Telegram Web App posture, and no-send safety. |
| `POST` | `/api/telegram/miniapp/session` | Detects browser preview versus Telegram launch and validates raw `initData` when present. |
| `POST` | `/api/telegram/miniapp/preview` | Builds one combined wallet-alert + Mira preview response for the Mini App. |
| `POST` | `/api/telegram/miniapp/ton-preview` | Builds a TON Risk Passport plus Mira claim preview for Telegram. No send, no tonProof, no transaction. |
| `POST` | `/api/telegram/webhook` | Handles inbound `/start`, `/stop`, and Mira preview after secret-header verification. |
| `POST` | `/api/telegram/mira-preview` | Builds a deterministic Mira policy response preview. No Telegram send. |
| `POST` | `/api/mira/claim-preview` | Builds an external-Mira-ready claim/evidence packet without making an external Mira call. |
| `POST` | `/api/telegram/wallet-alert-preview` | Builds a no-send wallet alert message preview with score, dedupe, cooldown, and source ids. |
| `GET` | `/api/0g/da-node/status` | Read-only DA node telemetry for signer/miner balances, relay socket, readiness, and yield-source honesty. |
| `GET`/`POST` | `/api/telegram/da-node-preview` | Builds a no-send DA node digest preview for balance/readiness updates. |
| `GET` | `/api/0g/storage-node/status` | Read-only mainnet storage-node telemetry for peer count, log sync height, relay socket, and no-key funding gate. |
| `GET`/`POST` | `/api/telegram/storage-node-preview` | Builds a no-send storage-node digest preview for peer/sync/funding-gate updates. |
| `GET` | `/api/0g/alignment-node/status` | Read-only Alignment Node license, reward, and operator-readiness posture. |
| `GET` | `/api/0g/validator-capacity` | Validator fit for the Windows/RV host: CPU, WSL memory, disk, bandwidth, and workarounds. |
| `GET` | `/api/0g/node-business` | Business plan for storage, Alignment, validator, and ZeroGuard service-revenue lanes. |
| `GET`/`POST` | `/api/telegram/node-business-preview` | Builds a no-send business digest for node economics and readiness. |
| `GET` | `/tonconnect-manifest.json` | Presentation-only TON Connect manifest for wallet UI context. |
| `GET` | `/api/ton/status` | TON integration posture and safety flags. |
| `GET` | `/api/ton/risk-rules` | Source-cited TON risk rules. |
| `POST` | `/api/ton/wallet-risk-preview` | Read-only TON wallet risk passport. |

For a real Telegram Mini App, send the raw
`window.Telegram.WebApp.initData` string to `/api/telegram/webapp/verify`.
The backend validates the HMAC signature before trusting the user identity.
Telegram's Mini App docs explicitly warn that `initDataUnsafe` is not trusted
until the raw `initData` is validated server-side:
https://core.telegram.org/bots/webapps#validating-data-received-via-the-mini-app

## Mini App Flow

The `/telegram` surface is a real Mini App candidate, not just a deep link to
the desktop workbench. It loads Telegram's `telegram-web-app.js`, calls
`ready()` / `expand()` when the host API is available, and uses the Telegram
Main Button only as a local "Preview alert" trigger. It does not call Telegram
message-delivery APIs from the browser.

Current Cloud Run preview URL:
`https://guard0-miniapp-s77j6bxyra-uc.a.run.app/telegram`

Current Telegram bot:
`https://t.me/Raris0guardBot`

The intended flow is:

1. BotFather points the Mini App URL to the deployed `/telegram` route.
2. Telegram opens the Mini App and exposes raw `window.Telegram.WebApp.initData`.
3. The frontend POSTs that raw string to `/api/telegram/miniapp/session`.
4. The backend validates the HMAC with `TELEGRAM_BOT_TOKEN`.
5. The user previews a wallet intent through `/api/telegram/miniapp/preview`.
6. The response includes `walletAlert`, `mira`, a Telegram-safe message string,
   quality-gate metadata, and explicit `telegram_send=false`.
7. The user can paste or connect a TON address for `/api/telegram/miniapp/ton-preview`;
   the response is a TON Risk Passport with a Mira claim packet and no wallet
   prompt.
8. Opted-in users can send `/da`, `/node`, or `/balance` to the webhook path;
   the route returns a DA node digest preview and still does not call Telegram
   `sendMessage`.

BotFather setup values:

- Web App URL: `https://guard0-miniapp-s77j6bxyra-uc.a.run.app/telegram`
- Short description: `Pre-wallet firewall for AI-agent wallet intents.`
- Description: `0guard previews wallet risk, hack signatures, and Mira explanations before an agent reaches a signer. Preview only; no Telegram sends from the Mini App.`
- Production env is configured on Cloud Run via Secret Manager:
  `TELEGRAM_BOT_TOKEN`, `TELEGRAM_WEBHOOK_SECRET_TOKEN`, and
  `TELEGRAM_REGISTRATION_SECRET`. Do not commit or print those values.
- The bot menu button is configured as `Open 0guard` and launches the Mini App.
- The webhook is configured for message updates only and uses Telegram's
  `X-Telegram-Bot-Api-Secret-Token` header. The Flask route remains no-send.

## Production Smoke

Run the live bot/Mini App smoke from the repo root:

```bash
.venv/bin/python scripts/telegram_production_smoke.py --format markdown
```

The script reads the bot token and webhook secret from Secret Manager through
`gcloud` when local env vars are not set. It redacts token/user details and
checks:

- Cloud Run Telegram status and no-send flags.
- Browser-preview Mini App launch posture.
- Synthetic signed Telegram `initData` validation.
- Combined wallet-alert + Mira Mini App preview.
- Bot API readbacks for `getMe`, menu button, commands, and webhook health.
- Webhook route secret-header enforcement without sending Telegram messages.

Opening `/telegram` in a normal browser is still useful for judging and local
QA: it becomes `local_browser_preview`, keeps the same no-send contract, and
does not pretend that a Telegram user has been verified.

## Safety Notes

- Registration tokens are HMAC-SHA256 signed and expire after a bounded TTL.
- Default TTL is 900 seconds; maximum TTL is 3600 seconds.
- The Flask demo uses an ephemeral process-local registration secret unless
  `TELEGRAM_REGISTRATION_SECRET` is configured. Set the env var before using
  challenges across restarts or multiple replicas.
- Tokens are one-time-use by contract. Persist `verified["token_id"]` after
  successful opt-in and pass consumed ids to `ensure_registration_token_not_replayed`.
- `build_opt_in_record` stores Telegram identifiers for local registry use.
- `public_opt_in_status` redacts user labels, Telegram ids, chat ids, usernames,
  first/last names, and token ids before public display.
- No bot token, chat id, or other secret should be committed with this flow.
- Live Telegram sends remain outside this flow and still require
  `scripts/telegram_post.py --live-send-confirm SEND_TO_TELEGRAM_FROM_0GUARD`.
- Webhook handling requires `TELEGRAM_WEBHOOK_SECRET_TOKEN` and checks the
  `X-Telegram-Bot-Api-Secret-Token` header. The app does not call
  `setWebhook`; webhook registration remains an explicit operator action.

## 0G DA Node Digest Boundary

`guard0.da_node` exposes a public telemetry contract for Ari's DA node without
touching private keys or signing. The default runtime points at the prepared
Galileo testnet DA node:

- Public socket: `35.254.123.37:34000`
- Signer: `0x6De500690f88A920Db7976b161034fC835b96A49`
- Miner: `0x8c497E41405C924D81dB24aB033CAca71ED559E9`
- RPC: `https://evmrpc-testnet.0g.ai`

Routes:

- `/api/0g/da-node/status` defaults to a configured snapshot. Add `?live=1`
  for read-only RPC chain/balance checks.
- `/api/telegram/da-node-preview` wraps that status as a Telegram-safe digest
  with `telegram_send=false`.

The digest policy is deliberately conservative:

- `enabled=false`
- `shouldSendNow=false`
- `minIntervalSeconds=3600`
- `maxMessagesPerDay=6`
- `sendOnlyOnStateChange=true`

Yield is not estimated from guesses. The route reports
`not_claimed_without_reward_source` until an official reward contract, indexer,
or documented 0G source is wired in.

## 0G Storage Node Digest Boundary

`guard0.da_node` also exposes a public read-only contract for the staged
mainnet storage node. The default runtime is the RV Windows host behind the GCP
relay:

- Public socket: `35.254.123.37:1234`
- RPC: `http://127.0.0.1:5678`
- Chain ID: `16661`
- Flow contract: `0x62d4144db0f0a6fbbaeb6296c785c71B3D57C526`

Routes:

- `/api/0g/storage-node/status` defaults to a configured snapshot. Add
  `?live=1` only from a runtime that can reach the storage node RPC.
- `/api/telegram/storage-node-preview` wraps that status as a Telegram-safe
  digest with `telegram_send=false`.

Funding is deliberately gated. The route reports
`not_ready_for_mainnet_funds` while the node is in no-key soak mode and never
returns private keys, signs, broadcasts, or recommends a mainnet transfer.

## 0G Node Business Digest Boundary

`guard0.node_business` packages the revenue and capacity story without turning
the workbench into a signer or operator console.

Routes:

- `/api/0g/alignment-node/status` checks configured owner wallets or token IDs
  against the public Alignment Node subgraph when `?live=1` is supplied. It
  reports license count, running/delegated status, published reward schedule,
  and the KYC/wallet-signature blocker. It never asks for or returns a private
  key.
- `/api/0g/validator-capacity` reports the RV Windows host fit against 0G
  validator guidance. Current defaults model the Ryzen 9 9900X3D host with 24
  logical processors, about 58 GiB WSL RAM, 32 GB swap, and 1.7 TB free disk.
- `/api/0g/node-business` combines storage economics, Alignment readiness,
  validator capacity, and ZeroGuard product monetization into one operator
  packet.
- `/api/telegram/node-business-preview` wraps the business packet as a
  Telegram-safe digest with `telegram_send=false`.

The business digest is intentionally conservative. Storage rewards are labeled
as tiny current protocol yield, Alignment rewards are license-dependent, and
validator APR is not guessed. The durable monetization path is operator
monitoring, proof receipts, pre-signing wallet-risk APIs, and readiness reports.

## Wallet Alert Quality Gate

`guard0.wallet_alerts` adds the Telegram Mini App alert layer. It validates an
EVM address, evaluates the current intent, attaches source/detector evidence,
and returns only high-signal direct wallet alerts. Emerging detector gaps are
kept as digest-only notes until a matching intent, calldata pattern, or source
signal makes them wallet-specific.

The quality policy requires direct wallet relevance, a source or detector id,
a dedupe key, cooldowns, and opt-in scope before a future live bot could send.
The current Flask and workbench routes always return `preview_no_send`.

## Mira Add-On Boundary

The current Mira integration is deterministic and local: `guard0.mira` turns a
0guard policy decision into a Telegram-safe explanation with no external LLM
call. That is deliberate for the hackathon submission because it is verifiable
and does not depend on a third-party key. A future external Mira adapter should
sit behind the same contract and keep the current fields:

- `schema="0guard.mira_preview.v1"`
- `delivery="preview_no_send"` until live sends are explicitly enabled
- `telegram_send=false` unless the separate live-send CLI path is reviewed
- `network_calls` truthfully set to the actual runtime behavior

## TON Boundary

The TON integration is a native Telegram wallet lane, not a bridge. The current
repo exposes a TON Connect manifest and risk-passport APIs, but it does not call
TON Connect `sendTransaction`, `signData`, or `tonProof`, and it does not fetch
live account activity unless a future read-only indexer adapter is explicitly
enabled.

This gives 0guard a clean Telegram-native story:

1. Validate Telegram Mini App `initData` server-side.
2. Accept a TON wallet address for preview.
3. Apply TON-specific phishing, payload, Jetton/NFT spam, and live-coverage
   rules.
4. Prepare a receipt hash and Mira-ready claim packet.
5. Keep all sends, signatures, and transactions outside the Mini App.
