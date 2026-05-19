# ZeroGuard Strategic Review

Updated: May 17, 2026.

This is the critical product compass for the current ZeroGuard stack. The
machine-readable version is:

```bash
curl -s http://127.0.0.1:8109/api/product/strategy-review | python3 -m json.tool
```

The route is read-only. It does not fetch live vendor feeds, call paid
inference, upload to 0G Storage, settle x402, send Telegram messages, sign
transactions, broadcast transactions, or move funds.

## The Hard Critique

ZeroGuard is strongest when it is narrow:

> Pre-wallet risk receipts for AI agents.

The product gets weaker when it looks like every adjacent crypto/AI integration
at once. 0G Chain, 0G Storage, 0G Private Computer, x402, Telegram, Raspberry
Pis, and the Windows storage node should all support the same spine:

1. Decide before a wallet prompt.
2. Explain with source-linked evidence.
3. Produce a receipt.
4. Prove selected receipts on 0G.
5. Deliver derived intelligence through opt-in or paid routes.

## What I Would Do Differently

- Lead with one buyer route, not the integration catalog.
- Treat 0G node ops as credibility and telemetry, not as a near-term yield
  promise.
- Build the historical feature store before adding more adapter logos.
- Use 0GM and Private Computer as a sealed explanation layer, never as policy
  authority.
- Keep Telegram as a pull-first operator console until opt-in, rate limits, and
  webhook identity proof are complete.
- Make every demo fixture visibly fixture-only or graduate it into an eval case.
- Freeze one x402 paid response schema before live settlement.

## Product Spine

| Layer | Job | Proof routes |
| --- | --- | --- |
| Decision | Pre-wallet allow/review/deny. | `/api/evaluate`, `/api/native-preflight` |
| Evidence | Human-readable threat dossier. | `/api/threat-case-file`, `/api/reputation/shadow-cache` |
| Proof | 0G receipt and storage trail. | `/api/0g/receipt`, `/api/0g/proof-ladder`, `/api/0g/storage-upload/manifest` |
| Distribution | Opt-in Telegram and x402 delivery. | `/api/telegram/status`, `/api/x402/dry-run/wallet-preflight` |
| Operations | Node/Pi telemetry. | `/api/0g/storage-node/status?snapshot=1`, `/api/0g/pi-mesh?snapshot=1` |

## Build Order

1. Freeze the first wallet-preflight product contract.
2. Seed the historical feature store from current incidents, eval cases, and
   derived reputation artifacts.
3. Configure Telegram identity readback with sends still disabled.
4. Upload the public-safe bundle to 0G Storage and prove download hash equality.
5. Run one budget-capped 0G Private Computer smoke on a redacted verdict packet.
6. Promote x402 from dry-run to testnet facilitator with spend caps and refund
   language.

## Defer Or Kill

- Yield marketing until official reward evidence exists.
- Unsolicited peer messages.
- More dashboard tabs that do not attach to the product spine.
- Live mainnet x402 settlement before testnet proof.
- Any model wording that implies it can override deterministic policy.

## Nice To Have

- Risk receipt explorer.
- Operator timeline of incidents, reputation runs, node snapshots, and proof
  receipts.
- Pi-collected storage health timeseries.
- Judge mode that hides unfinished surfaces.
- Customer terms packet for defensive analysis, no legal sanctions advice, no
  raw-feed resale, and no custody.

