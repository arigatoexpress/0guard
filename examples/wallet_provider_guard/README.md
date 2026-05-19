# Wallet Provider Guard Example

This example shows the practical 0guard integration point for browser wallets:
wrap an EIP-1193 provider, call `/api/wallet/provider-guard`, and only forward
requests that return `allow`.

The wrapper is intentionally not a wallet, custodian, signer, or broadcaster.
It never imports keys and never creates transactions. It decides whether your
app should forward the original request to the user's own provider.

## Minimal Use

```ts
import { create0guardProvider } from "./providerGuard";

const guardedEthereum = create0guardProvider(window.ethereum, {
  baseUrl: "http://127.0.0.1:8109",
  origin: window.location.origin,
});

const chainId = await guardedEthereum.request({ method: "eth_chainId" });
```

Sensitive methods such as transaction sends, message signing, and permission
grants return a `WalletGuardBlockedError` when 0guard says `review` or `deny`.
Show the receipt and explanation to the user before any wallet prompt.

## External Dapp Smoke

`examples/wallet_provider_guard/external_dapp/` is a browser-ready static dapp
that runs on its own origin and calls a hosted or local 0guard API before
touching `window.ethereum`.

Local smoke:

```bash
PYTHONPATH=src .venv/bin/python scripts/wallet_provider_external_dapp_smoke.py
```

Manual empty-wallet check:

```bash
cd examples/wallet_provider_guard/external_dapp
python3 -m http.server 8142
```

Then open `http://127.0.0.1:8142` in a wallet-enabled browser, keep the API
base as `https://guard0-miniapp-s77j6bxyra-uc.a.run.app`, and use a throwaway
empty account. `Read chain` may forward; `Switch chain` and `Unlimited approval`
should stop before a wallet prompt.

## Safety

- 0guard does not forward provider calls itself.
- `review` and `deny` block before the wallet popup.
- raw params are not returned by `/api/wallet/provider-guard`.
- the wrapper has no private-key or seed-phrase path.
