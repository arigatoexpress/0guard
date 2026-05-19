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

## Safety

- 0guard does not forward provider calls itself.
- `review` and `deny` block before the wallet popup.
- raw params are not returned by `/api/wallet/provider-guard`.
- the wrapper has no private-key or seed-phrase path.
