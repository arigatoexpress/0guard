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
PYTHONPATH=src .venv/bin/python scripts/browser_smoke.py
```

That smoke injects a mock EIP-1193 provider so CI can prove the wrapper blocks
`review` and `deny` requests before forwarding. It is not a real wallet
extension proof.

Manual empty-wallet check:

```bash
cd examples/wallet_provider_guard/external_dapp
python3 -m http.server 8142
```

Then open `http://127.0.0.1:8142` in a wallet-enabled browser, keep the API
base as `https://guard0-miniapp-s77j6bxyra-uc.a.run.app`, and use a throwaway
empty account. `Read chain` may forward; `Switch chain` and `Unlimited approval`
should stop before a wallet prompt.

After the manual run, enter the empty throwaway wallet address in the proof
draft panel. The page hashes it locally and emits the receipt hashes, provider
call counts, and recorder command without storing the raw address or raw params.
Record only that public-safe proof metadata:

```bash
PYTHONPATH=src .venv/bin/python scripts/record_wallet_provider_external_proof.py \
  --external-dapp-origin http://127.0.0.1:8142 \
  --guard-base-url https://guard0-miniapp-s77j6bxyra-uc.a.run.app \
  --wallet-address 0xTHROWAWAY_EMPTY_WALLET_ADDRESS \
  --read-receipt-hash <sha256-from-eth_chainId-verdict> \
  --review-receipt-hash <sha256-from-switch-chain-verdict> \
  --deny-receipt-hash <sha256-from-approval-deny-verdict> \
  --out docs/hackathon-0g/wallet-provider-external-proof.json \
  --real-wallet-extension \
  --window-ethereum-present \
  --throwaway-empty-wallet \
  --operator-reviewed
```

Do not claim production wallet protection until this manual check has been run
against an actual wallet extension window with an empty throwaway account and
the denial evidence has been saved. `/api/wallet/provider-proof` stays
`missing` until that artifact exists.

## Safety

- 0guard does not forward provider calls itself.
- `review` and `deny` block before the wallet popup.
- raw params are not returned by `/api/wallet/provider-guard`.
- the wrapper has no private-key or seed-phrase path.
