# Wallet Provider Guard

`0guard` is not a wallet and should not become one. The live protection layer is
the checkpoint before a dapp, agent, or Mini App forwards a request to the
user's wallet provider.

## Shipped Contract

`POST /api/wallet/provider-guard`

Input:

```json
{
  "origin": "https://example-dapp.test",
  "method": "eth_sendTransaction",
  "params": [
    {
      "chainId": "0x1",
      "to": "0x000000000000000000000000000000000000dEaD",
      "data": "0x095ea7b3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "value": "0x0"
    }
  ]
}
```

Output:

- `allow`: the wrapper may forward the request to the provider.
- `review`: show the 0guard receipt and explanation; do not forward yet.
- `deny`: block before any wallet prompt.

The response includes a public request summary, native-preflight receipt, and
enforcement action. It does not return raw params.

## Browser Wrapper

Use `examples/wallet_provider_guard/providerGuard.ts` to wrap an EIP-1193
provider. The wrapper calls 0guard before `provider.request(...)`, blocks
`review` and `deny`, and only forwards `allow`.

## What This Does Not Do

- no key import
- no wallet creation
- no signing by 0guard
- no transaction broadcast by 0guard
- no x402 settlement
- no fund movement
- no Telegram or social sends

That boundary is the product: 0guard becomes the pre-wallet decision layer, not
another hot-wallet runtime.
