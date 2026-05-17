# Threat Receipt Passport

This is the judge-facing proof drill for 0guard. It compresses the product into
one falsifiable flow: agent intent in, safety verdict out, receipt hash created,
source evidence attached, and 0G proof fields made explicit.

## Passport Fields

| Field | Current value |
|---|---|
| Product | `0guard` |
| Track | `Track 5: Privacy & Sovereign Infrastructure` |
| Agent session | `agent-7857-demo` |
| Sample intent | Unlimited ERC-20 approval in `live_transaction` mode |
| Expected verdict | `deny` |
| Expected severity | `critical` |
| Detector hits | `critical_selector:approve(address,uint256)`, `unlimited_approval` |
| Provenance layer | `/api/data/provenance` and canonical dataset evidence |
| Receipt hash | returned by `/api/evaluate` |
| 0G Chain status today | 0G mainnet anchor deployed; workbench still emits preflight payloads |
| 0G Storage status today | Storage-ready root hash and payload, no default upload |
| HackQuest-final proof | `docs/hackathon-0g/mainnet-proof.json` |

## Reproduce Locally

Start the server:

```bash
cd /Users/aribs/Code/0guard
.venv/bin/python -m guard0.app
```

Create the passport receipt:

```bash
curl -s http://127.0.0.1:8109/api/hackathon/threat-passport | python3 -m json.tool
```

Or run the underlying evaluation route directly:

```bash
curl -s -X POST http://127.0.0.1:8109/api/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "intent": {
      "action": "approve",
      "mode": "live_transaction",
      "requires_signature": true,
      "calldata": "0x095ea7b3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    },
    "enable_0g_anchor": true,
    "enable_0g_storage": true,
    "agent_id": "agent-7857-demo"
  }' | python3 -m json.tool
```

Expected proof fields:

- `decision: deny`
- `severity: critical`
- `zero_g.chain_anchor.status: preflight`
- `zero_g.chain_anchor.chain_id` matches the configured 0G network; the submitted
  mainnet proof uses `16661`
- `zero_g.storage_receipt.root_hash`
- `receipt_hash`

Mainnet proof for this exact receipt:

- 0G mainnet contract:
  `0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc`
- Contract page:
  `https://chainscan.0g.ai/address/0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc`
- Anchored receipt hash:
  `0x9739dbd4afb6ab21f15ccb634b49dabc9144550ef06d346cb4e7cd363e74afd1`
- Anchor transaction:
  `https://chainscan.0g.ai/tx/0x64ff260ccd02aa69fc18d5727eb4530d8774003bc7df63ec7d5cda036fc438ed`

Check source evidence:

```bash
curl -s http://127.0.0.1:8109/api/data/provenance | python3 -m json.tool
curl -s 'http://127.0.0.1:8109/api/data/provenance?live=1' | python3 -m json.tool
```

Check final readiness:

```bash
.venv/bin/python scripts/submission_readiness.py --format markdown
```

## Mainnet Completion Slot

Completed on May 14, 2026 UTC:

```text
0G_MAINNET_CONTRACT_ADDRESS=0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc
0G_MAINNET_EXPLORER_URL=https://chainscan.0g.ai/tx/0x64ff260ccd02aa69fc18d5727eb4530d8774003bc7df63ec7d5cda036fc438ed
ANCHORED_RECEIPT_HASH=0x9739dbd4afb6ab21f15ccb634b49dabc9144550ef06d346cb4e7cd363e74afd1
ANCHOR_TRANSACTION_HASH=0x64ff260ccd02aa69fc18d5727eb4530d8774003bc7df63ec7d5cda036fc438ed
```
