# 0guard Judge Demo Walkthrough

## Goal

Make the demo easy for judges to score: one clear threat model, one live
workbench, one 0G integration loop, and one honest gap register.

## Opening Line

0guard is a pre-wallet firewall for AI agents. It blocks risky agent intent
before a wallet, bridge, Telegram channel, or deploy script can act.

## Three-Minute Flow

### 0:00-0:30 - Problem

AI agents can now plan, trade, bridge, and request signatures at machine speed.
Most crypto security tools inspect a transaction after it is already near the
wallet. 0guard moves the safety check one step earlier: intent first, signer
later.

### 0:30-1:30 - Detection

Show three incident-derived intents:

- Drift-style durable-nonce social engineering.
- Kelp-style single-DVN bridge/verifier weakness.
- Wasabi-style compromised-deployer upgrade path.

For each one, point to:

- `decision`
- `severity`
- `blockers`
- `receipt_hash`

The judge should understand that the product is not only matching strings. It
combines action mode, signature requirement, calldata selectors, known IOCs,
behavioral sequences, and policy context.

### 1:30-2:20 - 0G Round-Trip

Run the read-only 0G status check:

```bash
curl -s http://127.0.0.1:8109/api/0g/status | python3 -m json.tool
```

Call out:

- `schema: 0guard.0g_status.v1`
- `network` and live RPC status
- `readMode: live_rpc_read_only`
- `rpc.observedChainId`
- `rpc.latestBlockNumber`
- `safety.signingEnabled: false`
- `safety.broadcastingEnabled: false`

Then run an evaluation with 0G proof flags:

```bash
curl -s -X POST http://127.0.0.1:8109/api/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "intent": {
      "action": "approve",
      "calldata": "0x095ea7b3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "mode": "live_transaction",
      "requires_signature": true
    },
    "enable_0g_anchor": true,
    "enable_0g_storage": true,
    "agent_id": "agent-7857-demo"
  }' | python3 -m json.tool
```

Call out:

- `receipt_hash`
- `zero_g.chain_anchor.status: preflight`
- `zero_g.chain_anchor.chain_id: 16661`
- `zero_g.storage_receipt.root_hash`
- `zero_g.storage_receipt.key`

Explain the round-trip plainly: intent enters, verifier/policy returns a
decision, the decision becomes a receipt hash, and the 0G proof payload is
prepared for Chain and Storage while the workbench remains read-only.

Then show the mainnet proof:

```bash
python3 -m json.tool docs/hackathon-0g/mainnet-proof.json
```

Open the anchor transaction:

```text
https://chainscan.0g.ai/tx/0x64ff260ccd02aa69fc18d5727eb4530d8774003bc7df63ec7d5cda036fc438ed
```

### 2:20-2:45 - Dataset and Coverage

Show that the evidence base is structured:

```bash
curl -s http://127.0.0.1:8109/api/data/summary | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/data/provenance | python3 -m json.tool
curl -s 'http://127.0.0.1:8109/api/data/provenance?live=1' | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/data/detection-coverage | python3 -m json.tool
curl -s http://127.0.0.1:8109/api/data/signature-map | python3 -m json.tool
```

Position this as a data product, not a slide: the dataset is schema-validated,
fingerprinted, summarized, filterable, and used as detector coverage input.
The signature map also names the detector gaps instead of hiding misses behind
one aggregate score.
The provenance matrix shows which canonical incidents already correlate to
live public source records and which still need postmortems, transaction links,
or trusted incident reports.
In the browser workbench, use `Provenance` for the deterministic offline view
backed by `data/incident_provenance_cache.json`, and `Live provenance` only
when the network path is healthy.

If time allows, show the OSINT source layer:

```bash
curl -s http://127.0.0.1:8109/api/osint/sources | python3 -m json.tool
curl -s 'http://127.0.0.1:8109/api/osint/signals?live=1&limit=5' | python3 -m json.tool
```

Call out source owner, rights envelope, output policy, caveats, and record
hashes. 0guard sells derived evidence and guardrail decisions, not raw source
payloads.

### 2:45-3:00 - Safety Close

Close with the boundary:

0guard is intentionally read-only in the browser workbench. It does not hold
keys, sign transactions, broadcast 0G writes, move funds, trade, or send
Telegram messages from the demo path. The mainnet receipt anchor is already
deployed; the next milestone is live runtime readback verification plus Storage
upload/readback.

## Judge Questions and Crisp Answers

### Is this live on 0G?

The app reads 0G live today. The browser prepares chain anchoring as a preflight
payload, and the submission includes a deployed 0G mainnet receipt anchor plus
one anchored deny receipt.

### Are you writing to 0G Storage?

The demo produces deterministic Storage-ready receipts and root hashes. Live
upload/readback is a mainnet/testnet gap, not claimed complete.

### Where does 0G Compute fit?

Compute is the planned inference layer for behavioral anomaly scoring beside the
deterministic signature engine. The current submission keeps that as
architecture/future work instead of faking inference output.

### Can the demo move funds?

No. The workbench has no signing or broadcast path. It evaluates intent before
custody risk begins.

### Why not just use a wallet scanner?

Wallet scanners inspect transactions near signing time. 0guard evaluates agent
goal, prompt, tool mode, calldata, policy, IOCs, and receipts before the wallet
is reached.
