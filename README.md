# 0guard

> Pre-wallet firewall for AI agents on 0G. Checks intent, calldata, reputation, and exploit intelligence before any signer, bridge, or payment rail acts.

[![CI](https://github.com/arigatoexpress/0guard/actions/workflows/ci.yml/badge.svg)](https://github.com/arigatoexpress/0guard/actions)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

## What this does

0guard is a security layer that sits between an AI agent and its wallet. Instead of waiting for a wallet prompt, it reviews the proposed action first and returns `allow`, `review`, or `deny`. It produces deterministic receipts that can be anchored on 0G mainnet for audit and accountability.

## Quick start

```bash
git clone https://github.com/arigatoexpress/0guard.git
cd 0guard
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e '.[dev]'
python3 -m guard0.app
```

Open `http://127.0.0.1:8109` for the local dashboard.

Try the core flow:

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
    "agent_id": "agent-7857-demo"
  }' | python3 -m json.tool
```

## Architecture

```
AI agent or wallet app
        |
        v
0guard native preflight
        |
        +-- policy engine: mode, value, approval, bridge, send
        +-- exploit signatures: calldata selectors and behavioral patterns
        +-- reputation layer: domains, counterparties, source evidence
        +-- incident intelligence: source-linked exploit corpus
        |
        v
allow / review / deny verdict
        |
        +-- 0G Chain receipt anchor payload
        +-- Telegram/Mira alert preview
        +-- developer-kit response for agents, CI, wallets, and Mini Apps
```

## Key features

- **Intent firewall** — Evaluates actions before they reach a signer.
- **Exploit signatures** — 28 incident-derived detection seeds covering $634M+ in analyzed losses.
- **Reputation layer** — Domain, counterparty, and source-evidence scoring.
- **0G mainnet receipts** — Deterministic verdict receipts anchored on-chain.
- **Wallet-provider guard** — EIP-1193-style dapp wrapper that stops risky requests before provider access.
- **Threat intelligence** — CISA KEV, NVD CVE, MITRE ATT&CK, and crypto exploit context as defensive signals.

## Tech stack

- Python 3.10+
- Flask 3.0+
- web3.py 7.0+
- pytest, ruff
- Docker

## Safety notes

This repo is **proof-first** and read-only by design:

- No private keys, signing, or broadcasting.
- No bridges, swaps, x402 settlement, or exchange orders.
- No outbound Telegram messages from the workbench.
- Mainnet-aware but not mainnet-spending.

## Repository guide

| Path | Purpose |
| --- | --- |
| `src/guard0/` | Flask app, CLI, policy engine, signatures, OSINT, reputation, Telegram, and integration routes. |
| `contracts/` and `foundry/` | 0G mainnet receipt-anchor Solidity source and build artifacts. |
| `data/april_2026_incidents.json` | Source-linked incident dataset used for detector coverage. |
| `docs/` | Proof files, runbooks, and legal/asset policy. |
| `tests/` | pytest suite covering policy, data, routes, and integration contracts. |

## Tests

```bash
pytest -q
python3 -m compileall src scripts
ruff check src tests scripts
```

## Agent collaborators

See [AGENTS.md](AGENTS.md) for project structure, safety boundaries, and development conventions.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
