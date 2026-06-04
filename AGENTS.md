# 0guard — Agent Guide

## What this repo does

0guard is a **0G-native agent guard** that evaluates blockchain intents, calldata, and reputation context before any wallet or signer acts. It returns `allow`, `review`, or `deny` verdicts and produces deterministic receipts that can be anchored on 0G mainnet.

## Key directories and files

```
0guard/
├── src/guard0/               # Application code
│   ├── app.py                # Flask web server and API routes
│   ├── cli.py                # Command-line interface
│   ├── policy.py             # Policy engine and security rules
│   ├── signatures.py         # Exploit signature detection
│   ├── reputation.py         # Reputation scoring and connectors
│   ├── storage.py            # Data persistence layer
│   └── telegram_routes.py    # Telegram/Mira preview routes (no sends)
├── contracts/                # Solidity receipt-anchor contracts
├── foundry/                  # Foundry build artifacts and config
├── data/                     # Incident datasets and provenance caches
├── docs/                     # Proof files, runbooks, legal policy
├── scripts/                  # Utility and ops scripts
└── tests/                    # pytest suite
```

## How to run tests / dev server

```bash
# Install
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e '.[dev]'

# Tests
pytest -q
python3 -m compileall src scripts
ruff check src tests scripts

# Dev server
python3 -m guard0.app
# open http://127.0.0.1:8109
```

## Safety boundaries (DO NOT CHANGE)

1. **No private key exposure** — Never log, store, or transmit private keys or mnemonics.
2. **No unauthorized transactions** — The engine must never sign or broadcast transactions.
3. **No social media spam** — Telegram/X routes are read-only previews; no outbound sends without explicit live-confirm flags.
4. **Testnet-first** — Blockchain interactions default to testnet unless explicitly configured for mainnet.
5. **No raw upstream resale** — Source-linked defensive outputs only; never mirror or resell raw OSINT payloads.

## Current status

- Proof-first build with one live 0G mainnet deny receipt anchored.
- 28 of 28 incident-derived seeds covered by the detector engine.
- Wallet-provider guard and Telegram Mini App are live previews with sends disabled.
- CI gates lint, tests, compile check, and demo smoke test.

# AGENTS.md — Operating Charter

> Guiding principles for any AI agent (or human) working in this repo. Derived from the Andrej Karpathy engineering philosophy. Tool-neutral: applies whether you drive this repo with Claude Code, goose, or by hand.

## The four rules
1. **Simplicity first.** Write the minimum code that solves the task. No speculative abstractions, no unrequested features, no single-use platforms. Extract a shared module only when there are >= 2 real call-sites today.
2. **Surgical changes, one concern per PR.** Touch only what the task requires. Do not opportunistically reformat, bump unrelated deps, or fix adjacent dead code. Small, reviewable, independently revertable diffs.
3. **Evals are the spec.** Define and run the repo verification (tests, build, typecheck, smoke) BEFORE and AFTER a change. Nothing merges unless it stays green. Keep the generate->verify loop tight and reversible.
4. **Delete > add; fewer dependencies.** Removing code, repos, and dependencies is the highest-leverage move. Every dependency is attack surface you own. Pin and lock what remains. Humans stay in the loop for irreversible / outward-facing / production steps (deletes, credential rotation, infra teardown, deploys).

## Safety
- Never use `git add .` or `git add -A` — stage changed files by explicit path (avoids sweeping in WIP or secrets).
- Never commit secrets; `.env*` stays gitignored (except `.env.example`).
- Treat anything outward-facing or irreversible as draft-then-confirm.
