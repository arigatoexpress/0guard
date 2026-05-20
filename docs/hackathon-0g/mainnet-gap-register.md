# 0guard Mainnet Gap Register

This register keeps the hackathon submission honest. It separates what judges
can verify now from what remains before a production/mainnet launch.

## Verified or Demo-Ready Now

- Intent firewall: browser/API/CLI policy evaluation returns allow/review/deny
  verdicts. Evidence: `/api/evaluate`, `python3 -m guard0.cli evaluate`, and
  `scripts/demo_april_2026.py`.
- Incident signatures: April 2026 exploit signatures and behavioral checks are
  wired into the detector. Evidence: `data/april_2026_incidents.json` and
  `/api/data/detection-coverage`.
- Dataset validation: incident data is schema-checked, summarized,
  fingerprinted, and filterable. Evidence: `/api/data/summary` and
  `/api/data/incidents`.
- OSINT source layer: rights-aware source metadata, live readiness, normalized
  public signal leads, and signature gap mapping are exposed read-only.
  Evidence: `/api/osint/sources`, `/api/osint/readiness`,
  `/api/osint/signals`, and `/api/data/signature-map`.
- 0G Galileo read: live read-only RPC status check reports chain ID, latest
  block, latency, and safety flags. Evidence: `/api/0g/status`.
- 0G Chain payload: receipt anchor payloads are produced when
  `enable_0g_anchor=true`. Evidence: `zero_g.chain_anchor.status: preflight`.
- 0G mainnet anchor: `PolicyReceiptAnchor` is deployed on 0G mainnet and one
  deny receipt is anchored. Evidence:
  `docs/hackathon-0g/mainnet-proof.json`,
  `https://chainscan.0g.ai/address/0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc`,
  and
  `https://chainscan.0g.ai/tx/0x64ff260ccd02aa69fc18d5727eb4530d8774003bc7df63ec7d5cda036fc438ed`.
- 0G receipt verifier: `/api/0g/receipt?receipt_hash=...` performs a read-only
  verifier lookup when `ZGG_RECEIPT_CONTRACT` is configured and returns
  `contract_not_configured` honestly otherwise.
- 0G Storage payload: Storage-ready receipts and deterministic root hashes are
  produced for matching threat intel. Evidence:
  `zero_g.storage_receipt.root_hash` and `/api/0g/storage-upload/manifest`,
  which exposes flat live-proof status fields plus the external recorder
  command template.
- 0G node telemetry: read-only DA/storage/alignment/validator/operator routes
  expose balance, relay, peer, sync, yield-source, and readiness posture without
  funding or signing. Evidence: `/api/0g/da-node/status`,
  `/api/0g/storage-node/status`, `/api/0g/node-business`.
- 0G Private Computer readiness: Router/model/API-key/hot-wallet resources are
  manifest-ready, can read the Router model catalog without authentication,
  expose a no-inference prompt-scrub smoke contract, and verify a future paid
  smoke proof without storing raw prompts, raw responses, API keys, private
  keys, or payment headers.
  Evidence: `/api/0g/private-computer`, `/api/0g/private-computer?live=1`,
  `/api/0g/private-computer/smoke-preview`,
  `/api/0g/private-computer/smoke-proof`,
  `/api/0g/hot-wallet-resources`, and
  `docs/0G_PRIVATE_COMPUTE_AND_HOT_WALLET_RUNBOOK.md`.
- Production gap matrix: the repo now exposes a machine-readable real/local/
  source-ready/mock classifier and an eval-first model-training roadmap.
  Evidence: `/api/production/gaps`, `/api/model/training-roadmap`,
  `/api/model/incident-eval-set`, `data/evals/incident_detector_eval.v1.jsonl`,
  and `docs/PRODUCTION_GAP_MATRIX.md`.
- First derived reputation backfill: PhishDestroy is promoted into a derived
  artifact with hashes/counts/evidence only, no raw domains. Evidence:
  `/api/reputation/backfill/status` and
  `data/backfill/reputation_features/phishdestroy/latest.json`.
- x402 dry-run and proof rail: wallet-preflight product route returns HTTP-402
  metadata and accepts only a fixture payment header without facilitator calls
  or settlement. The settlement-policy route now exposes caps/terms plus proof
  status, and `/api/x402/settlement-proof` verifies an externally performed
  Base Sepolia payment using only hashes and public receipt metadata.
  Evidence: `/api/x402/dry-run/wallet-preflight`,
  `/api/x402/settlement-policy`, and `/api/x402/settlement-proof`.
- Telegram Mira preview: local opt-in and response preview exist without
  sending Telegram messages. Evidence: `/api/telegram/status` and
  `/api/telegram/mira-preview`.

## Mainnet/Testnet Gaps

- Runtime verifier config: the public proof file is complete, but a local demo
  that wants `/api/0g/receipt` to return `verified` must set
  `ZGG_CHAIN_RPC=https://evmrpc.0g.ai`, `ZGG_CHAIN_ID=16661`, and
  `ZGG_RECEIPT_CONTRACT=0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc`.
- Live 0G Storage upload: current Storage receipts and bundle manifests are
  deterministic and Storage-ready but not uploaded by default. The exact
  operator path is now:
  `PYTHONPATH=src .venv/bin/python scripts/build_0g_storage_bundle.py`, upload
  `dist/0g-storage/zeroguard-public-safe-derived-bundle.json` with the official
  0G Storage SDK from a reviewed signer environment, download it back, then run
  `scripts/record_0g_storage_live_proof.py` with the upload root, transaction
  hash, uploaded bundle, and downloaded file. The readiness gate stays blocked
  until the recorded downloaded hash equals the uploaded bundle hash.
- Historical feature store: the backfill plan exists, but production still
  needs scheduled append-only JSONL runs and then DuckDB/SQLite query storage
  for source-cited incidents, reputation features, node telemetry, and x402
  usage metadata. The first incident eval and first reputation artifact now
  exist; the next step is supervision and query storage.
- 0G Compute scoring: current scoring is deterministic policy/signature logic,
  not live paid 0G Compute inference. Next step: deposit a small Router budget
  through `pc.0g.ai`, create one server-side API key, review the smoke-preview
  contract, and run a tiny operator-confirmed inference smoke before using 0GM
  explanations in previews.
- x402 Base Sepolia proof: product caps/terms and the recorder now exist, but
  no real facilitator proof is recorded by default. Next step: from a
  throwaway buyer wallet, perform one reviewed low-cost x402 payment to the
  reviewed pay-to address, hash the payment header and derived response packet,
  then run `scripts/record_x402_base_sepolia_settlement_proof.py`. Never store
  the raw `X-PAYMENT` header, signatures, or private keys.
- 0G model data loop: 0GM/local inference should summarize and explain
  deterministic verdict packets, not replace policy authority. Next step: build
  the remaining eval harness around the new incident JSONL export, then extend
  it with policy traces, node telemetry, and no-send peer drafts before claiming
  training or fine-tuning.
- Provenance completion: 28 of 28 April 2026 records now carry per-incident
  source URLs and reviewed derived source evidence. Detector coverage is 28 of
  28 incident-derived patterns after the `Quant` row was promoted from
  SlowMist-syndicated EIP-7702 delegated batch access-control evidence.
- Key custody: the workbench correctly contains no private keys, but production
  anchoring needs signer custody. Next step: use a dedicated deployer/signer
  path outside the browser workbench, with explicit confirmation and no custody
  in repo.
- Hot wallet resources: wallet roles are identified, but no Router deposit,
  Direct provider transfer, storage-miner funding, staking, or delegation is
  executed by the app. Next step: fill the transaction manifest with exact
  chain, recipient/contract, amount, max fee, and final confirmation.
- Mainnet launch: mainnet requires real tokens, audit, monitoring, and rollback
  plans. Next step: complete testnet verification first, then prepare a
  reversible mainnet runbook.

## Claims to Avoid

- Do not say 0guard has live 0G Compute inference today.
- Do not say 0guard has funded Router balance, provider sub-accounts, staking,
  delegation, or mainnet storage uploads unless a fresh proof route exists.
- Do not say the workbench can deploy, sign, trade, bridge, or move funds.
- Do not imply Telegram messages are sent during the judge demo.
- Do not use "fully decentralized" until Storage upload, Chain anchoring, and
  verifier readback are live.

## Strong Honest Claim

0guard demonstrates the end-to-end safety architecture on 0G without crossing
dangerous workbench boundaries: live read-only 0G proof, deterministic policy
receipts, a mainnet PolicyReceiptAnchor with one anchored deny receipt,
Storage-ready threat-intel receipts, and explicit remaining gaps for live
Storage upload and 0G Compute inference.
