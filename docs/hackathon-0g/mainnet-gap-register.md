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
  `zero_g.storage_receipt.root_hash`.
- Telegram Mira preview: local opt-in and response preview exist without
  sending Telegram messages. Evidence: `/api/telegram/status` and
  `/api/telegram/mira-preview`.

## Mainnet/Testnet Gaps

- Runtime verifier config: the public proof file is complete, but a local demo
  that wants `/api/0g/receipt` to return `verified` must set
  `ZGG_CHAIN_RPC=https://evmrpc.0g.ai`, `ZGG_CHAIN_ID=16661`, and
  `ZGG_RECEIPT_CONTRACT=0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc`.
- Live 0G Storage upload: current Storage receipts are deterministic and
  Storage-ready but not uploaded by default. Next step: wire the 0G Storage
  SDK/gateway upload behind explicit operator config and add readback by key or
  root hash.
- 0G Compute scoring: current scoring is deterministic policy/signature logic,
  not live 0G Compute inference. Next step: add a Compute-backed anomaly scorer
  as an optional signal with clear provenance in the verdict.
- Provenance completion: 28 of 28 April 2026 records now carry per-incident
  source URLs and reviewed derived source evidence. Detector coverage is 28 of
  28 incident-derived patterns after the `Quant` row was promoted from
  SlowMist-syndicated EIP-7702 delegated batch access-control evidence.
- Key custody: the workbench correctly contains no private keys, but production
  anchoring needs signer custody. Next step: use a dedicated deployer/signer
  path outside the browser workbench, with explicit confirmation and no custody
  in repo.
- Mainnet launch: mainnet requires real tokens, audit, monitoring, and rollback
  plans. Next step: complete testnet verification first, then prepare a
  reversible mainnet runbook.

## Claims to Avoid

- Do not say 0guard has live 0G Compute inference today.
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
