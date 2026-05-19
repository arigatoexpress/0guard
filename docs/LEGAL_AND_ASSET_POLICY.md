# Legal, Source, and Asset Policy

Updated: May 19, 2026.

This is the working rights posture for 0guard. It is product guidance, not
legal advice.

## License Choice

0guard uses Apache-2.0 for original source code and documentation. That keeps
the project permissive for hackathon judges, SDK users, and ecosystem partners
while adding a clearer patent grant than the prior MIT posture.

The controlling license text is in `LICENSE`. Attribution and boundary notes
are in `NOTICE`.

## Source Intelligence Boundary

0guard's OSINT posture is derived-analysis-first:

- keep source ids, owners, URLs, retrieval mode, TTLs, caveats, and rights
  envelopes;
- normalize evidence into hashes, detector hints, risk labels, and provenance
  links;
- do not resell, mirror, or expose raw upstream payloads unless the source
  terms explicitly permit it;
- keep credentialed, paywalled, anti-bot, or private-person data out of public
  product surfaces;
- fail closed when source terms or freshness are unclear.

The public demo pages and API surfaces should show evidence lineage and safety
status without copying full third-party records.

For CISA KEV, NVD CVE, MITRE ATT&CK, OFAC SLS, Chainalysis, TRM, URLhaus,
ThreatFox, Google Web Risk, and similar sources:

- treat official public feeds as defensive context, not as material to mirror
  wholesale;
- expose CVE ids, technique ids, source links, hashes, derived categories,
  confidence bands, and redacted exact-address screening results;
- do not expose exploit payloads, proof-of-concept instructions, full article
  bodies, raw sanctions rows, full wallet lists, vendor investigation payloads,
  or paid-feed exports;
- do not present sanctions signals as legal advice or compliance
  certification;
- do not assert Lazarus, DPRK, or malware attribution from MITRE/TTP context
  without corroborating wallet, domain, transaction, host, package, or vendor
  evidence.

## Generated Media Boundary

The repo contains product media that was generated or assembled for 0guard:

- `docs/hackathon-0g/assets/0guard-hackquest-demo-final.mp4`
- `docs/hackathon-0g/assets/0guard-logo.png`
- `docs/hackathon-0g/assets/0guard-workbench-provenance.png`
- `docs/hackathon-0g/assets/0guard-x-banner.png`
- `src/guard0/static/0guard-logo.png`

Treat these as 0guard project artifacts unless a future file-level note says
otherwise. Do not add third-party logos, copied screenshots, private account
screens, wallet secrets, private keys, or real user data to tracked media.

For Google Flow, Veo, Gemini, Sora, or other generation platforms, review the
platform terms before publication. Generated clips should supplement real
product footage; they must not imply live signing, bridges, swaps, payments,
Telegram sends, X posts, or 0G writes that the product does not perform.

## External Integrations

Integrations with 0G, Telegram, TON, Mira, Virtuals, x402, Lighter, Celestia,
Ika, EVM chains, and future ecosystems should be represented by one of these
states:

- `live_read_only`
- `source_ready`
- `dry_run`
- `preview_only`
- `operator_controlled`
- `blocked_pending_terms`
- `future_work`

Public pages must use these states honestly. A demo can show prepared payloads,
receipts, and manifests, but it must not present local previews as live
external actions.

## Asset Hygiene

Tracked assets need an explicit purpose and owner-facing status. Deprecated,
draft, or account-private screenshots belong in ignored `output/` folders until
they are reviewed. Reproducible caches such as `__pycache__` and local browser
smoke screenshots should not be committed.
