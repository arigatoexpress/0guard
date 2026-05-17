# HackQuest Submission Form Fields

Generated for final operator submission on May 14, 2026. The project was
submitted and publicly verified on May 14, 2026 at 05:32:38 UTC, updated
and publicly re-verified on May 15, 2026 at 20:28:18 UTC, then rechecked on
May 16, 2026 at 14:14:05 UTC after the repository/license/video-packet
professionalization pass.

This file remains the copy/paste packet and historical record. Current
submitted-state proof lives in
`docs/hackathon-0g/hackquest-submission-proof.json`.

## Project

HackQuest draft URL:

```text
https://www.hackquest.io/projects/setup/f8333543-559e-48f4-b6fa-4ff447777966
```

HackQuest public project:

```text
https://www.hackquest.io/projects/0guard
```

Submitted state:

```text
isSubmit=true
hackathonId=57e543a9-0b08-4ba3-8326-e5cd751c0248
prizeTrack=Grand Prizes
```

Project name:

```text
0guard
```

Recommended track:

```text
Track 5: Privacy & Sovereign Infrastructure
```

Alternate track:

```text
Track 1: Agentic Infrastructure & OpenClaw Lab
```

One-line description:

```text
0guard is a 0G-native pre-wallet firewall and Telegram Mini App that checks AI-agent wallet intents before any signer can act.
```

## Summary

```text
0guard is a pre-wallet firewall for AI agents. It checks intent, calldata, policy context, and source-linked exploit intelligence before a wallet is asked to sign. The current stack includes a live Telegram Mini App, server-side Telegram initData validation, wallet-alert plus Mira previews, deterministic receipts, 28/28 incident-derived detector coverage, and one deny receipt anchored on 0G mainnet. The workbench and Mini App stay read-only: no signing, broadcasts, trading, bridging, x402 settlement, exchange actions, or Telegram sends.
```

## Problem

```text
AI agents are gaining wallet and bridge tooling faster than their safety controls are maturing. Most security checks happen near signing time, after an agent has already formed a risky action. 0guard moves the review point earlier: intent first, signer later.
```

## Solution

```text
0guard checks agent intent against deterministic policy rules, known exploit signatures, behavioral sequences, domain context, and source-cited incident intelligence. Risky actions are blocked before wallet custody begins, and every evaluation can become a tamper-evident receipt for 0G Chain and 0G Storage workflows.
```

## 0G Integration

```text
0guard uses 0G Chain for policy receipt anchoring, 0G Storage for portable threat-intel receipt payloads and root hashes, and a planned 0G Compute layer for agent-risk anomaly scoring. A PolicyReceiptAnchor contract is deployed on 0G mainnet with one anchored deny receipt; the browser workbench remains read-only and returns deterministic Storage-ready root hashes without private keys or browser-side broadcasts.
```

Proof routes to show:

```text
/api/0g/status
/api/evaluate with enable_0g_anchor=true and enable_0g_storage=true
/api/data/provenance
/api/data/provenance?live=1
/api/integrations/cross-chain
/api/integrations/virtuals-facilitator
docs/hackathon-0g/mainnet-proof.json
```

## Links

Repository:

```text
https://github.com/arigatoexpress/0guard
```

Public demo page:

```text
https://arigatoexpress.github.io/0guard/hackathon-0g/
```

Telegram Mini App:

```text
https://guard0-miniapp-s77j6bxyra-uc.a.run.app/telegram
```

Telegram bot:

```text
https://t.me/Raris0guardBot
```

Project images submitted to HackQuest:

```text
https://arigatoexpress.github.io/0guard/hackathon-0g/assets/0guard-workbench-provenance.png
https://arigatoexpress.github.io/0guard/hackathon-0g/assets/0guard-x-banner.png
```

Screenshot asset:

```text
docs/hackathon-0g/assets/0guard-workbench-provenance.png
```

Final readiness checklist:

```text
docs/hackathon-0g/final-submission-checklist.md
```

Demo script:

```text
docs/hackathon-0g/final-demo-video-script.md
```

Professional replacement video packet:

```text
docs/hackathon-0g/veo3-flow-production-prompt.md
https://arigatoexpress.github.io/0guard/hackathon-0g/veo3-flow-production-prompt.md
```

Demo video URL:

```text
https://arigatoexpress.github.io/0guard/hackathon-0g/assets/0guard-hackquest-demo-final.mp4
```

X post URL:

```text
https://x.com/rariwrldd/status/2054779961425461542
```

0G contract address:

```text
0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc
```

0G explorer URL:

```text
https://chainscan.0g.ai/tx/0x64ff260ccd02aa69fc18d5727eb4530d8774003bc7df63ec7d5cda036fc438ed
```

0G contract page:

```text
https://chainscan.0g.ai/address/0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc
```

Anchored receipt hash:

```text
0x9739dbd4afb6ab21f15ccb634b49dabc9144550ef06d346cb4e7cd363e74afd1
```

0G on-chain integration proof field:

```text
0G Chain anchors policy receipt hashes. Contract: 0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc. Anchor tx: https://chainscan.0g.ai/tx/0x64ff260ccd02aa69fc18d5727eb4530d8774003bc7df63ec7d5cda036fc438ed. Public proof packet: https://arigatoexpress.github.io/0guard/hackathon-0g/. The live Telegram Mini App and browser workbench keep signing/broadcasting disabled while returning Storage-ready root hashes and receipt payloads.
```

Post-submit professionalization note:

```text
The public proof packet now also exposes Apache-2.0 licensing, NOTICE/source-rights boundaries, a public asset registry, /api/readyz, /api/reputation/shadow-cache, /api/osint/sources with 30 tracked source lanes, /api/reputation/connectors with 17 no-network connector candidates, and the Flow/Veo 3 production packet for a polished post-submit cut.
```

## X Post

Required tags and hashtags:

```text
@0G_labs @0g_CN @0g_Eco @HackQuest_
#0GHackathon #BuildOn0G
```

Dry-run command:

```bash
.venv/bin/python scripts/x_post.py --file content/hackquest_x_post.json --media docs/hackathon-0g/assets/0guard-workbench-provenance.png --dry-run --verbose
```

Live command after Ari review:

```bash
.venv/bin/python scripts/x_post.py --file content/hackquest_x_post.json --media docs/hackathon-0g/assets/0guard-workbench-provenance.png --live-post-confirm POST_TO_X_FROM_0GUARD
```

Readiness audit:

```bash
.venv/bin/python scripts/submission_readiness.py --format markdown
```

## Final Submit Order

Completed on May 14, 2026 and refreshed on May 15, 2026:

1. Saved the HackQuest project setup fields via HackQuest GraphQL.
2. Submitted the HackQuest project with the 0G custom submission fields.
3. Verified public readback at `https://www.hackquest.io/projects/0guard`.
4. Updated the public MVP link, one-liner, description, progress note,
   project images, deployment details, and 0G proof field to include the
   Telegram Mini App and current proof packet.
5. Refreshed the public proof packet, repo license posture, source/asset
   policy, asset registry, and Flow/Veo production packet on May 16, 2026.
6. Refreshed the production source/intelligence proof on May 16, 2026:
   production revision `guard0-miniapp-112c7b7`, 30 source lanes, 17
   no-network connector candidates, and new disabled-by-default ThreatFox,
   Chainalysis sanctions oracle, and Google Cloud Web Risk lanes.

## Manual Recovery Note

The signed-in HackQuest draft exists and the project is now submitted. Do not
continue blind UI automation. Future checks should use public readback unless a
specific field must be edited.

## Claims To Avoid

- Do not claim live 0G Compute inference.
- Do not imply the browser can sign, trade, bridge, send Telegram messages, or
  move funds.
- Do not claim live Virtuals launch, x402 settlement, or custom 0G x402
  facilitation until those paths are separately configured and verified.
- Do not claim live Lighter orders, exchange account actions, transfers, or
  withdrawals from the workbench.
- Do not mirror or resell raw upstream OSINT payloads.
