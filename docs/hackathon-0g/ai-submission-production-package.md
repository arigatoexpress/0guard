# 0guard AI Submission Production Package

Updated: May 16, 2026.

This package is the working brief for using Gemini, Veo 3, Claude, ChatGPT, or
Kimi to polish and produce the final HackQuest submission without weakening the
truth boundary.

## Non-Negotiable Submission Constraints

- HackQuest deadline: May 16, 2026 at 23:59 UTC+8.
- Video: public link, three minutes or less, product demo required, slide-only
  or concept-only videos rejected.
- 0G proof: include a 0G mainnet contract address and a 0G Explorer link with
  verifiable on-chain activity.
- X post: include project name, screenshot or short clip, `#0GHackathon`,
  `#BuildOn0G`, and tags `@0G_labs @0g_CN @0g_Eco @HackQuest_`.
- Veo/Gemini video clips are best used as short cinematic assets around real
  product screen capture. The current public MP4 is already assembled from
  product footage; use `veo3-flow-production-prompt.md` for a later replacement
  cut that improves clarity without adding unsupported claims.
- Generated video clips must contain no text at all. No captions, subtitles,
  lower thirds, title cards, brand lettering, API paths, fake UI labels,
  addresses, hashes, numbers, QR codes, or decorative glyphs that look like
  writing. Use narration and real product screen capture for exact proof.

Sources:

- HackQuest 0G APAC Hackathon:
  `https://www.hackquest.io/hackathons/0G-APAC-Hackathon`
- Google Flow Help, create videos:
  `https://support.google.com/flow/answer/16353334`
- Google Flow Help, model features:
  `https://support.google.com/flow/answer/16352836`
- Google Flow Help, edit videos and Scenebuilder:
  `https://support.google.com/flow/answer/16935718`
- Google Blog, Veo 3.1 Flow updates:
  `https://blog.google/innovation-and-ai/products/veo-updates-flow/`
- Google Blog, Veo 3.1 high-fidelity/upscaling updates:
  `https://blog.google/innovation-and-ai/technology/ai/veo-3-1-ingredients-to-video/`

## Final Positioning

Use this exact thesis:

```text
0guard is a 0G-native pre-wallet firewall for AI agents. It checks agent
intents against policy, calldata, known exploit patterns, and source-aware
incident intelligence before any signer can act. The system returns
allow/review/deny decisions, deterministic receipt hashes, 0G mainnet anchor
proof, Storage-ready threat records, and a read-only cross-chain guardrail
catalog.
```

Do not say:

```text
0guard trades, signs, bridges, posts, launches agents, settles x402 payments,
places Lighter orders, takes exchange account actions, or uploads live 0G Storage objects from the
browser workbench.
```

## AI Browser Workflow

Use `scripts/open_ai_submission_workspace.sh` to open the working tabs in Brave.

Recommended order:

1. Open this package and the final demo script.
2. Open Gemini or Flow for Veo 3 / Veo 3.1 clip generation.
3. Use `veo3-flow-production-prompt.md` as the current master prompt packet.
4. Compare any generated inserts against the current public MP4.
5. Replace the public MP4 only if the edited version remains under three
   minutes and stays grounded in real product footage.
6. Dry-run the X draft or thread before any new live post.
7. Keep `docs/hackathon-0g/submission-form-fields.md` as the historical
   submitted-state packet.

## Master Video Assembly

| Segment | Duration | Source |
| --- | ---: | --- |
| Cold open | 0:00-0:06 | Optional Veo clip 1 |
| Live workbench intro | 0:06-0:25 | Screen capture |
| Drift intent block | 0:25-0:50 | Screen capture |
| Kelp intent block | 0:50-1:12 | Screen capture |
| Wasabi intent block | 1:12-1:35 | Screen capture |
| 0G status and mainnet proof | 1:35-2:18 | Screen capture |
| Provenance and Storage-ready receipts | 2:18-2:36 | Screen capture |
| Cross-chain/Lighter guardrails | 2:36-2:50 | Screen capture |
| Close | 2:50-2:58 | Screen capture or optional Veo clip 4 |

## Veo 3 Prompt Pack

The current higher-quality prompt and Flow configuration lives in
`docs/hackathon-0g/veo3-flow-production-prompt.md`. Keep the older prompts
below only as compact fallback clips.

Use landscape `16:9`. Generate 8 seconds per clip. Keep generated clips fully
textless. AI video text is not accurate enough for this submission; all exact
proof belongs in narration and real product screen capture.

### Clip 1: Pre-Wallet Firewall

```text
Cinematic 8-second opener for a Web3 security product. A luminous stream of
machine-generated wallet intents flows toward a secure signing vault. Before
the intents reach the vault, a transparent firewall made of policy receipts and
cryptographic hashes filters risky red packets away while safe blue packets
continue. High-end cyber documentary style, realistic UI reflections, dark
background, cyan and white highlights, subtle 0G-inspired modular network
geometry, no readable logos, no fake transaction hashes, no text overlays.
Audio: low precise pulse, soft verification chime when a safe intent passes.
```

Negative prompt:

```text
No fake brand logos, no readable wallet addresses, no scary hacker stereotype,
no stock footage feel, no cartoon style, no illegible text overlays.
```

### Clip 2: Receipt Anchor

```text
An 8-second cinematic macro shot of a cryptographic receipt becoming anchored
into a decentralized ledger. A receipt hash appears as abstract glowing blocks,
then locks into a transparent chain grid. The motion communicates auditability,
not money movement. Dark premium interface aesthetic, crisp cyan highlights,
realistic glass materials, shallow depth of field, no readable text, no logos,
no token price visuals. Audio: quiet mechanical lock, soft confirmation tone.
```

### Clip 3: OSINT Provenance

```text
An 8-second cinematic data-room scene showing many public-source evidence cards
being normalized into a clean provenance matrix. Cards transform into hashes,
source ids, and confidence lanes without showing real personal data. Premium
investigative interface, dark neutral background, white and cyan accents,
smooth camera dolly, no news logos, no screenshots of real articles, no
readable copied text. Audio: subtle paper-to-digital sweep and calm analysis
tone.
```

### Clip 4: Cross-Chain Guardrail

```text
An 8-second cinematic visualization of a read-only cross-chain safety fabric.
Several abstract EVM and data-availability networks connect to one central
policy firewall. A separate exchange/API lane is visibly guarded but never
executes a trade. The mood is controlled, credible, and technical. Dark
background, cyan-white proof lines, tiny safety locks, no logos, no price
charts, no buy or sell buttons, no readable text. Audio: restrained network
hum, one verification chime.
```

### Clip 5: Final Hero Loop

```text
An 8-second final hero shot for a serious AI x Web3 security demo. A calm
operator dashboard shows abstract allow, review, deny lanes flowing into a
tamper-evident proof layer. The scene should feel like enterprise-grade
security infrastructure, not a trading app. Realistic dark UI, sharp details,
cinematic lighting, cyan accents, no readable labels, no fake data, no logos.
Audio: confident low swell ending in a clean proof-confirmation tone.
```

## Prompt For Gemini, Claude, ChatGPT, Or Kimi

Paste this if you want another model to critique the final video script:

```text
You are a hackathon judge and demo video editor. Review this 0guard HackQuest
video script for a 3-minute AI x Web3 submission. The video must show live
product functionality, user flow, and actual 0G component usage. It must not be
slide-only. Keep all claims honest: the browser workbench is read-only; it does
not sign, broadcast, bridge, trade, post, launch agents, settle x402 payments,
place Lighter orders, take exchange account actions, or upload live
0G Storage objects. The verified
proof is a deployed 0G mainnet PolicyReceiptAnchor contract and one anchored
deny receipt. Improve clarity, pacing, and judge impact without adding claims
that are not supported by the repo.

Script:
[paste docs/hackathon-0g/final-demo-video-script.md]
```

## YouTube Or Loom Title

```text
0guard - 0G-Native Pre-Wallet Firewall for AI Agents
```

## YouTube Or Loom Description

```text
0guard is a 0G-native pre-wallet firewall for AI agents. It evaluates agent
intent, calldata, target context, policy rules, and incident-derived exploit
intelligence before any signer can act.

Built for the 0G APAC Hackathon.

Repo: https://github.com/arigatoexpress/0guard
Demo page: https://arigatoexpress.github.io/0guard/
0G contract: 0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc
0G anchor tx:
https://chainscan.0g.ai/tx/0x64ff260ccd02aa69fc18d5727eb4530d8774003bc7df63ec7d5cda036fc438ed
```

## Final X Post

Use the existing dry-run command first:

```bash
.venv/bin/python scripts/x_post.py --file content/hackquest_x_post.json --media docs/hackathon-0g/assets/0guard-workbench-provenance.png --dry-run --verbose
```

Draft:

```text
0guard: a pre-wallet firewall for AI agents. It checks intent -> policy ->
wallet before any signature. Now: 28/28 April 2026 incidents source-linked,
28/28 detector coverage, and a 0G mainnet receipt anchor. @0G_labs @0g_CN
@0g_Eco @HackQuest_ #0GHackathon #BuildOn0G
```

## Final Operator Checklist

- Run `.venv/bin/python scripts/submission_readiness.py --format markdown`.
- Use the current generated public demo video, or replace it only with a
  manually reviewed Veo-enhanced cut if desired:
  `https://arigatoexpress.github.io/0guard/hackathon-0g/assets/0guard-hackquest-demo-final.mp4`.
- Optional: generate Veo clips only after reviewing the script.
- Use the published X post URL:
  `https://x.com/rariwrldd/status/2054779961425461542`.
- Verify repo, Pages, contract, and anchor transaction from a logged-out window.
- For X cleanup, generate and review a manifest before any live deletion.
