# 0guard Veo 3 / Flow Production Packet

Updated: May 16, 2026.

Goal: create a replacement-quality 0guard demo video that feels professional,
cypherpunk, calm, and technically credible. The video should explain the simple
human story first, then prove the system with real product footage and 0G
mainnet evidence. Generated clips are atmosphere and visual explanation. Real
screen capture remains the source of truth.

## Current Flow Reality Check

Use these current Google Flow constraints when building the cut:

- Flow can create video clips from text prompts, visual references, voice
  references, start frames, and end frames.
- Google recommends prompts that specify subject, action, environment,
  lighting, and style.
- Flow model settings include aspect ratio, number of outputs, and model.
- Veo 3.1 supports audio generation, but it is still experimental.
- Speech works better when transcripts are long enough to fit the clip, and it
  can still produce low-quality or missing audio.
- Flow Scenebuilder can arrange and trim multiple clips, but final editing in
  DaVinci Resolve, Premiere, ScreenFlow, CapCut, or Descript is still the safer
  route for timing, mix, and product screen capture.
- No text rule: every generated Veo/Flow clip must be textless. Do not generate
  subtitles, captions, lower thirds, labels, logos made of letters, UI words,
  addresses, hashes, article snippets, terminal output, or decorative glyphs
  that look like writing. Use narration and real product screen capture for all
  exact claims.

Official references:

- Google Flow Help, create videos:
  `https://support.google.com/flow/answer/16353334`
- Google Flow Help, model features:
  `https://support.google.com/flow/answer/16352836`
- Google Flow Help, edit videos and Scenebuilder:
  `https://support.google.com/flow/answer/16935718`
- Google Blog, Flow overview:
  `https://blog.google/innovation-and-ai/products/google-flow-veo-ai-filmmaking-tool/`
- Google Blog, Veo 3.1 Flow updates:
  `https://blog.google/innovation-and-ai/products/veo-updates-flow/`
- Google Blog, Veo 3.1 high-fidelity/upscaling updates:
  `https://blog.google/innovation-and-ai/technology/ai/veo-3-1-ingredients-to-video/`

## Flow Project Setup

Project name:

```text
0guard - Mainnet Proof Cut - May 2026
```

Primary settings:

| Setting | Use |
| --- | --- |
| Model | Veo 3.1 Quality for final clips; Veo 3.1 Fast for iterations; use the closest Veo 3 Quality option if the UI still labels it Veo 3. |
| Clip mode | Text to Video for abstract/explanatory scenes; Ingredients or Frames when using the logo, banner, or workbench reference. |
| Aspect ratio | 16:9 landscape for HackQuest, GitHub Pages, LinkedIn, and YouTube. |
| Length | Generate in 8-second clips, then assemble. Use Extend only after a clip is strong. |
| Outputs | 2 per prompt for final contenders; 1 per prompt for rough iteration. |
| Resolution | Upscale final selected clips to 1080p or 4K if Flow exposes the option. |
| Audio | Generate only restrained ambience and verification sounds in Flow. Use a separate human or premium TTS narration track for the final voiceover. |
| Captions | Do not add captions to generated clips. Use narration plus real product screen capture for exact repo/API wording. |

Ingredients to upload:

| Ingredient name | File | How to use |
| --- | --- | --- |
| `@0guard-logo` | `docs/hackathon-0g/assets/0guard-logo.png` | Style reference only. Prefer symbol, silhouette, color, and composition; do not ask Veo to recreate text. |
| `@0guard-banner-style` | `docs/hackathon-0g/assets/0guard-x-banner.png` | Visual style reference only. Do not ask Veo to reproduce any lettering. |
| `@0guard-workbench` | `docs/hackathon-0g/assets/0guard-workbench-provenance.png` | UI composition reference only. Use real screen capture for readable UI. |

If Flow rejects or distorts an ingredient, create a clean reference image in
Flow first: dark background, single object, no extra subjects, no text, no
third-party logos.

## Editorial Spine

Target length: 95 to 115 seconds.

Audience: a smart hackathon judge or normie founder who understands crypto risk
but does not want a wall of jargon.

Structure:

1. The human problem: an AI agent is about to ask a wallet to sign.
2. The simple model: agent intent enters 0guard before the signer is touched.
3. The product proof: allow, review, deny, and no-sign flags on real UI.
4. The data proof: 28 April 2026 incidents, source-linked and hashed.
5. The 0G proof: read-only status, deterministic receipt hash, public mainnet
   anchor.
6. The expansion story: Telegram/Mira, TON preview, EVM/x402/Lighter/bridge
   guardrails stay checkpoint-first and no-send/no-trade by default.
7. The close: autonomous finance needs a checkpoint before the wallet.

## Global No-Text Rule

Paste this before every Flow prompt:

```text
No text anywhere in this generated clip. No captions, subtitles, lower thirds,
labels, title cards, brand lettering, API paths, wallet addresses, transaction
hashes, article snippets, terminal text, chat messages, UI words, numbers, QR
codes, or decorative marks that resemble writing. Communicate only through
motion, color, shapes, spacing, light, and camera language. Exact information
will be delivered by narration and real product screen capture outside this
generated clip.
```

## Global Visual Style Prompt

Paste this into every prompt, then append the scene-specific block.

```text
Visual style: professional cypherpunk security film, clean dark interface,
matte black glass, restrained cyan and electric green proof lines, subtle red
only for denied risk, realistic product-light reflections, high-end documentary
macro cinematography, slow deliberate camera movement, no fantasy hacker
stereotypes, no random crypto coins, no stock market charts, no fake wallet
transactions, no bridges or swaps executing, no generated text, no generated
logos, no third-party logos, no private keys, no seed phrases, no real personal
data.

Audio direction: restrained low pulse, quiet room tone, soft verification
chimes, no dramatic trailer boom, no robotic narration inside the generated
clip unless explicitly requested.
```

Global negative prompt:

```text
Avoid: fake exchange screens, fake signatures, fake wallet approvals,
fake token prices, fake news article screenshots, scrolling gibberish text,
captions, subtitles, lower thirds, labels, title cards, fake UI words, numbers,
API paths, wallet addresses, transaction hashes, QR codes, blue-purple gradient
blob backgrounds, cartoon robots, hooded hackers, explosion effects, meme
crypto visuals, busy dashboards, hallucinated brand logos, visible seed
phrases, private keys, phone numbers, emails, or real user account screens.
```

## Master Prompt

Use this for a single hero trailer pass if you want Flow to draft the overall
look before generating individual scenes.

```text
Create a cinematic 16:9 product-demo opening for 0guard, a pre-wallet firewall
for AI agents built on 0G. The story is simple: an autonomous agent prepares a
wallet action, the action passes through a calm security checkpoint, and only
safe read-only actions continue. Risky signing attempts become red quarantined
packets before the wallet is ever asked. Show a dark professional interface
with abstract agent intent packets, policy receipt objects, source-linked
evidence shapes, and a public proof ledger. Do not include any text, symbols
that look like text, captions, labels, addresses, hashes, or title cards. The
mood is elite defensive engineering, not trading hype.

Visual style: professional cypherpunk security film, clean dark interface,
matte black glass, restrained cyan and electric green proof lines, subtle red
only for denied risk, realistic product-light reflections, high-end documentary
macro cinematography, slow deliberate camera movement, no fantasy hacker
stereotypes, no random crypto coins, no stock market charts, no fake wallet
transactions, no bridges or swaps executing, no generated text, no generated
logos, no third-party logos, no private keys, no seed phrases, no real personal
data.

Audio: restrained low pulse, quiet room tone, soft verification chimes.
```

## Scene Prompts

Generate each scene as an 8-second clip. Save the best frame from each approved
clip so later clips can use Frames to Video for cleaner transitions.

### Scene 1: The Moment Before Signing

Use: Text to Video, Veo 3.1 Quality, 16:9, 2 outputs.

```text
An AI agent intent packet travels through a quiet dark workspace toward a
sealed wallet signing vault. Just before it reaches the vault, a precise
security checkpoint lights up and pauses the packet. The vault never opens.
The camera moves slowly from the agent side to the checkpoint side, macro lens,
crisp dark glass, cyan proof lines, one subtle red warning glint. No text of
any kind. No wallet brand. No transaction confirmation. No fake address.

Visual style: professional cypherpunk security film, clean dark interface,
matte black glass, restrained cyan and electric green proof lines, subtle red
only for denied risk, realistic product-light reflections.

Audio: low room tone, soft digital pause, no voice.
```

Voiceover cue:

```text
Before the signer opens, 0guard checks the intent.
```

### Scene 2: The Simple Explanation

Use: Ingredients to Video if available with `@0guard-logo`; otherwise Text to
Video. Veo 3.1 Fast for draft, Quality for final.

```text
Three clean lanes appear in a dark interface: agent intent, 0guard checkpoint,
and protected wallet. A safe blue packet passes only after the checkpoint turns
green. A risky red packet is diverted into quarantine before touching the
wallet lane. The motion is simple enough for a non-technical viewer, elegant
and minimal, like a premium security product explainer. No text of any kind.
No captions, labels, title cards, brand lettering, or UI words.

Use @0guard-logo only as a shape, color, and lighting reference. Do not
generate brand lettering.

Visual style: professional cypherpunk security film, clean dark interface,
matte black glass, precise geometry, restrained cyan and electric green proof
lines, minimal red risk lane.

Audio: soft verification chime for safe packet, muted block tone for risky
packet, no voice.
```

Voiceover cue:

```text
Agent asks. 0guard checks. Wallet stays protected.
```

### Scene 3: Product Truth Cutaway

Use: real screen capture, not Veo.

Record the current app or use the existing builder. Show:

```text
/api/evaluate
decision: deny
walletNotAskedToSign: true
telegram_send: false
```

Use real product screen capture only. Do not generate this scene in Veo.

### Scene 4: Incident Intelligence Becomes Detectors

Use: Text to Video or Frames to Video from a clean data-card frame.

```text
A wall of public-source evidence cards becomes a clean provenance matrix. Each
card collapses into abstract source blocks and detector hints without text,
numbers, labels, article snippets, or real people. The camera glides across the
matrix as red exploit patterns become structured cyan detector signals. The
scene feels like an analyst room, not a news montage.

Visual style: professional cypherpunk security film, dark neutral data room,
sharp cards, restrained motion, no text of any kind, no news logos, no personal
data.

Audio: soft paper-to-digital sweep, low analysis pulse, no voice.
```

Voiceover cue:

```text
28 source-linked April 2026 incidents become detector coverage.
```

### Scene 5: Signature and Behavior Attack Types

Use: Text to Video, Veo 3.1 Quality.

```text
Four abstract attack signatures appear as separate suspended objects in a dark
security lab: social-engineering prompt lure, weak bridge verifier gate,
compromised admin upgrade path, and delegated account batch-call risk. Each
object is inspected by a thin cyan scan line, then stamped as review or deny.
No exploit instructions. No real code. No copied transaction calldata. The
visuals are elegant, readable through motion, and threat-model oriented.
Do not use any letters, labels, numbers, or stamped text.

Visual style: professional cypherpunk security film, matte black glass, precise
threat objects, cyan scan lines, red quarantine glow only at the edges.

Audio: four quiet scan ticks and one final proof chime.
```

Voiceover cue:

```text
0guard catches behavior, not just known bad addresses.
```

### Scene 6: The 0G Receipt Anchor

Use: Frames to Video if you can start from a simple receipt-card image; else
Text to Video.

```text
A deterministic receipt hash becomes a tamper-evident proof object and locks
into a transparent 0G mainnet ledger grid. The action communicates auditability
only: no token transfer, no wallet approval, no price chart. The camera starts
close on the receipt object, then pulls back to reveal a calm decentralized
proof layer. Do not show the contract address, transaction hash, receipt hash,
numbers, labels, title cards, or any generated text. Exact proof details belong
in narration and real product screen capture.

Visual style: professional cypherpunk security film, premium dark ledger,
transparent chain grid, cyan proof lines, small green verification pulse.

Audio: quiet mechanical lock, short verification tone, no voice.
```

Voiceover cue:

```text
Public 0G mainnet anchor: 0xBaC59b...7182abc
```

### Scene 7: Reputation Shadow Cache

Use: Text to Video, Veo 3.1 Quality.

```text
Three external intelligence streams enter a privacy-preserving normalization
layer. Raw payloads are filtered out, and only abstract derived evidence blocks
and risk signals continue into the 0guard checkpoint. The camera shows the raw
layer dimming while the derived analysis layer becomes crisp and usable.
No vendor logos. No copied source text. No labels, words, numbers, hashes, or
personal data.

Visual style: professional cypherpunk security film, clean data pipelines,
dark glass, cyan normalization gates, clean geometry, no text.

Audio: low data hum, three clean normalization clicks, no voice.
```

Voiceover cue:

```text
Source-aware intelligence without raw payload resale.
```

### Scene 8: Telegram Mini App Without Spam

Use: real screen capture for readable UI, optional Veo background only.

Record:

```text
/telegram
/api/telegram/miniapp/preview
telegram_send=false
qualityGate=...
```

Optional Veo background prompt:

```text
A phone-shaped dark glass frame shows abstract wallet-alert cards arriving
only after a quality gate approves them. Most low-value alerts fade away before
reaching the phone. No real Telegram interface, no chat usernames, no message
spam, no text of any kind. The mood is calm, protective, and respectful of user
attention.

Visual style: professional cypherpunk security film, restrained mobile UI,
cyan quality gates, minimal red risk chips, no real app logos.
```

Voiceover cue:

```text
Telegram preview is opt-in, deduped, and no-send by default.
```

### Scene 9: Cross-Chain Checkpoint, Not Bridge Hype

Use: Text to Video, Veo 3.1 Quality.

```text
Several abstract network lanes connect to one central 0guard checkpoint:
0G-native proof lane, EVM intent lane, x402 payment-intent lane, Lighter
order-intent lane, TON wallet context lane, and bridge-protocol risk lane. The
checkpoint evaluates each lane without executing any bridge, trade, payment,
or transfer. The visual language is native checkpointing, not wrapped-asset
bridge hype.
Do not label the lanes with words, symbols, tickers, or logos.

Visual style: professional cypherpunk security film, dark topological network,
clean white/cyan proof routes, no token logos, no price charts, no transfer
animation, no buy or sell buttons.

Audio: restrained network hum and one clean lock tone.
```

Voiceover cue:

```text
Cross-chain expansion stays read-only and checkpoint-first.
```

### Scene 10: Final Hero

Use: Ingredients to Video with `@0guard-logo` and `@0guard-banner-style` if
available. Otherwise use Text to Video and overlay the real logo in edit.

```text
Final hero shot for 0guard. A calm operator surface shows allow, review, and
deny lanes flowing into a tamper-evident 0G proof layer. The protected wallet
remains behind the checkpoint. The scene feels like serious infrastructure for
autonomous finance, not a trading app. Leave clean negative space in the center
for a real logo asset outside Flow if needed. No generated text, no labels, no
title card.

Visual style: professional cypherpunk security film, clean dark interface,
matte black glass, restrained cyan and electric green proof lines, subtle red
deny lane, sharp premium lighting.

Audio: confident low swell ending in a precise proof-confirmation tone.
```

Voiceover cue:

```text
0guard: pre-wallet proof for autonomous finance.
```

## Voiceover Script

Use a recorded Ari voiceover if possible. If using TTS, use a warm natural
voice, no exaggerated trailer pacing, no long pauses, and no over-pronounced
crypto terms. Target 145 to 160 spoken words per minute.

```text
An AI agent can move faster than a human can think. That is useful, until the
agent asks your wallet for the wrong signature.

0guard sits in the moment before signing. The agent sends an intent. 0guard
checks the prompt context, calldata, policy, known exploit behavior, and source
linked incident intelligence. Safe read-only actions can continue. Risky wallet
actions are denied before the signer is ever asked.

The demo is intentionally conservative. No private key in the browser. No
signing. No broadcast. No bridge. No trade. No Telegram send.

The proof is the important part. 0guard maps twenty-eight public April 2026
incidents into detector coverage, builds deterministic receipt hashes, prepares
Storage-ready evidence roots, and anchors one deny receipt on 0G mainnet so the
verdict is inspectable outside the demo.

From there, the same checkpoint can protect Telegram wallet alerts, TON wallet
context, EVM agents, x402 payment intents, Lighter order intents, and bridge
protocol risk. The point is not to force everything through a bridge. The point
is to add a native safety checkpoint before autonomous systems touch money.

That is 0guard: agent intent in, policy proof out, wallet protected.
```

## Final Edit Recipe

1. Generate Scenes 1, 2, 4, 5, 6, 7, 9, and 10 in Flow.
2. Record real product footage for Scenes 3 and 8, plus any proof readback
   shots from the browser.
3. Put the voiceover down first. Cut visuals to the voice, not the reverse.
4. Use Veo scenes as 2 to 5 second inserts between real UI proof shots.
5. Do not add captions, subtitles, lower thirds, title cards, or decorative
   text to generated clips. Exact claims should appear only through narration
   and real product screen capture.
6. Keep real product UI proof shots on screen long enough to inspect when they
   are used.
7. Mix voice around -16 LUFS integrated, with music/ambience at least 12 dB
   below narration.
8. Export:
   - `1920x1080`, H.264, high profile, 20 to 30 Mbps.
   - AAC audio, 48 kHz, 320 kbps.
   - Length under 2:00 for the polished public cut.
9. Replace the public MP4 only after review confirms:
   - no fake live external actions;
   - no generated text appears anywhere in Veo/Flow clips;
   - product UI is real screen capture when readable text appears;
   - 0G proof details match `docs/hackathon-0g/mainnet-proof.json`;
   - no private data or account screens appear.

## Quality Bar

Reject a generated clip if any of these appear:

- any generated text, caption, subtitle, lower third, title card, label, number,
  address, hash, QR code, or fake UI typography;
- any fake token balance, fake wallet approval, fake tx success, or fake bridge;
- visible private key, seed phrase, QR code, phone number, email, or account
  profile;
- real third-party logo that was not intentionally licensed or referenced;
- noisy one-note purple/blue gradient background;
- generic hooded-hacker or trading-hype imagery;
- a clip that makes 0guard look like it executes money movement.

Approve a generated clip only if it helps a viewer understand one honest part
of the product: pre-wallet gating, source-linked intelligence, 0G proof,
no-send Telegram previews, or read-only cross-chain checkpointing.
