# 0guard Veo 3 / Flow Production Packet

Updated: May 16, 2026. No generated-video text allowed.

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
  route for subtitles, mix, and precise product overlays.
- For 0guard, do not rely on generated text inside Veo clips. Add exact text,
  API routes, receipt hashes, and captions in the editor from real repo data.

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
| Captions | Add in the editor, not inside Veo. Use exact repo/API wording. |

Ingredients to upload:

| Ingredient name | File | How to use |
| --- | --- | --- |
| `@0guard-logo` | `docs/hackathon-0g/assets/0guard-logo.png` | Brand reference for final hero and intro. |
| `@0guard-banner-style` | `docs/hackathon-0g/assets/0guard-x-banner.png` | Visual style reference only. Do not ask Veo to reproduce all text. |
| `@0guard-workbench` | `docs/hackathon-0g/assets/0guard-workbench-provenance.png` | UI composition reference. Use real screen capture for readable UI. |

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

## Global Visual Style Prompt

Paste this into every prompt, then append the scene-specific block.

```text
Visual style: professional cypherpunk security film, clean dark interface,
matte black glass, crisp white typography added later in edit, restrained cyan
and electric green proof lines, subtle red only for denied risk, realistic
product-light reflections, high-end documentary macro cinematography, slow
deliberate camera movement, no fantasy hacker stereotypes, no random crypto
coins, no stock market charts, no fake wallet transactions, no bridges or swaps
executing, no unreadable AI-generated UI text, no third-party logos, no private
keys, no seed phrases, no real personal data.

Audio direction: restrained low pulse, quiet room tone, soft verification
chimes, no dramatic trailer boom, no robotic narration inside the generated
clip unless explicitly requested.
```

Global negative prompt:

```text
Avoid: fake exchange screens, fake signatures, fake wallet approvals,
fake token prices, fake news article screenshots, scrolling gibberish text,
blue-purple gradient blob backgrounds, cartoon robots, hooded hackers,
explosion effects, meme crypto visuals, busy dashboards, hallucinated brand
logos, visible seed phrases, private keys, QR codes, phone numbers, emails, or
real user account screens.
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
with abstract agent intent packets, policy receipts, source-linked evidence
cards, and a public proof ledger. Keep all text abstract; exact captions will
be added later. The mood is elite defensive engineering, not trading hype.

Visual style: professional cypherpunk security film, clean dark interface,
matte black glass, crisp white typography added later in edit, restrained cyan
and electric green proof lines, subtle red only for denied risk, realistic
product-light reflections, high-end documentary macro cinematography, slow
deliberate camera movement, no fantasy hacker stereotypes, no random crypto
coins, no stock market charts, no fake wallet transactions, no bridges or swaps
executing, no unreadable AI-generated UI text, no third-party logos, no private
keys, no seed phrases, no real personal data.

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
crisp dark glass, cyan proof lines, one subtle red warning glint. No readable
text. No wallet brand. No transaction confirmation. No fake address.

Visual style: professional cypherpunk security film, clean dark interface,
matte black glass, restrained cyan and electric green proof lines, subtle red
only for denied risk, realistic product-light reflections.

Audio: low room tone, soft digital pause, no voice.
```

Editor caption:

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
and minimal, like a premium security product explainer. No readable text;
captions will be added later.

Use @0guard-logo only as a small brand mark style reference, not as large
generated text.

Visual style: professional cypherpunk security film, clean dark interface,
matte black glass, precise geometry, restrained cyan and electric green proof
lines, minimal red risk lane.

Audio: soft verification chime for safe packet, muted block tone for risky
packet, no voice.
```

Editor caption:

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

Keep readable text from the product. Do not generate this scene in Veo.

### Scene 4: Incident Intelligence Becomes Detectors

Use: Text to Video or Frames to Video from a clean data-card frame.

```text
A wall of public-source evidence cards becomes a clean provenance matrix. Each
card collapses into a source id, a record hash, and a detector hint. The cards
do not show copied article text or real people. The camera glides across the
matrix as red exploit patterns become structured white and cyan detector
signals. The scene feels like an analyst room, not a news montage.

Visual style: professional cypherpunk security film, dark neutral data room,
sharp cards, source-aware hashes, restrained motion, no readable copied text,
no news logos, no personal data.

Audio: soft paper-to-digital sweep, low analysis pulse, no voice.
```

Editor caption:

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

Visual style: professional cypherpunk security film, matte black glass, precise
threat objects, cyan scan lines, red quarantine glow only at the edges.

Audio: four quiet scan ticks and one final proof chime.
```

Editor caption:

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
proof layer. Keep all text abstract; exact contract address and tx hash will
be overlaid in edit from real repo proof data.

Visual style: professional cypherpunk security film, premium dark ledger,
transparent chain grid, cyan proof lines, small green verification pulse.

Audio: quiet mechanical lock, short verification tone, no voice.
```

Editor caption:

```text
Public 0G mainnet anchor: 0xBaC59b...7182abc
```

### Scene 7: Reputation Shadow Cache

Use: Text to Video, Veo 3.1 Quality.

```text
Three external intelligence streams enter a privacy-preserving normalization
layer. Raw payloads are filtered out, and only derived evidence, hashes, source
ids, and risk signals continue into the 0guard checkpoint. The camera shows the
raw layer dimming while the derived analysis layer becomes crisp and usable.
No vendor logos. No copied source text. No personal data.

Visual style: professional cypherpunk security film, clean data pipelines,
dark glass, cyan normalization gates, white source-id glyphs added later.

Audio: low data hum, three clean normalization clicks, no voice.
```

Editor caption:

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
spam, no readable text. The mood is calm, protective, and respectful of user
attention.

Visual style: professional cypherpunk security film, restrained mobile UI,
cyan quality gates, minimal red risk chips, no real app logos.
```

Editor caption:

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

Visual style: professional cypherpunk security film, dark topological network,
clean white/cyan proof routes, no token logos, no price charts, no transfer
animation, no buy or sell buttons.

Audio: restrained network hum and one clean lock tone.
```

Editor caption:

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
for a real 0guard logo overlay in editing. No generated text.

Visual style: professional cypherpunk security film, clean dark interface,
matte black glass, restrained cyan and electric green proof lines, subtle red
deny lane, sharp premium lighting.

Audio: confident low swell ending in a precise proof-confirmation tone.
```

Editor caption:

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
5. Add captions in the editor with exact repo terms:
   - `walletNotAskedToSign: true`
   - `/api/reputation/shadow-cache`
   - `/api/readyz`
   - `0G mainnet PolicyReceiptAnchor`
   - `telegram_send=false`
   - `rawPayloadsReturned=false`
6. Keep all readable product claims on screen for at least 1.5 seconds.
7. Mix voice around -16 LUFS integrated, with music/ambience at least 12 dB
   below narration.
8. Export:
   - `1920x1080`, H.264, high profile, 20 to 30 Mbps.
   - AAC audio, 48 kHz, 320 kbps.
   - Length under 2:00 for the polished public cut.
9. Replace the public MP4 only after review confirms:
   - no fake live external actions;
   - no generated gibberish text in critical shots;
   - product UI is readable;
   - 0G proof details match `docs/hackathon-0g/mainnet-proof.json`;
   - no private data or account screens appear.

## Quality Bar

Reject a generated clip if any of these appear:

- unreadable AI text where exact claims matter;
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
