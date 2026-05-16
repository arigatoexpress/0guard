# 0guard Final Demo Video Script

Final generated length: 2:24.1.

Submission rule: HackQuest requires a public demo video of no more than three
minutes that shows product functionality, user flow, and actual 0G component
usage. This cut is a real product walkthrough, not a slide deck.

Generated asset:

```text
https://arigatoexpress.github.io/0guard/hackathon-0g/assets/0guard-hackquest-demo-final.mp4
```

Professional replacement packet:

```text
docs/hackathon-0g/veo3-flow-production-prompt.md
```

Text rule for any replacement cut:

```text
Generated Veo/Flow clips must contain no text at all. Use narration and real
product screen capture for exact claims, API paths, hashes, addresses, and
status fields. Do not rely on AI-generated captions, labels, title cards, or
UI typography.
```

Rebuild command:

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/build_hackquest_demo_video.py
```

## Core Story

0guard is a pre-wallet firewall for AI agents. In plain terms: an agent asks,
0guard checks, and the wallet stays protected. Safe read-only simulations can
continue. Risky live wallet actions are denied before the signer ever sees a
transaction.

The technical proof is shown after the simple explanation: real April 2026
incident data, deterministic receipt hashes, Storage-ready roots, a public 0G
mainnet receipt anchor, source-aware provenance, and the current signature map.

## Final Timeline

| Time | Narration | Visual |
| --- | --- | --- |
| 0:00-0:15 | "I built 0guard for one very specific moment: an AI agent is about to ask your wallet for a signature. Before the signer opens, 0guard reads the intent, the calldata, and the policy context." | Open with the new launch-banner intro over the real workbench, then reveal the product UI. |
| 0:15-0:25 | "For a normal user, the model is simple. The agent asks, 0guard checks, and the wallet stays out of it until the request earns a clean verdict." | Show the agent, 0guard, wallet, and receipt flow with the new non-overlapping story canvas. |
| 0:25-0:36 | "Here the agent is being nudged to pre-sign an admin transfer. That is the kind of social engineering that looks harmless in a chat window, but becomes dangerous at the wallet." | Run the social-engineering scenario. Show the packet stopping at 0guard and the wallet reading `not asked to sign`. |
| 0:36-0:47 | "Now the request changes to a bridge release through a weak verifier setup. 0guard catches the shortcut before a cross-chain mistake can become a real transaction." | Run the bridge release scenario. Show the red blocker chips and deny verdict. |
| 0:47-0:58 | "Then we test a compromised admin path trying to upgrade a contract. The system does not have to guess. It sees the risky sequence and blocks the signer step." | Run the upgrade scenario. Keep the visual deny path centered. |
| 0:58-1:08 | "Good requests still work. A read-only simulation does not move funds, does not need a signature, and should keep moving without creating noise for the operator." | Run the safe simulation scenario. Show the allow state and `simulation only` wallet label. |
| 1:08-1:21 | "That is the simple story. The proof layer is where 0guard gets serious: 28 public April 2026 incidents, source-linked, hashed, and turned into detector coverage." | Click `Load data summary`. Show the incident summary and source list. |
| 1:21-1:31 | "Every verdict can become a receipt hash. In this browser workbench, there is still no private key, no signing, no broadcast, and no money movement." | Show the 0G read-only status and safety flags. |
| 1:31-1:42 | "For this submission, one deny receipt is already anchored on 0G mainnet. That gives judges a public receipt path instead of just a local screen recording." | Show the PolicyReceiptAnchor proof data from `docs/hackathon-0g/mainnet-proof.json`. |
| 1:42-1:53 | "0guard also prepares Storage-ready roots and a provenance matrix. The important part is that every incident stays traceable, while raw upstream payloads stay out of resale." | Show provenance coverage, source matches, and raw-payload safety. |
| 1:53-2:05 | "The detector map is measurable. It now covers all 28 incident-derived patterns, including the Quant EIP-7702 batch-call evidence that closed the last gap." | Click `Load signature map`. Show `matchedCount=28`, `gapCount=0`, and the Quant EIP-7702 detector row. |
| 2:05-2:16 | "For external systems, 0guard is a checkpoint, not a launch button. Base and Virtuals, x402, EVM networks, Celestia, Lighter order intents, and bridge protocols stay read-only here." | Show the read-only cross-chain catalog. |
| 2:16-2:24 | "That is the thesis: autonomous finance needs a clear checkpoint before the wallet, and proof people can inspect. That is 0guard, built on 0G." | End on the cross-chain/read-only guardrail surface and a clean visual lockup; no generated text overlays. |

## Exact Demo Scenarios

The reproducible builder calls the browser-only story runner for four scenarios:

```text
drift   - durable-nonce social-engineering admin transfer
bridge  - LayerZero-style bridge release with weak verifier risk
upgrade - proxy upgrade request from a compromised admin path
safe    - read-only simulation using eth_call with no signature
```

It then drives the real workbench controls for:

```text
/api/data/summary
/api/0g/status
/api/evaluate with enable_0g_anchor and enable_0g_storage
docs/hackathon-0g/mainnet-proof.json readback
/api/data/provenance
/api/data/signature-map
/api/integrations/cross-chain
```

Mainnet proof links:

```text
docs/hackathon-0g/mainnet-proof.json
https://chainscan.0g.ai/address/0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc
https://chainscan.0g.ai/tx/64ff260ccd02aa69fc18d5727eb4530d8774003bc7df63ec7d5cda036fc438ed
```

## Audio Notes

The builder prefers a neural `edge-tts` voice when available, then falls back to
macOS `say`. It also accepts a finished voiceover through
`DEMO_NARRATION_AUDIO=/path/to/voiceover.wav`, which lets a manually recorded or
OpenAI/ElevenLabs export replace the generated narration without changing the
screen recording.

Current default local voice settings:

```text
DEMO_TTS_ENGINE=auto
DEMO_EDGE_TTS_VOICE=en-US-BrianMultilingualNeural
DEMO_EDGE_TTS_RATE=-2%
DEMO_EDGE_TTS_PITCH=-1Hz
```

The final audio path still uses segmented narration, short controlled pauses,
high-pass and low-pass filtering, compression, light presence EQ, loudness
normalization, and fade-in/fade-out padding. This avoids the old abrupt stop and
reduces the strange pauses from one large text-to-speech paragraph.

Objective checks from the final MP4 after rebuild:

```text
video: 1920x1080, 25 fps, 144.08 seconds
audio: AAC mono, 144.09 seconds, 176 kb/s
silence check: no internal >1.0 second silence detected at -35 dB threshold
```

## Safety Notes

- The demo performs no signing, transaction broadcast, bridge, swap, Lighter
  order, exchange account action, Telegram send, or X post from the browser.
- 0G status is read-only.
- The anchored receipt is shown as public proof; the workbench remains
  simulation-first and explicit-confirmation-only for any live external action.
