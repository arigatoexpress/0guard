# ZeroGuard Peer Protection and Pi Mesh

Updated: 2026-05-17

## Thesis

ZeroGuard should protect the moment before an operator, agent, or node peer does
something risky. The live 0G storage node gives us real infrastructure truth; 0G
Private Computer gives us sealed AI explanations; Raspberry Pis give us cheap
edge sentinels. The product is not "we run a node and hope for rewards." The
product is "we turn node operation into a proof-backed safety layer for peers."

## What We Can Do Now

- Watch our funded 0G storage node for peer count, sync height, DB growth, and
  public relay reachability.
- Build peer-protection bulletins as drafts with hashes and source ids.
- Use 0GM-1.0 through 0G Private Computer once an API key and prompt-minimizing
  policy are configured.
- Use `rvpi-a` as a lightweight watcher and evidence cache. It is reachable at
  `rvpi-a.local` on Wi-Fi; `eth0` was still down before the Ethernet cable was
  connected.
- Keep `rvpi-b` as the paired cache/standby role once it is online.

## Safety Boundary

No automatic Telegram messages, email, blockchain messages, or fund movement
ship from the workbench. Peer outreach stays in `/api/peer/outreach-preview`
until all of these are true:

- the peer opted in or published a clear security contact;
- the exact message body is reviewed;
- the destination and channel are selected;
- a separate sender or CLI has explicit operator approval.

## 0G Private Computer Integration

The current 0G-native model lane is `0GM-1.0-35B-A3B`:

- OpenAI-compatible endpoint: `https://router-api.0g.ai/v1/chat/completions`
- Model id: `0GM-1.0-35B-A3B`
- Recommended production posture: `verify_tee=true`
- ZeroGuard role: explanation, compression, and draft review over deterministic
  ZeroGuard verdicts, never policy authority.

Sources:

- https://0g.ai/blog/0gm-1-0-35b-a3b
- https://pc.0g.ai/api-reference/0GM-1.0-35B-A3B
- https://0g.ai/blog/0g-private-computer

## Pi Roles

`rvpi-a` should run the sentinel loop first:

- probe Windows storage RPC and public relay;
- compare local node height to latest public 0G block;
- write a local heartbeat JSON file;
- dedupe repeated alerts before they become Telegram or bulletin drafts.

Staged path on `rvpi-a`:

- `~/zeroguard-pi-sentinel/pi_sentinel.py`
- `~/zeroguard-pi-sentinel/state/heartbeat.json`

`rvpi-b` should become the proof cache:

- mirror public-safe heartbeat JSON;
- keep receipt payload hashes and 0G Storage readback metadata;
- serve as the Ethernet-pair backup once cabled.

The Pis should not hold private keys, run validator duties, run a storage miner,
or attempt 35B model inference. Small local classifiers and JSON/hash work are
the right job for them.

## New Read-Only APIs

- `/api/0g/private-computer`
- `/api/0g/peer-protection`
- `/api/0g/pi-mesh`
- `/api/peer/outreach-preview`

These are designed as product surfaces first: they are useful to a dashboard,
Telegram digest preview, future CLI sender, or external operator portal without
opening live side effects.
