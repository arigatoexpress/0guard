# RV 0G Storage Soak Operations

Updated: May 19, 2026.

This runbook connects the live RV Windows storage node to ZeroGuard without
turning the workbench into a signer, wallet, Telegram sender, or node-control
panel.

## Current Operating Shape

| Surface | Role |
| --- | --- |
| Windows host | Runs the 0G mainnet storage node inside WSL. |
| FRP relay | Publishes storage P2P on `35.254.123.37:1234`. |
| ZeroGuard collector | Reads process/task/RPC/balance state over SSH and public RPC. |
| ZeroGuard workbench | Displays the latest local snapshot and blocks funding expansion. |

## Refresh The Local Snapshot

From the repo root:

```bash
./scripts/rv_0g_storage_soak_snapshot.py --out content/rv_0g_storage_soak.local.json
```

The output file is intentionally ignored by git. It can contain public wallet
addresses, balances, task names, block heights, and relay health, but it must
never contain private keys, mnemonics, API tokens, or Telegram send capability.

## Read It Through The Workbench

```bash
curl 'http://127.0.0.1:8109/api/0g/storage-node/status?snapshot=1'
```

The browser button is **0G Node Ops -> Storage soak**. It reads the same route
and shows:

- `funded_soak_syncing` while sync-gap blockers remain;
- `funded_soak_blocked` when the node is near-current but another expansion
  blocker, such as peer depth, is still present;
- `activeMinerBalanceOg` for the monitored miner public address;
- `onlyPriorTestFundingObserved`;
- `hundredOgTransferSent`;
- DB size, sync gap, relay state, connected peers, and expansion blockers.
- live shard config from `zgs_getShardConfig`, which is the actual storage
  responsibility the node has adopted from its DB.

## Peer Diagnostics

When sync is current but peer depth is low, refresh the redacted peer diagnostic
snapshot:

```bash
./scripts/rv_0g_peer_diagnostics.py --out content/rv_0g_peer_diagnostics.local.json
curl 'http://127.0.0.1:8109/api/0g/storage-node/peer-diagnostics?snapshot=1'
```

The current diagnostic posture is:

- `zgs_node v1.2.0` is running.
- Storage RPC is healthy on 0G mainnet with `connectedPeers=0`.
- Sync is effectively current; the last refreshed gap was `8` blocks.
- Live shard readback reports `shardId=0`, `numShard=1`. This means the node is
  currently responsible for the full storage range, even though the config file
  still contains the initial `shard_position = "0/2"` hint. Per 0G's docs, that
  config value only applies before the DB stores a shard config.
- Local TCP and UDP `1234` are listening inside WSL.
- The GCP relay publishes storage TCP/UDP `1234`, and the DA reverse tunnel on
  `34000` is reachable again. On May 19, the remaining relay issue was a stale
  GCP firewall source range for FRP control port `7000`; adding the current
  home IP restored both public sockets.
- The redacted config exposes mainnet boot/libp2p nodes, `auto_sync_enabled`,
  and `shard_position = "0/2"`.
- Recent zgs logs repeatedly show `Finding peers ... num_new_peers=0`.
- No storage-node restart was performed during the May 19 relay fix.

That means the only remaining expansion blocker is shallow peer
discovery/availability. Public relay and DA tunnel blockers are cleared; larger
funding is still blocked until peer depth reaches the reviewed target.

## Public-Safe Readiness Proof

After refreshing the storage soak, peer diagnostics, and Pi mesh snapshots, an
operator can record a redacted proof artifact:

```bash
PYTHONPATH=src .venv/bin/python scripts/record_node_pi_readiness_proof.py \
  --operator-reviewed-public-safe
curl 'http://127.0.0.1:8109/api/0g/node-pi-readiness-proof'
```

The recorder only consumes existing local snapshot files and writes
`docs/hackathon-0g/node-pi-readiness-proof.json`. It does not SSH, probe the
LAN, restart services, read keys, sign, broadcast, move funds, or send
messages. If peer depth or Pi readiness is still blocked, the artifact remains
public-safe but reports `status=blocked` until the next reviewed green snapshot.

## Expansion Blockers

Do not send larger mainnet funds until these are clear:

- `storage_log_sync_gap_too_large`
- `connected_peers_below_target_8`
- `public_storage_tcp_relay_unreachable`
- `adjacent_da_relay_task_not_running`
- any balance result other than the prior `0.25 0G` test amount on the active
  miner

The DA relay blocker is tracked separately because it gates the future DA lane,
not the storage node's current P2P relay on `1234`.

## 25 0G Funding Review

Do not top up the active miner while `connected_peers_below_target_8` remains.
The reviewed recipient for future storage-node expansion is the active miner
public address reported by the snapshot:

```text
0xf5c1c3eb88c262adb451c1ce3b1c391f7d968ecd
```

The current recommended action remains `continue_soak_no_additional_funding`.
When peer depth is green, prepare a final transaction manifest with exact
recipient, amount, source wallet, chain id `16661`, expected post-transfer
balances, and rollback/stop criteria before signing from the wallet UI.

## Safety Boundary

The collector is read-only. It does not read or return private key material,
does not sign, does not broadcast, does not transfer funds, and does not send
Telegram messages. Any Router deposit, miner top-up, validator action, staking,
delegation, or provider sub-account transfer still needs its own exact manifest
and final confirmation.
