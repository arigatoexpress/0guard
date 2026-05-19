0guard post-submit update:

The HackQuest project still reads back as submitted, and the live production
service is now running a stronger source-intelligence layer.

What changed:

- Production revision: `guard0-miniapp-112c7b7`
- Source catalog: 34 rights-aware intelligence lanes
- Reputation connector manifest: 20 no-network connector candidates
- New disabled-by-default lanes: ThreatFox IOC API, Chainalysis sanctions
  API/Oracle, TRM Wallet Screening/BLOCKINT, MITRE Lazarus context, and Google
  Cloud Web Risk
- Hard boundary preserved: no raw feed resale, no hidden API keys, no live
  fetches until credentials, commercial-use terms, privacy, and retention rules
  are reviewed

The thesis is the same:

AI agents should not get to the wallet first.

0guard checks intent, calldata, domain/reputation context, exploit signatures,
and source-linked provenance before any signer prompt appears. The project is
not a wallet custodian, bridge, trading bot, or social automation bot. It is a
pre-wallet checkpoint with deterministic verdicts and 0G-verifiable receipt
proof.

Live proof hub:
https://arigatoexpress.github.io/0guard/hackathon-0g/

Live Mini App:
https://guard0-miniapp-s77j6bxyra-uc.a.run.app/telegram

Repo:
https://github.com/arigatoexpress/0guard

0G anchor proof:
https://chainscan.0g.ai/tx/0x64ff260ccd02aa69fc18d5727eb4530d8774003bc7df63ec7d5cda036fc438ed

#0GHackathon #BuildOn0G #Web3Security #AIagents #CryptoSecurity
