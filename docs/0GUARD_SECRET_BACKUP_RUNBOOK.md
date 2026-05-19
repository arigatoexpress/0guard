# 0guard Secret Backup Runbook

Updated: May 17, 2026.

This repo can prepare a backup workflow, but Codex must not read, print, copy,
or archive private keys unattended. The safe operator path is an encrypted,
passphrase-protected archive created from a trusted local shell.

## Current Secret Root

Local secret files live under:

```text
/Users/aribs/.0guard-secrets
```

Observed posture:

- wallet and relay private files are mode `600`;
- helper scripts are mode `700`;
- Proton Drive is mounted at
  `/Users/aribs/Library/CloudStorage/ProtonDrive-aribspector@proton.me-folder`;
- the dedicated destination folder is
  `Sapphire-OS/0guard-mainnet-deployer`.

## Preview Without Reading Secrets

```bash
./scripts/secure_0guard_secret_backup.sh
```

Dry-run mode lists source filenames and the destination archive path. It does
not archive or hash secret contents.

## Create The Encrypted Backup

Run this only from a trusted local shell:

```bash
./scripts/secure_0guard_secret_backup.sh --apply
```

The script:

- requires `age`;
- prompts for a passphrase with `age -p`;
- creates a temporary tarball with a manifest;
- writes `0guard-secrets-<timestamp>.tar.gz.age` to Proton Drive;
- sets the encrypted archive to mode `600`;
- deletes the temporary plaintext archive.

Do not store the passphrase in this repo, in shell history, or beside the
archive. Keep one offline recovery copy of the passphrase.

## What Codex Can And Cannot Do

Codex can maintain the script, verify file permissions and destination paths,
and confirm that no plaintext secret backup is present. Codex should not run
`--apply`, inspect private-key contents, or move funds.
