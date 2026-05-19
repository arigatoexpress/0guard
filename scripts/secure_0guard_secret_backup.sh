#!/usr/bin/env bash
set -euo pipefail

# Create an encrypted Proton Drive backup of local 0guard secrets.
#
# Default mode is dry-run and does not read secret file contents. Pass --apply
# to build the archive. The --apply path prompts for an age passphrase and
# removes the temporary plaintext archive before exiting.

SOURCE_DIR="${SOURCE_DIR:-/Users/aribs/.0guard-secrets}"
PROTON_DIR="${PROTON_DIR:-/Users/aribs/Library/CloudStorage/ProtonDrive-aribspector@proton.me-folder/Sapphire-OS/0guard-mainnet-deployer}"
APPLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --apply)
      APPLY=1
      shift
      ;;
    --source-dir)
      SOURCE_DIR="$2"
      shift 2
      ;;
    --proton-dir)
      PROTON_DIR="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! -d "$SOURCE_DIR" ]]; then
  echo "Missing source secret directory: $SOURCE_DIR" >&2
  exit 1
fi

case "$PROTON_DIR" in
  */Library/CloudStorage/ProtonDrive-*/Sapphire-OS/*) ;;
  *)
    echo "Refusing destination outside expected Proton Drive Sapphire-OS folder: $PROTON_DIR" >&2
    exit 1
    ;;
esac

if ! command -v age >/dev/null 2>&1; then
  echo "age is required for encryption." >&2
  exit 1
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
archive_name="0guard-secrets-${timestamp}.tar.gz.age"
destination="${PROTON_DIR}/${archive_name}"

echo "0guard secret backup plan"
echo "source=$SOURCE_DIR"
echo "destination=$destination"
find "$SOURCE_DIR" -type f -print | sed "s#^${SOURCE_DIR}/#- #"

if [[ "$APPLY" -ne 1 ]]; then
  echo "dry_run=true"
  echo "Run with --apply to create the encrypted archive."
  exit 0
fi

umask 077
mkdir -p "$PROTON_DIR"
workdir="$(mktemp -d)"
cleanup() {
  rm -rf "$workdir"
}
trap cleanup EXIT

manifest="${workdir}/manifest.txt"
(
  echo "created_utc=$timestamp"
  echo "source=$SOURCE_DIR"
  echo "host=$(hostname)"
  echo "files="
  find "$SOURCE_DIR" -type f -print0 |
    while IFS= read -r -d '' file; do
      mode="$(stat -f '%Lp' "$file")"
      size="$(stat -f '%z' "$file")"
      digest="$(shasum -a 256 "$file" | awk '{print $1}')"
      rel="${file#"$SOURCE_DIR"/}"
      printf '%s mode=%s size=%s sha256=%s\n' "$rel" "$mode" "$size" "$digest"
    done
) >"$manifest"

plain_archive="${workdir}/0guard-secrets-${timestamp}.tar.gz"
tar -C "$(dirname "$SOURCE_DIR")" \
  --exclude='.DS_Store' \
  -czf "$plain_archive" "$(basename "$SOURCE_DIR")" -C "$workdir" manifest.txt

age -p -o "$destination" "$plain_archive"
chmod 600 "$destination"
rm -f "$plain_archive"

echo "encrypted_archive=$destination"
echo "plaintext_removed=true"
