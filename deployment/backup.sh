#!/bin/sh
set -eu

umask 077

fail() {
  echo "backup: $*" >&2
  exit 1
}

DATA_DIR="${ENIGMA_DATA_DIR:-/var/lib/enigma/daemon}"
BACKUP_DIR="${ENIGMA_BACKUP_DIR:-/var/backups/enigma}"
BACKUP_NAME="${ENIGMA_BACKUP_NAME:-daemon-backup.tar.gz}"
BACKUP_PATH="${ENIGMA_BACKUP_PATH:-$BACKUP_DIR/$BACKUP_NAME}"
CHECKSUM_PATH="${ENIGMA_CHECKSUM_PATH:-$BACKUP_PATH.sha256}"
OVERWRITE="${ENIGMA_BACKUP_OVERWRITE:-0}"

command -v tar >/dev/null 2>&1 || fail "missing tar"
command -v sha256sum >/dev/null 2>&1 || fail "missing sha256sum"

[ -d "$DATA_DIR" ] || fail "data dir not found: $DATA_DIR"

mkdir -p "$BACKUP_DIR"

if [ -f "$BACKUP_PATH" ] && [ "$OVERWRITE" != "1" ]; then
  fail "backup exists: $BACKUP_PATH"
fi

base_dir=$(dirname "$DATA_DIR")
name=$(basename "$DATA_DIR")

tar -C "$base_dir" -czf "$BACKUP_PATH" "$name"
sha256sum "$BACKUP_PATH" > "$CHECKSUM_PATH"

echo "backup: ok"
echo "backup: $BACKUP_PATH"
echo "backup: $CHECKSUM_PATH"
