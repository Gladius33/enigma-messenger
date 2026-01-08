#!/bin/sh
set -eu

fail() {
  echo "restore: $*" >&2
  exit 1
}

DATA_DIR="${ENIGMA_DATA_DIR:-/var/lib/enigma/daemon}"
BACKUP_PATH="${ENIGMA_BACKUP_PATH:-/var/backups/enigma/daemon-backup.tar.gz}"
CHECKSUM_PATH="${ENIGMA_CHECKSUM_PATH:-$BACKUP_PATH.sha256}"
OVERWRITE="${ENIGMA_RESTORE_OVERWRITE:-0}"
OWNER="${ENIGMA_OWNER:-enigma:enigma}"

command -v tar >/dev/null 2>&1 || fail "missing tar"
command -v sha256sum >/dev/null 2>&1 || fail "missing sha256sum"

[ -f "$BACKUP_PATH" ] || fail "backup not found: $BACKUP_PATH"

if [ -f "$CHECKSUM_PATH" ]; then
  sha256sum -c "$CHECKSUM_PATH" >/dev/null 2>&1 || fail "checksum mismatch"
fi

if [ -d "$DATA_DIR" ] && [ -n "$(ls -A "$DATA_DIR" 2>/dev/null)" ]; then
  if [ "$OVERWRITE" != "1" ]; then
    fail "data dir not empty: $DATA_DIR"
  fi
  rm -rf "$DATA_DIR"
fi

mkdir -p "$(dirname "$DATA_DIR")"
tar -xzf "$BACKUP_PATH" -C "$(dirname "$DATA_DIR")"

if [ -n "$OWNER" ]; then
  chown -R "$OWNER" "$DATA_DIR" || fail "chown failed"
fi

echo "restore: ok"
