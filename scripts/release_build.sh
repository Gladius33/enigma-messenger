#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
export CARGO_TERM_COLOR=always

cd "$ROOT"

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --locked
cargo test --locked --all-features
cargo build --locked --release --workspace

mkdir -p "$ROOT/dist"
cp "$ROOT/target/release/enigma-daemon" "$ROOT/dist/enigma-daemon"
cp "$ROOT/target/release/enigma-cli" "$ROOT/dist/enigma-cli"

cargo build --locked --release --workspace --all-features

GIT_COMMIT="$(git rev-parse HEAD)"
GIT_TAG="$(git describe --tags --abbrev=0 2>/dev/null || echo "untagged")"
RUSTC_VERSION="$(rustc -V)"
CARGO_VERSION="$(cargo -V)"
TARGET_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
TIMESTAMP_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
FEATURES="default"

cat > "$ROOT/dist/BUILDINFO.json" <<EOF
{
  "git_commit": "$GIT_COMMIT",
  "git_tag": "$GIT_TAG",
  "rustc": "$RUSTC_VERSION",
  "cargo": "$CARGO_VERSION",
  "target": "$TARGET_TRIPLE",
  "timestamp_utc": "$TIMESTAMP_UTC",
  "enabled_features": ["$FEATURES"]
}
EOF

(cd "$ROOT/dist" && sha256sum enigma-daemon enigma-cli BUILDINFO.json > SHA256SUMS)
