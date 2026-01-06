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
cargo build --locked --release --workspace --all-features
TARGET="${TARGET:-x86_64-unknown-linux-musl}"
cargo build --locked --release --workspace --target "$TARGET"
cargo build --locked --release --workspace --all-features --target "$TARGET"

mkdir -p "$ROOT/dist"
cp "$ROOT/target/$TARGET/release/enigma-daemon" "$ROOT/dist/enigma-daemon-$TARGET"
cp "$ROOT/target/$TARGET/release/enigma-cli" "$ROOT/dist/enigma-cli-$TARGET"

GIT_COMMIT="$(git rev-parse HEAD)"
GIT_TAG="$(git describe --tags --abbrev=0 2>/dev/null || echo "untagged")"
RUSTC_VERSION="$(rustc -V)"
CARGO_VERSION="$(cargo -V)"
TARGET_TRIPLE="$TARGET"
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

(cd "$ROOT/dist" && sha256sum "enigma-daemon-$TARGET" "enigma-cli-$TARGET" BUILDINFO.json > SHA256SUMS)
