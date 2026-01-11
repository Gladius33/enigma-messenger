#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}"
export CARGO_TERM_COLOR=always

cd "$ROOT"

TARGET="${TARGET:-x86_64-unknown-linux-gnu}"
PROFILE="${PROFILE:-release}"

metadata_versions() {
  python3 - <<'PY'
import json
import subprocess

data = json.loads(subprocess.check_output(["cargo", "metadata", "--no-deps", "--format-version", "1"]))
versions = {pkg["name"]: pkg["version"] for pkg in data["packages"]}
for name in ["enigma-core", "enigma-daemon", "enigma-cli", "enigma-ui-api"]:
    if name not in versions:
        raise SystemExit(f"missing {name}")
    print(f"{name}={versions[name]}")
PY
}

bash scripts/check_versions.sh
bash scripts/check_docs.sh
bash scripts/check_deployment_docs.sh

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --locked
cargo test --locked --all-features
cargo build --locked --release --workspace
cargo build --locked --release --workspace --all-features

cargo build --locked --release -p enigma-daemon -p enigma-cli --target "$TARGET"
cargo build --locked --release -p enigma-daemon -p enigma-cli --target "$TARGET" --all-features

while IFS='=' read -r name version; do
  case "$name" in
    enigma-daemon) daemon_version="$version" ;;
    enigma-cli) cli_version="$version" ;;
    enigma-core) core_version="$version" ;;
    enigma-ui-api) ui_api_version="$version" ;;
  esac
done < <(metadata_versions)

daemon_artifact="enigma-daemon-${daemon_version}-${TARGET}-${PROFILE}"
cli_artifact="enigma-cli-${cli_version}-${TARGET}-${PROFILE}"
deployment_artifact="enigma-deployment-${daemon_version}-${TARGET}-${PROFILE}.tar.gz"

rm -rf "$ROOT/dist"
mkdir -p "$ROOT/dist"
cp "$ROOT/target/$TARGET/release/enigma-daemon" "$ROOT/dist/$daemon_artifact"
cp "$ROOT/target/$TARGET/release/enigma-cli" "$ROOT/dist/$cli_artifact"
tar -czf "$ROOT/dist/$deployment_artifact" deployment systemd MIGRATIONS.md COMPATIBILITY.md RELEASE.md API.md

cat > "$ROOT/dist/manifest.json" <<EOF
{
  "target": "$TARGET",
  "profile": "$PROFILE",
  "rustc": "$(rustc -V)",
  "features": ["default"],
  "crates": {
    "enigma-core": "$core_version",
    "enigma-daemon": "$daemon_version",
    "enigma-cli": "$cli_version",
    "enigma-ui-api": "$ui_api_version"
  }
}
EOF

manifest_keys="$(awk -F '"' '/^  "/ {print $2}' "$ROOT/dist/manifest.json" | tr '\n' ' ')"
expected_keys="target profile rustc features crates "
if [ "$manifest_keys" != "$expected_keys" ]; then
  echo "manifest.json key order mismatch" >&2
  exit 1
fi
if grep -qi "timestamp" "$ROOT/dist/manifest.json"; then
  echo "manifest.json contains timestamp" >&2
  exit 1
fi

(cd "$ROOT/dist" && sha256sum "$daemon_artifact" > "${daemon_artifact}.sha256")
(cd "$ROOT/dist" && sha256sum "$cli_artifact" > "${cli_artifact}.sha256")
(cd "$ROOT/dist" && sha256sum "$deployment_artifact" > "${deployment_artifact}.sha256")
(cd "$ROOT/dist" && sha256sum manifest.json > manifest.json.sha256)
(cd "$ROOT/dist" && sha256sum "$daemon_artifact" "$cli_artifact" "$deployment_artifact" manifest.json > SHA256SUMS)

cat <<EOF
Release artifacts staged in dist/
Verify checksums: (cd dist && sha256sum -c SHA256SUMS)
EOF
