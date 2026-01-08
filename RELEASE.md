Release process and governance

Versioning (<0.1.0)
- X is fixed at 0 for now.
- Y is breaking.
- Z is patch/backward-compatible.

Publish order
1. enigma-node-registry
2. enigma-relay
3. enigma-core
4. enigma-transport-* (including enigma-transport-webrtc)
5. enigma-daemon
6. enigma-cli

Pre-tag checklist (run locally and in CI)
- cargo fmt --all -- --check
- cargo clippy --workspace --all-targets -- -D warnings
- cargo test
- cargo test --all-features
- cargo build --release
- cargo build --release --all-features

Tagging
- Use tags of the form vX.Y.Z.

Release workflow
- Push tag vX.Y.Z; the GitHub Actions release workflow runs `scripts/release_build.sh` and uploads `dist/`.
- Artifacts are built for `x86_64-unknown-linux-gnu` and named `enigma-daemon-<version>-x86_64-unknown-linux-gnu-release` and `enigma-cli-<version>-x86_64-unknown-linux-gnu-release`.
- `dist/` includes `manifest.json`, per-file `.sha256`, and a `SHA256SUMS` aggregate for verification.
- No auto-publish to crates.io; publishing is manual in the order above after artifacts are verified from the tagged build.

Local release build
- Run `./scripts/release_build.sh`.
- Verify artifacts: `cd dist && sha256sum -c SHA256SUMS`.
- After deploying to a host, run `deployment/smoke.sh` with `ENIGMA_CONFIG=/etc/enigma/daemon.toml` (and `ENIGMA_UI_TOKEN` if required).

Rollback guidance
- If a release fails validation or post-tag verification, yank the tag and republish after fixes.
- Do not publish crates.io artifacts until the tag build is green.

Security note
- Artifacts are built from tags only; no auto-deploy to production systems.
