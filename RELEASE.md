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
- Push tag vX.Y.Z; GitHub Actions release workflow validates the checklist, runs scripts/release_build.sh, builds release binaries, and uploads artifacts for enigma-daemon and enigma-cli.
- Release artifacts are built for `x86_64-unknown-linux-musl` (`enigma-daemon-x86_64-unknown-linux-musl` and `enigma-cli-x86_64-unknown-linux-musl`) alongside BUILDINFO.json.
- SHA256SUMS is produced for every tagged build and signed when a minisign key is configured.
- No auto-publish to crates.io; publishing is manual in the order above after artifacts are verified from the tagged build.

Rollback guidance
- If a release fails validation or post-tag verification, yank the tag and republish after fixes.
- Do not publish crates.io artifacts until the tag build is green.

Security note
- Artifacts are built from tags only; no auto-deploy to production systems.
- See docs/distribution.md for verification and trust guidance.
