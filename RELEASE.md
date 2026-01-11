Release process and governance

Versioning (<0.1.0)
- X is fixed at 0 for now.
- Y is breaking.
- Z is patch/backward-compatible.

Release checklist
- Review `MIGRATIONS.md` and `COMPATIBILITY.md` for compatibility or migration notes.
- Confirm versions are pinned exactly in Cargo.toml and `enigma-daemon --version` / `enigma-cli --version` match.
- Run validation:
  - cargo fmt --all -- --check
  - cargo clippy --workspace --all-targets -- -D warnings
  - cargo test
  - cargo test --all-features
  - cargo build --release
  - cargo build --release --all-features
- Run `./scripts/release_build.sh` and verify: `cd dist && sha256sum -c SHA256SUMS`.
- Validate migrations: `enigma-cli migrate --dry-run --config /etc/enigma/daemon.toml` and apply only when required: `enigma-cli migrate --apply --yes --config /etc/enigma/daemon.toml`.
- Tag as `vX.Y.Z` and push; tags imply a release build from that exact commit.
- After deploying, run `deployment/smoke.sh` with `ENIGMA_CONFIG=/etc/enigma/daemon.toml` (and `ENIGMA_UI_TOKEN` if required).

Publish order (crates.io)
- Internal crates published from this repo: enigma-ui-api -> enigma-core -> enigma-daemon -> enigma-cli.
- External services enigma-node-registry and enigma-relay are published separately; keep their versions pinned in Cargo.toml.

Tagging
- Use tags of the form vX.Y.Z.

Release workflow
- Push tag vX.Y.Z; the GitHub Actions release workflow runs `scripts/release_build.sh` and uploads `dist/`.
- Artifacts are built for `x86_64-unknown-linux-gnu` and named `enigma-daemon-<version>-x86_64-unknown-linux-gnu-release` and `enigma-cli-<version>-x86_64-unknown-linux-gnu-release`.
- `dist/` includes `manifest.json`, per-file `.sha256`, a `SHA256SUMS` aggregate, and a deployment tarball containing `deployment/` and `systemd/`.
- No auto-publish to crates.io; publishing is manual in the order above after artifacts are verified from the tagged build.

Local release build
- Run `./scripts/release_build.sh`.
- Verify artifacts: `cd dist && sha256sum -c SHA256SUMS`.

Rollback guidance
- If a release fails validation or post-tag verification, yank the tag and republish after fixes.
- Do not publish crates.io artifacts until the tag build is green.

Security note
- Artifacts are built from tags only; no auto-deploy to production systems.
- Operational hardening guidance lives in `deployment/security.md`.
