enigma-messenger orchestrates core messaging for Enigma. It wires identity, policy, relay, and transport modules into a single runtime for future UIs while exposing a stable DTO crate.

Contents
- crates/enigma-core: core runtime, policy, persistence, transports, groups/channels, attachments
- crates/enigma-api: DTOs and validation for UI surfaces
- bins/enigma-daemon: background runtime wrapper
- bins/enigma-cli: smoke-test CLI

Build
- cargo test
- run daemon: cargo run -p enigma-daemon -- --config config.json
- run CLI: cargo run -p enigma-cli -- --help

How to run CI locally
- cargo fmt --all -- --check
- cargo clippy --workspace --all-targets -- -D warnings
- cargo test && cargo test --all-features
- cargo test -p enigma-core --features sender-keys
- cargo test -p enigma-daemon && cargo test -p enigma-daemon --all-features
- cargo build --release && cargo build --release --all-features

Release process
- Update CHANGELOG.md and pin versions in Cargo.toml before tagging.
- Run the full CI command set locally.
- Tag as vX.Y.Z and push; the release workflow builds artifacts for enigma-daemon and enigma-cli.
- Manual publish (when ready): cargo publish -p enigma-api, then -p enigma-core, then binaries (enigma-daemon, enigma-cli) if distributing via crates.io.
- Reproducible build and verification steps are documented in scripts/release_build.sh and docs/distribution.md.

Feature matrix
- Relay 0.0.3 ack/pull contract: cargo test -p enigma-daemon tests::relay_integration_outbox
- Optional sender-keys mode: cargo test -p enigma-core --features sender-keys
- Daemon runtime/config surface: cargo test -p enigma-daemon
- Node-registry envelope integration: cargo test -p enigma-daemon tests::registry_integration_smoke
