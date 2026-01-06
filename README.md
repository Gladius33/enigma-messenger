enigma-messenger orchestrates core messaging for Enigma. It wires identity, policy, relay, and transport modules into a single runtime for future UIs while exposing a stable DTO crate.

Contents
- crates/enigma-core: core runtime, policy, persistence, transports, groups/channels, attachments
- crates/enigma-api: DTOs and validation for UI surfaces
- crates/enigma-ui-api: UI-facing DTOs and response envelopes used by the daemon API (see API.md)
- bins/enigma-daemon: background runtime wrapper
- bins/enigma-cli: smoke-test CLI

Build
- cargo test
- run daemon: cargo run -p enigma-daemon -- --config config.json
- run CLI: cargo run -p enigma-cli -- --help
- UI contract: /api/v1 is documented in API.md with versioned DTOs from crates/enigma-ui-api

Production quickstart
- Install runtime services pinned to crates.io releases: `cargo install enigma-node-registry --version 0.0.2` and `cargo install enigma-relay --version 0.0.3`.
- Example registry 0.0.2 config (registry.toml):
  ```
  address = "127.0.0.1:9000"
  mode = "http"
  allow_sync = true

  [envelope]
  pepper_hex = "0000000000000000000000000000000000000000000000000000000000000000"
  [[envelope.keys]]
  kid_hex = "0102030405060708"
  x25519_private_key_hex = "1111111111111111111111111111111111111111111111111111111111111111"
  active = true

  [storage]
  kind = "memory"
  path = ""

  [pow]
  enabled = false
  ```
- Example relay 0.0.3 config (relay.toml):
  ```
  address = "127.0.0.1:9100"
  mode = "http"

  [storage]
  kind = "memory"
  path = ""

  [relay]
  pull_batch_max = 128
  message_ttl_seconds = 300
  ```
- Minimal daemon config pointing to the local services (enigma.toml):
  ```
  data_dir = "/tmp/enigma"

  [identity]
  user_handle = "alice"

  [policy]
  # keep defaults or copy the policy table from tests/mod.rs

  [registry]
  enabled = true
  base_url = "http://127.0.0.1:9000"
  mode = "http"
  pepper_hex = "0000000000000000000000000000000000000000000000000000000000000000"
  key_cache_ttl_secs = 300
  [registry.http]
  timeout_secs = 5
  connect_timeout_secs = 3
  read_timeout_secs = 5
  retry_attempts = 4
  retry_backoff_ms = 200
  [registry.pow]
  enabled = false
  max_solve_ms = 1500
  retry_attempts = 2

  [relay]
  enabled = true
  base_url = "http://127.0.0.1:9100"
  mode = "http"
  [relay.http]
  timeout_secs = 5
  connect_timeout_secs = 3
  read_timeout_secs = 5
  retry_attempts = 4
  retry_backoff_ms = 200

  [transport.webrtc]
  enabled = false
  stun_servers = []

  [sfu]
  enabled = false

  [calls]
  enabled = false

  [logging]
  level = "info"
  ```
- Run all three locally: `enigma-node-registry --config registry.toml`, `enigma-relay --config relay.toml`, then `cargo run -p enigma-daemon -- --config enigma.toml`.

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
