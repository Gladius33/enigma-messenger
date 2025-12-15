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
