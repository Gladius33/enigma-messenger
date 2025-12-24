# Changelog

## Unreleased
- CI and release automation scaffolding (fmt, clippy, tests, release builds)
- Pinned Enigma crate versions and documented release governance (Step 12)
- Reproducible release builds with checksums/signing hooks and supply-chain checks (Step 13)
- Step 14: hardened registry/relay HTTP clients with retries and typed errors, structured daemon API errors, hermetic integration harnesses against enigma-node-registry 0.0.2 and enigma-relay 0.0.3, and production quickstart docs

## 0.0.2
- Relay 0.0.3 compatibility: chunk-aware pull/ack contract in the daemon HTTP client and integration tests

## 0.0.1
- Optional sender-keys mode for group messaging
- Daemon runtime and configuration wrapper for enigma-core
- Node-registry envelope resolution and integration
