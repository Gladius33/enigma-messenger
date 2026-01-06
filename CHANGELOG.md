# Changelog

## Unreleased
- CI and release automation scaffolding (fmt, clippy, tests, release builds)
- Pinned Enigma crate versions and documented release governance (Step 12)
- Reproducible release builds with checksums/signing hooks and supply-chain checks (Step 13)
- Step 14: hardened registry/relay HTTP clients with retries and typed errors, structured daemon API errors, hermetic integration harnesses against enigma-node-registry 0.0.2 and enigma-relay 0.0.3, and production quickstart docs
- Step 16: protocol V2 messaging with X3DH prekey bundles, double-ratchet framing, persisted sessions, proto-v2 feature flag, and dedicated tests
- Step 18: daemon UI API v1 freeze with enigma-ui-api DTOs, structured envelopes, optional auth, and contract tests for contacts/conversations/sync
- Step 19: production packaging with /etc/enigma templates, hardened systemd units, enigma-cli doctor/default-config commands, musl release artifacts, and deployment docs
- Step 20: compatibility policy and migration framework (store version stamping, CLI migrate/doctor JSON output, UI error snapshot), CI guardrails for pinned versions/docs, and compatibility/migrations docs

## 0.0.3
- Protocol V2 handshake and ratchet sessions with X3DH-derived keys and persisted state

## 0.0.2
- Relay 0.0.3 compatibility: chunk-aware pull/ack contract in the daemon HTTP client and integration tests

## 0.0.1
- Optional sender-keys mode for group messaging
- Daemon runtime and configuration wrapper for enigma-core
- Node-registry envelope resolution and integration
