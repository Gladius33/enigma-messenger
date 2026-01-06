# Compatibility policy (pre-1.0)

Stable surfaces
- UI API `/api/v1` is contract-stable: DTO shapes are frozen, error envelopes always include `meta` (api_version/request_id/timestamp_ms) and structured `error` objects.
- Relay client contract is pinned to `enigma-relay` `0.0.3` pull/ack semantics.
- Registry envelopes follow the `enigma-node-registry` `0.0.2` schema; optional identity bundles remain forward-compatible.
- Wire format supports message V1 and V2; V2 (X3DH + double ratchet) is preferred with fallback to V1 for peers without proto-v2.
- On-disk persistence versions: identity v2, sessions v1, outbox v2 (tracked via `store:versions`).

Pre-1.0 versioning discipline
- Patch bumps only within the `0.y.z` window; any behavior change or new surface is accompanied by explicit notes in CHANGELOG and docs.
- Internal crates are pinned exactly (no caret ranges) and published in order: registry -> relay -> core -> transports -> daemon -> CLI.
- External compatibility (relay/registry) is maintained by pinning tested versions in Cargo manifests and CI.

Matrix (current release line)
- UI API: `/api/v1` with `enigma-ui-api` DTOs; error envelope frozen.
- Relay: `0.0.3` (HTTP pull/ack).
- Registry: `0.0.2` (envelope pubkeys + presence).
- Wire: message V2 default, V1 fallback.
- Storage: identity v2, sessions v1, outbox v2 (see MIGRATIONS.md).

Upgrade guidance
- Read MIGRATIONS.md before deploying new binaries; run `enigma-cli migrate --dry-run` and `enigma-cli doctor` to confirm store versions and health.
- Keep daemon UI bound to loopback by default; expose only registry/relay listener ports to trusted peers.
