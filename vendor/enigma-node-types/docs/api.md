# API

- `UserId`: newtype around 32-byte array. Build with `UserId::from_username(&str)` or `UserId::from_hex(&str)`. Serialize/deserialize as lowercase hex. `normalize_username` trims and rejects control characters.
- `PublicIdentity`: identity record with `validate()`. `signed_payload(username_hint, signing_key, encryption_key)` builds length-prefixed bytes for signatures.
- Registry payloads: `RegisterRequest`, `RegisterResponse`, `ResolveResponse`, `CheckUserResponse`, `SyncRequest`, `SyncResponse` (all `deny_unknown_fields`).
- `Presence`: address heartbeat with `validate()`.
- `NodeInfo` and `NodesPayload`: directory entries with `validate()` to enforce schemes.
- Relay: `RelayEnvelope` and `RelayKind` variants for opaque messages, signaling, and attachment chunks. `RelayEnvelope::validate()` checks timestamps, base64 blobs, and optional content type lengths. `RelayPushRequest`, `RelayPushResponse`, `RelayPullResponse`, `RelayAckRequest`, `RelayAckResponse` mirror relay flows.
- Codecs: `to_json_string` and `from_json_str` wrap serde_json and propagate `EnigmaNodeTypesError::JsonError` on failure.
- Errors: `EnigmaNodeTypesError` and `Result<T>` alias for consistent error handling without panics.
