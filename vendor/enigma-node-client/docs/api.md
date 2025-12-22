# API

This crate exposes a thin HTTP client around Enigma node services. All payloads come from `enigma-node-types`, preserving strict JSON validation.

## Configuration
- `NodeClientConfig` controls timeouts, user agent, and response size cap.

## Client
- `NodeClient::new(base_url, cfg)` constructs a client after validating the base URL.
- `NodeClient::base_url()` returns the configured base URL.

## Registry operations
- `register(RegisterRequest) -> RegisterResponse`
- `resolve(&str user_id_hex) -> ResolveResponse`
- `check_user(&str user_id_hex) -> CheckUserResponse`
- `announce(Presence) -> serde_json::Value` for lightweight acknowledgement payloads
- `sync(SyncRequest) -> SyncResponse`
- `nodes() -> NodesPayload`
- `add_nodes(NodesPayload) -> serde_json::Value`

All methods are async and return `Result<T, EnigmaNodeClientError>`.
