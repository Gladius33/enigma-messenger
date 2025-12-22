# enigma-node-client

Client-only Rust crate to interact with Enigma node services over HTTP. It reuses the canonical payloads from `enigma-node-types` and is designed for embedding into apps such as `enigma-messenger` without pulling server dependencies.

## Features
- Registry operations (register, resolve, check_user) and node discovery helpers
- Safe defaults: bounded timeouts and response size limits
- Strict JSON decoding via `enigma-node-types` payloads
- Pure client crate: no server-side code or runtime

## Quickstart

```rust
use enigma_node_client::{NodeClient, NodeClientConfig};
use enigma_node_types::{PublicIdentity, RegisterRequest, UserId};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = NodeClient::new(
        "https://registry.example.com",
        NodeClientConfig::default(),
    )?;

    let username = "alice";
    let user_id = UserId::from_username(username)?;

    let identity = PublicIdentity {
        user_id,
        username_hint: Some(username.to_string()),
        signing_public_key: vec![1, 2, 3],
        encryption_public_key: vec![4, 5, 6],
        signature: vec![7, 8, 9],
        created_at_ms: 1,
    };

    let register_req = RegisterRequest {
        identity: identity.clone(),
    };
    client.register(register_req).await?;

    let resolved = client.resolve(&identity.user_id.to_hex()).await?;
    if let Some(found) = resolved.identity {
        println!("Resolved user id: {}", found.user_id.to_hex());
    }

    Ok(())
}
```

## Notes
- TLS via `rustls` is enabled by default and recommended for all deployments.
- Registry endpoints operate on `UserId` values, not raw usernames.

## License
MIT © 2025 Sébastien TOUILLEUX (Gladius33)
