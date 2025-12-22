# Optional patch overrides for local development

Paste the snippet below into the workspace `Cargo.toml` under `[patch.crates-io]` when working on these crates directly, then remove once you are done to avoid unused patch warnings.

```toml
enigma-aead = { git = "https://github.com/Gladius33/enigma-aead" }
enigma-node-client = { git = "https://github.com/Gladius33/enigma-node-client" }
enigma-packet = { git = "https://github.com/Gladius33/enigma-packet" }
enigma-relay = { git = "https://github.com/Gladius33/enigma-relay" }
enigma-signaling = { git = "https://github.com/Gladius33/enigma-signaling" }
enigma-transport-webrtc = { git = "https://github.com/Gladius33/enigma-transport-webrtc" }
enigma-sfu = { git = "https://github.com/Gladius33/enigma-sfu" }
```
