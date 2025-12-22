# enigma-node-types

Canonical node-facing types and strict codecs for Enigma components. Endpoints exchange hashed user identifiers instead of raw usernames, keeping registry, relay, and SFU traffic aligned while limiting metadata exposure.

Highlights:
- Deterministic `UserId` hashing from usernames using BLAKE3 with a fixed domain separation string.
- Optional `username_hint` field; omit it when privacy matters.
- Validated payloads for registry, presence, node listings, and relay envelopes.
- Relay envelopes carry opaque, encoded blobs; intermediaries should forward without decrypting.

Usage:
1. Construct and validate types locally (e.g., `PublicIdentity::validate`, `RelayEnvelope::validate`).
2. Encode/decode JSON with `to_json_string` and `from_json_str`; unknown fields are rejected.
3. Prefer `UserId` over plaintext usernames in network endpoints; hints are optional.
