# Design

The crate separates concerns between registry flows (identity publication and sync), presence discovery, node directory listings, and relay envelopes used for offline store-and-forward. Each payload is validated locally to prevent passing malformed data across node boundaries.

User-facing metadata is minimized. Network endpoints should expose only hashed `UserId` values. Plaintext usernames stay local; the optional `username_hint` exists solely for user experience and can be omitted entirely. Relay envelopes are intentionally opaque and avoid any schema for inner contents.

Validation rules are strict but lightweight. Strings are length-bound, timestamps must be positive, and JSON decoding rejects unknown fields to keep compatibility predictable.
