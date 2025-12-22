# Privacy

Enigma nodes should avoid leaking usernames over the network. `UserId` values are derived by hashing a normalized username with a domain-separated BLAKE3 input. Remote peers and relays see only the hash, not the original string.

The optional `username_hint` is for convenience only and should be omitted on privacy-sensitive paths. Presence announcements and relay envelopes rely on `UserId` to limit correlation.

This hashing does not replace transport security. Use TLS or equivalent channel protection to prevent observation or tampering and rotate keys as operational policy dictates.
