# Formats

UserId values appear in JSON as lowercase hex strings.

Public identity:
```json
{
  "user_id": "4d8f3c6a4e974fbc0a7b8df71c8ccf847b2f8c3a5b7d9e10f2a4b6c7d8e9f0a1",
  "username_hint": "alice",
  "signing_public_key": [1, 2, 3],
  "encryption_public_key": [4, 5, 6],
  "signature": [7, 8, 9],
  "created_at_ms": 1700000000000
}
```

Presence:
```json
{
  "user_id": "4d8f3c6a4e974fbc0a7b8df71c8ccf847b2f8c3a5b7d9e10f2a4b6c7d8e9f0a1",
  "addr": "203.0.113.7:51820",
  "ts_ms": 1700000005000
}
```

Node directory:
```json
{
  "nodes": [
    { "base_url": "https://node1.example.org" },
    { "base_url": "https://node2.example.org" }
  ]
}
```

Registry payloads:
```json
{ "identity": { "...": "public identity fields" } }
{ "ok": true }
{ "identity": null }
{ "exists": false }
{ "identities": [ { "...": "public identity fields" } ] }
{ "merged": 5 }
```

Relay envelope:
```json
{
  "id": "6a1ef508-9d0d-4a08-85c6-0d9f50ae6f0c",
  "to": "4d8f3c6a4e974fbc0a7b8df71c8ccf847b2f8c3a5b7d9e10f2a4b6c7d8e9f0a1",
  "from": null,
  "created_at_ms": 1700000010000,
  "expires_at_ms": 1700000610000,
  "kind": {
    "OpaqueMessage": {
      "blob_b64": "YmFzZTY0LWRhdGE=",
      "content_type": "application/octet-stream"
    }
  }
}
```

Relay push and pull:
```json
{ "envelopes": [ { "...": "relay envelope fields" } ] }
{ "accepted": 1 }
{ "envelopes": [ { "...": "relay envelope fields" } ], "next_cursor": null }
{ "ids": [ "6a1ef508-9d0d-4a08-85c6-0d9f50ae6f0c" ] }
{ "removed": 1 }
```
