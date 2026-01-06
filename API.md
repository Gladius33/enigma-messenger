# Enigma UI API v1

The daemon exposes a local HTTP API under `/api/v1` for UI clients. Responses always include `meta` and either `data` or `error`.

- `meta`: `{ api_version: 1, request_id: UUID, timestamp_ms: u64 }`
- `data`: endpoint-specific payload
- `error`: `{ code: string, message: string, details?: object }`
- Auth (optional): enable the `ui-auth` feature and set `ENIGMA_UI_TOKEN`; clients send `Authorization: Bearer <token>`.

## Endpoints
- `GET /api/v1/health` → `{ status: "ok" }`
- `GET /api/v1/identity` → `IdentityInfo`
- `POST /api/v1/contacts/add` body `{ handle?: string, user_id?: string, display_name?: string }` → `Contact`
- `GET /api/v1/contacts` → `[Contact]`
- `POST /api/v1/conversations/create` body `{ handle?: string, user_id?: string, title?: string }` → `Conversation`
- `GET /api/v1/conversations` → `[Conversation]`
- `GET /api/v1/conversations/{id}/messages?cursor=&limit=` → `[Message]`
- `POST /api/v1/messages/send` body `SendMessageRequest` → `SendMessageResponse`
- `POST /api/v1/sync` body `SyncRequest` → `SyncResponse` (events with optional `next_cursor`)
- `GET /api/v1/stats` → minimal runtime stats (no secrets)

## DTO snapshots (see `crates/enigma-ui-api`)
- `IdentityInfo { user_id, handle?, devices: [DeviceInfo], has_bundle_v2, created_ms }`
- `Contact { user_id, handle, display_name?, last_seen_ms }`
- `Conversation { id, kind: Direct|Group|Channel, title?, members, unread_count, last_message? }`
- `Message { id, conversation_id, sender, sent_ms, edited_ms?, kind, body_preview?, attachments_meta?, status: Pending|Sent|Delivered }`
- `SendMessageRequest { conversation_id, kind, body? }`
- `SyncResponse { events: [Event], next_cursor? }` where `Event` is currently `Message` or `ContactAdded`
