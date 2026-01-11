# Enigma UI API v1

The daemon exposes a local HTTP API under `/api/v1` for UI clients. Responses always include `meta` and either `data` or `error`.

- `meta`: `{ api_version: 1, request_id: UUID, timestamp_ms: u64 }`
- `data`: endpoint-specific payload
- `error`: `{ code: string, message: string, details?: object }`
- Auth (optional): enable the `ui-auth` feature and set `ENIGMA_UI_TOKEN`; clients send `Authorization: Bearer <token>`.
- If the daemon binds the UI API to a non-loopback address, `ui-auth` must be enabled and `ENIGMA_UI_TOKEN` must be set.

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

## Pagination and sync semantics
- `GET /api/v1/conversations/{id}/messages` returns messages in deterministic insertion order. `cursor` is a zero-based offset; `limit` defaults to 50 and is capped at 200. When `cursor` is past the end, an empty list is returned.
- `POST /api/v1/sync` returns events ordered by a monotonic cursor. `cursor` is exclusive; `next_cursor` is the last delivered cursor when events are returned, or `null` when no events exist. `limit` defaults to 50 and is capped at 200. Cursors are in-memory and reset on daemon restart.

## DTO snapshots (see `crates/enigma-ui-api`)
- `IdentityInfo { user_id, handle?, devices: [DeviceInfo], has_bundle_v2, created_ms }`
- `Contact { user_id, handle, display_name?, last_seen_ms }`
- `Conversation { id, kind: Direct|Group|Channel, title?, members, unread_count, last_message? }`
- `Message { id, conversation_id, sender, sent_ms, edited_ms?, kind, body_preview?, attachments_meta?, status: Pending|Sent|Delivered }`
- `SendMessageRequest { conversation_id, kind, body? }`
- `SyncResponse { events: [Event], next_cursor? }` where `Event` is currently `Message` or `ContactAdded`

## UI integration checklist
- Required endpoints: `/api/v1/health`, `/api/v1/identity`, `/api/v1/contacts`, `/api/v1/conversations`, `/api/v1/messages/send`, `/api/v1/sync`.
- Auth: send `Authorization: Bearer <token>` when `ui-auth` is enabled; expect `401` with the standard error envelope when missing or invalid.
- Retry/backoff: use exponential backoff for transient `5xx` responses; do not retry on `4xx` validation errors.
- Idempotency: `contacts/add` and `conversations/create` can be safely retried; `messages/send` is not idempotent.
- Message kinds: only send the documented kinds; unknown kinds return `INVALID_MESSAGE_KIND` with the standard error envelope.
