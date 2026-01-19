# Enigma UI API v1

The daemon exposes a local HTTP API under `/api/v1` for UI clients. Responses always include `meta` and either `data` or `error`.

- `meta`: `{ api_version: 1, request_id: UUID, timestamp_ms: u64 }`
- `data`: endpoint-specific payload
- `error`: `{ code: string, message: string, details?: object }`
- Auth (optional): enable the `ui-auth` feature and set `ENIGMA_UI_TOKEN`; clients send `Authorization: Bearer <token>`.
- If the daemon binds the UI API to a non-loopback address, `ui-auth` must be enabled and `ENIGMA_UI_TOKEN` must be set.

## Endpoints
- `GET /api/v1/health` → `{ "status": "ok" }` (data payload)
- `GET /api/v1/identity` → `IdentityInfo`
- `POST /api/v1/contacts/add` body `ContactAddRequest` → `Contact`
- `GET /api/v1/contacts` → `[Contact]`
- `POST /api/v1/conversations/create` body `ConversationCreateRequest` → `Conversation`
- `GET /api/v1/conversations` → `[Conversation]`
- `GET /api/v1/conversations/{id}/messages?cursor=&limit=` → `[Message]`
- `POST /api/v1/messages/send` body `SendMessageRequest` → `SendMessageResponse`
- `POST /api/v1/sync` body `SyncRequest` → `SyncResponse` (events with optional `next_cursor`)
- `GET /api/v1/stats` → `Stats` (minimal runtime stats + capabilities/policy caps)

## DTO definitions
Primitive conventions:
- `UUID`: RFC 4122 hyphenated string.
- `user_id`: 64-char lowercase hex string.
- `timestamp_ms`: `u64` milliseconds since Unix epoch.

### HealthResponse
`/api/v1/health` data payload is exactly:
- `HealthResponse { status: "ok" }`

### IdentityInfo
- `IdentityInfo { user_id: string (user_id), handle?: string, devices: [DeviceInfo], has_bundle_v2: bool, created_ms: u64 }`
- `DeviceInfo { device_id: string (UUID), last_seen_ms: u64 }`

### Contact
- `Contact { user_id: string (user_id), handle: string, display_name?: string, last_seen_ms: u64 }`

### ContactAddRequest
- `ContactAddRequest { handle?: string, user_id?: string, display_name?: string }`
- Exactly one of `handle` or `user_id` is required. If both are provided, `user_id` takes precedence.

### Conversation
- `Conversation { id: string, kind: "Direct"|"Group"|"Channel", title?: string, members: [string], unread_count: u32, last_message?: Message }`

### ConversationCreateRequest
- `ConversationCreateRequest { handle?: string, user_id?: string, title?: string }`
- Exactly one of `handle` or `user_id` is required for direct conversations. If both are provided, `user_id` takes precedence.

### Message
- `Message { id: string (UUID), conversation_id: string, sender: string (user_id), sent_ms: u64, edited_ms?: u64, kind: MessageKind, body_preview?: string, attachments_meta?: object, status: "Pending"|"Sent"|"Delivered" }`
- `body_preview` is a short preview and may be omitted. The full body is not returned in UI API v1; do not assume it is available in `Message`.
- `attachments_meta` is omitted when empty. When present, its shape is described in the Attachments section.

### SendMessageRequest
- `SendMessageRequest { conversation_id: string, kind: MessageKind, body?: string, attachment_id?: UUID (planned), attachment?: AttachmentDescriptor (planned), attachment_bytes_b64?: string (planned) }`
- `conversation_id` and `kind` are required. `body` is required for `Text`.
- Non-text kinds require attachments (planned). Until attachments endpoints are implemented, only `Text` is supported.
- Planned fields are currently ignored by the daemon.

### SendMessageResponse
- `SendMessageResponse { message_id: string (UUID), status: "Pending"|"Sent"|"Delivered" }`
- No `accepted` flag or timestamps are included in this response.

### SyncRequest
- `SyncRequest { cursor?: u64, limit?: u64 }`
- Defaults: `limit` = 50, capped at 200.

### SyncResponse
- `SyncResponse { events: [Event], next_cursor?: u64 }`
- `Event` is a tagged object with a `type` field:
  - Message event: `{ type: "Message", ...Message }`
  - Contact event: `{ type: "ContactAdded", ...Contact }`

## Stats payload (/api/v1/stats)
`GET /api/v1/stats` returns a stable, non-secret payload with fast boot support:
- `Stats { user_id_hex: string (user_id), device_id: string (UUID), conversations: u64, groups: u64, channels: u64, pending_outbox: u64, directory_len: u64, daemon_ready: bool, daemon_ready_ms?: u64, capabilities: Capabilities, policy_caps?: PolicyCaps }`
- `daemon_ready`: boolean indicating if the daemon core initialization is complete. UI clients should poll until this is true before making full requests.
- `daemon_ready_ms`: optional timestamp (ms since Unix epoch) indicating when the daemon became ready. Present only if daemon_ready is true.

### Capabilities
- `Capabilities { ui_api_v1: bool, ui_auth_enabled: bool, proto_v1: bool, proto_v2: bool, relay_enabled: bool, registry_enabled: bool, transport_webrtc_enabled: bool, sfu_enabled: bool, calls_enabled: bool, attachments_ui_api: bool, attachments_inline_enabled: bool, pagination_limit_cap: u32, sync_limit_cap: u32 }`
- `ui_auth_enabled` is true when the daemon enforces `Authorization: Bearer` (feature `ui-auth` + `ENIGMA_UI_TOKEN` set).
- `attachments_ui_api` is false until attachment endpoints are implemented.
- `attachments_inline_enabled` is true when `max_inline_media_bytes > 0` and attachments are not disabled.

### PolicyCaps (optional)
- `PolicyCaps { max_text_bytes: u64, max_inline_media_bytes: u64, max_attachment_chunk_bytes: u64, max_attachment_parallel_chunks: u64 }`

### UI guidance
- Use `capabilities.pagination_limit_cap` and `capabilities.sync_limit_cap` to cap page sizes for `/conversations/{id}/messages` and `/sync`.
- Use `policy_caps` to enforce text limits, inline media size, and attachment chunk parallelism without parsing TOML.
- Hide or disable attachment upload UI when `attachments_ui_api` is false.
- Allow inline media only when `attachments_inline_enabled` is true and `max_inline_media_bytes` is respected.

## Message kinds
Allowed kinds (case-insensitive input; canonical form shown):
- `Text`, `File`, `Image`, `Video`, `Voice`, `System`, `CallSignal`, `ChannelPost`, `GroupEvent`
Unknown kinds return `INVALID_MESSAGE_KIND` with HTTP 400.

## Semantics
### Pagination
- `GET /api/v1/conversations/{id}/messages` returns messages in deterministic insertion order.
- `cursor` is a zero-based offset; `limit` defaults to 50 and is capped at 200.
- When `cursor` is past the end, an empty list is returned.

### Sync cursor
- `POST /api/v1/sync` returns events ordered by a monotonic cursor.
- `cursor` is exclusive; `next_cursor` is the last delivered cursor when events are returned, or `null` when no events exist.
- Cursors are in-memory and reset on daemon restart.
- UI should treat a smaller `next_cursor` (or `null` after previously non-null) as a restart and perform a full refresh before resuming sync.

### Idempotency
- `contacts/add` and `conversations/create` can be safely retried.
- `messages/send` is not idempotent.
- Attachment chunk uploads are idempotent per sequence (planned).

## Errors
Errors use the standard envelope (`{ meta, error }`); `details` may be present.

Common status mappings (non-exhaustive):
- 400: `INVALID_BODY`, `INVALID_REQUEST`, `INVALID_USER`, `INVALID_HANDLE`, `INVALID_MESSAGE_KIND`, `UNKNOWN_CONVERSATION`
- 401: `UNAUTHORIZED`
- 404: `NOT_FOUND`
- 409: `CONFLICT`, `CHUNK_CONFLICT` (planned)
- 413: `ATTACHMENT_TOO_LARGE`, `CHUNK_TOO_LARGE` (planned)
- 429: `RATE_LIMITED` (planned)
- 500: `SEND_FAILED`

## Attachments (planned; not yet implemented in the daemon UI API)
This section defines the stable, additive contract for attachment upload/download. It aligns with the core chunking behavior and relay ack semantics, but the UI endpoints below are not yet exposed by the daemon. UI clients should feature-flag until the implementation lands.

### Attachment DTOs
- `AttachmentDescriptor { id: UUID, filename?: string, content_type: string, total_size: u64 }`
- `AttachmentMeta { id: UUID, filename?: string, content_type: string, total_size: u64, chunk_size: u64, chunk_count: u64 }`
- `AttachmentUploadInitRequest { filename?: string, content_type: string, total_size: u64 }`
- `AttachmentUploadInitResponse { attachment: AttachmentMeta, max_parallel_chunks: u64 }`
- `AttachmentChunkUploadRequest { bytes_b64: string }`
- `AttachmentChunkUploadResponse { attachment_id: UUID, sequence: u64, received_bytes: u64 }`
- `AttachmentFinalizeResponse { attachment: AttachmentMeta, status: "ready" }`
- `AttachmentInfoResponse { attachment: AttachmentMeta, state: "uploading"|"ready" }`
- `AttachmentChunkResponse { attachment_id: UUID, sequence: u64, chunk_count: u64, bytes_b64: string, is_last: bool }`

`Message.attachments_meta` is `{ "items": [AttachmentMeta] }` when a message carries attachments (currently one item only). `attachments_meta` is omitted otherwise.
Indexing: UI upload/download uses `sequence` (1-based). Relay ack uses `chunk_index` (0-based).

### Workflow (upload -> send -> download)
1) `POST /api/v1/attachments/uploads` to create an upload session and obtain `chunk_size` and `chunk_count`.
2) `PUT /api/v1/attachments/uploads/{attachment_id}/chunks/{sequence}` for each chunk (1-based `sequence`).
3) `POST /api/v1/attachments/uploads/{attachment_id}/complete` to finalize.
4) `POST /api/v1/messages/send` with `attachment_id` (uploaded) or inline bytes for small media.
5) `GET /api/v1/attachments/{attachment_id}` to fetch metadata.
6) `GET /api/v1/attachments/{attachment_id}/chunks/{sequence}` to download chunks and reassemble locally.

### Planned attachment endpoints
- Planned: `POST /api/v1/attachments/uploads`
  - Request: `AttachmentUploadInitRequest`
  - Response: `AttachmentUploadInitResponse` (`201`)
  - Errors: `400 INVALID_BODY`, `400 INVALID_ATTACHMENT`, `403 ATTACHMENTS_DISABLED`, `413 ATTACHMENT_TOO_LARGE`, `429 RATE_LIMITED`, `500 INTERNAL_ERROR`
- Planned: `PUT /api/v1/attachments/uploads/{attachment_id}/chunks/{sequence}`
  - Request: `AttachmentChunkUploadRequest` (JSON base64)
  - Response: `AttachmentChunkUploadResponse` (`200` or `202`)
  - Errors: `400 INVALID_BODY`, `400 INVALID_CHUNK_INDEX`, `404 UNKNOWN_ATTACHMENT`, `409 CHUNK_CONFLICT`, `413 CHUNK_TOO_LARGE`, `429 RATE_LIMITED`, `500 INTERNAL_ERROR`
- Planned: `POST /api/v1/attachments/uploads/{attachment_id}/complete`
  - Request: `{}` (empty JSON object)
  - Response: `AttachmentFinalizeResponse` (`200`)
  - Errors: `400 INVALID_BODY`, `404 UNKNOWN_ATTACHMENT`, `409 UPLOAD_INCOMPLETE`, `500 INTERNAL_ERROR`
- Planned: `DELETE /api/v1/attachments/uploads/{attachment_id}`
  - Response: `{ status: "cancelled" }` (`200`)
  - Errors: `404 UNKNOWN_ATTACHMENT`, `500 INTERNAL_ERROR`
- Planned (additive to existing endpoint): `POST /api/v1/messages/send`
  - Additional request fields (optional):
    - `attachment_id?: UUID` (reference an uploaded attachment)
    - `attachment?: AttachmentDescriptor` (required when using inline bytes)
    - `attachment_bytes_b64?: string` (inline bytes; size <= `max_inline_media_bytes`)
  - When using inline bytes, clients must generate `attachment.id` (UUID). That value becomes the download `attachment_id`.
  - Response: existing `SendMessageResponse`
  - Errors: existing message send errors plus `403 ATTACHMENTS_DISABLED`, `404 UNKNOWN_ATTACHMENT`, `413 ATTACHMENT_TOO_LARGE`
- Planned: `GET /api/v1/attachments/{attachment_id}`
  - Response: `AttachmentInfoResponse` (`200`)
  - Errors: `404 UNKNOWN_ATTACHMENT`, `500 INTERNAL_ERROR`
- Planned: `GET /api/v1/attachments/{attachment_id}/chunks/{sequence}`
  - Response: `AttachmentChunkResponse` (`200`)
  - Errors: `400 INVALID_CHUNK_INDEX`, `404 UNKNOWN_ATTACHMENT`, `500 INTERNAL_ERROR`

### Error codes (attachments)
Errors use the standard envelope (`{ meta, error }`). Messages are human-readable and may include `details`.
- `INVALID_BODY`: "empty body" or "invalid json"
- `UNAUTHORIZED`: "missing or invalid token"
- `INVALID_ATTACHMENT`: "invalid attachment metadata"
- `INVALID_CHUNK_INDEX`: "chunk index out of range"
- `CHUNK_CONFLICT`: "chunk already uploaded or size mismatch"
- `UPLOAD_INCOMPLETE`: "upload incomplete"
- `UNKNOWN_ATTACHMENT`: "unknown attachment"
- `ATTACHMENTS_DISABLED`: "attachments disabled"
- `ATTACHMENT_TOO_LARGE`: "attachment too large"
- `CHUNK_TOO_LARGE`: "chunk too large"
- `RATE_LIMITED`: "rate limited"

### Limits and policy alignment
- `max_inline_media_bytes`: maximum payload size for `attachment_bytes_b64` in `/api/v1/messages/send`.
- `max_attachment_chunk_bytes`: maximum chunk size accepted for uploads and returned for downloads. `chunk_size` in `AttachmentMeta` never exceeds this cap; the last chunk may be smaller.
- `max_attachment_parallel_chunks`: recommended upper bound for in-flight chunk uploads/downloads.
- `total_size` must be > 0; the daemon rejects `total_size` that exceeds policy or configured storage limits (`413 ATTACHMENT_TOO_LARGE`).
- `sequence` is 1-based and must be within `1..=chunk_count`. `chunk_count = ceil(total_size / chunk_size)`.
- Relay ack uses `chunk_index` (0-based) and is distinct from UI `sequence`.
- Chunked transfers are index-based; there is no list pagination beyond `chunk_count`.
- `allow_attachments` disables all attachment endpoints and attachment fields in `/api/v1/messages/send` with `403 ATTACHMENTS_DISABLED`.

### UI guidance (chunking, retry, resume)
- Use `chunk_size` and `chunk_count` from `AttachmentUploadInitResponse`; clients do not pick a custom chunk size.
- Limit parallel chunk transfers to `max_parallel_chunks`.
- Retry `5xx` and `429` with exponential backoff; chunk uploads are idempotent (identical re-uploads return `200`, mismatched bytes return `409 CHUNK_CONFLICT`).
- Resume by persisting `attachment_id` and re-sending missing `sequence` values; uploads are idempotent per sequence.
- Downloads are index-based; request any missing `sequence` values and reassemble in order.

### Attachments, conversations, relay, and inline media
- Attachments are scoped to the message that references them; the `conversation_id` on `/api/v1/messages/send` determines recipients.
- The canonical recipient string is the lowercase hex `user_id` (same as `IdentityInfo.user_id`); relay/offline delivery uses that value.
- Relay 0.0.3 uses `pull` items and `ack` entries `{ message_id, chunk_index }`; each attachment chunk is acked independently.
- Inline media is for small payloads embedded in `/api/v1/messages/send` (<= `max_inline_media_bytes`). Larger media should use the chunked attachment upload flow.

### Examples
Create upload session:
```json
{
  "filename": "photo.jpg",
  "content_type": "image/jpeg",
  "total_size": 3145728
}
```

Upload first chunk:
```json
{
  "bytes_b64": "aGVsbG8tY2h1bmstMQ=="
}
```

Send message referencing uploaded attachment:
```json
{
  "conversation_id": "conv-123",
  "kind": "Image",
  "body": "look",
  "attachment_id": "b7f4a3f1-66f4-4a8b-9aa1-60282b4ce2cf"
}
```

Download chunk:
```json
{
  "attachment_id": "b7f4a3f1-66f4-4a8b-9aa1-60282b4ce2cf",
  "sequence": 1,
  "chunk_count": 3,
  "bytes_b64": "aGVsbG8tY2h1bmstMQ==",
  "is_last": false
}
```

## UI boot handshake
- `GET /api/v1/health`
- `GET /api/v1/stats` (capabilities + policy caps)
- `GET /api/v1/identity`
- Initial refresh: `GET /api/v1/contacts` + `GET /api/v1/conversations`
- Start `/api/v1/sync` loop (cursor = null) and persist `next_cursor`

## UI integration checklist
- Required endpoints: `/api/v1/health`, `/api/v1/stats`, `/api/v1/identity`, `/api/v1/contacts`, `/api/v1/conversations`, `/api/v1/messages/send`, `/api/v1/sync`.
- Auth: send `Authorization: Bearer <token>` when `ui-auth` is enabled; expect `401` with the standard error envelope when missing or invalid.
- Retry/backoff: use exponential backoff for transient `5xx` responses; do not retry on `4xx` validation errors.
- Idempotency: `contacts/add` and `conversations/create` can be safely retried; `messages/send` is not idempotent.
- Message kinds: only send the documented kinds; unknown kinds return `INVALID_MESSAGE_KIND` with the standard error envelope.
