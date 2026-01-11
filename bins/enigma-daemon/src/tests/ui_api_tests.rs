use super::*;
use enigma_ui_api::{
    ApiResponse, ContactDto, ConversationDto, IdentityInfo, MessageDto, SendMessageResponse,
    SyncResponse,
};
use http_body_util::BodyExt;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::sync::OnceLock;
use tokio::sync::Mutex;

async fn body_bytes(resp: Response<Incoming>) -> Vec<u8> {
    collect_bytes(resp.into_body()).await.unwrap().to_vec()
}

async fn body_full_bytes(resp: Response<Full<Bytes>>) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}

async fn decode_response<T: DeserializeOwned>(resp: Response<Incoming>) -> ApiResponse<T> {
    serde_json::from_slice(&body_bytes(resp).await).unwrap()
}

fn normalize_envelope(value: Value) -> Value {
    let mut normalized = value;
    if let Some(obj) = normalized.as_object_mut() {
        obj.entry("data").or_insert(Value::Null);
        if let Some(meta) = obj.get_mut("meta").and_then(|m| m.as_object_mut()) {
            meta.insert(
                "request_id".to_string(),
                Value::String("request".to_string()),
            );
            meta.insert("timestamp_ms".to_string(), Value::Number(0.into()));
        }
        if let Some(error) = obj.get_mut("error").and_then(|e| e.as_object_mut()) {
            error.entry("details").or_insert(Value::Null);
        }
    }
    normalized
}

fn error_fixture(path: &'static str) -> Value {
    serde_json::from_str(path).unwrap()
}

async fn env_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().await
}

#[tokio::test]
async fn ui_api_endpoints_return_dtos() {
    let _guard = env_guard().await;
    let cfg = test_config(false, false, false);
    let state = build_state(&cfg).await;
    let api_addr = cfg.api.socket_addr().unwrap();
    let (addr, tx, handle) = start_server(state.clone(), api_addr).await;

    let root = decode_response::<Value>(
        dispatch_request(state.clone(), addr, build_request("GET", "/api/v1", None)).await,
    )
    .await;
    assert_eq!(
        root.data.unwrap().get("status").and_then(|v| v.as_str()),
        Some("ok")
    );

    let health = decode_response::<Value>(
        dispatch_request(
            state.clone(),
            addr,
            build_request("GET", "/api/v1/health", None),
        )
        .await,
    )
    .await;
    assert_eq!(health.meta.api_version, enigma_ui_api::API_VERSION);

    let identity = decode_response::<IdentityInfo>(
        dispatch_request(
            state.clone(),
            addr,
            build_request("GET", "/api/v1/identity", None),
        )
        .await,
    )
    .await;
    assert_eq!(identity.data.unwrap().user_id.len(), 64);

    let add_contact = decode_response::<ContactDto>(
        dispatch_request(
            state.clone(),
            addr,
            build_request(
                "POST",
                "/api/v1/contacts/add",
                Some(serde_json::json!({"handle":"bob"})),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(add_contact.data.unwrap().handle, "bob");

    let contacts = decode_response::<Vec<ContactDto>>(
        dispatch_request(
            state.clone(),
            addr,
            build_request("GET", "/api/v1/contacts", None),
        )
        .await,
    )
    .await;
    assert!(!contacts.data.unwrap().is_empty());

    let conversation = decode_response::<ConversationDto>(
        dispatch_request(
            state.clone(),
            addr,
            build_request(
                "POST",
                "/api/v1/conversations/create",
                Some(serde_json::json!({"handle":"bob"})),
            ),
        )
        .await,
    )
    .await;
    let convo_id = conversation.data.unwrap().id;

    let send = decode_response::<SendMessageResponse>(
        dispatch_request(
            state.clone(),
            addr,
            build_request(
                "POST",
                "/api/v1/messages/send",
                Some(serde_json::json!({
                    "conversation_id": convo_id,
                    "kind": "Text",
                    "body": "hi"
                })),
            ),
        )
        .await,
    )
    .await;
    assert_eq!(send.error, None);

    let messages = decode_response::<Vec<MessageDto>>(
        dispatch_request(
            state.clone(),
            addr,
            build_request(
                "GET",
                &format!("/api/v1/conversations/{}/messages", convo_id),
                None,
            ),
        )
        .await,
    )
    .await;
    assert_eq!(messages.data.unwrap().len(), 1);

    let sync = decode_response::<SyncResponse>(
        dispatch_request(
            state.clone(),
            addr,
            build_request("POST", "/api/v1/sync", Some(serde_json::json!({}))),
        )
        .await,
    )
    .await;
    assert!(sync.data.unwrap().next_cursor.is_some());

    let stats = decode_response::<Value>(
        dispatch_request(
            state.clone(),
            addr,
            build_request("GET", "/api/v1/stats", None),
        )
        .await,
    )
    .await;
    assert!(stats.data.unwrap().get("user_id_hex").is_some());

    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn ui_api_messages_pagination_is_deterministic() {
    let _guard = env_guard().await;
    let cfg = test_config(false, false, false);
    let state = build_state(&cfg).await;
    let api_addr = cfg.api.socket_addr().unwrap();
    let (addr, tx, handle) = start_server(state.clone(), api_addr).await;

    let conversation = decode_response::<ConversationDto>(
        dispatch_request(
            state.clone(),
            addr,
            build_request(
                "POST",
                "/api/v1/conversations/create",
                Some(serde_json::json!({"handle":"bob"})),
            ),
        )
        .await,
    )
    .await;
    let convo_id = conversation.data.unwrap().id;

    for body in ["one", "two", "three"] {
        let _ = decode_response::<SendMessageResponse>(
            dispatch_request(
                state.clone(),
                addr,
                build_request(
                    "POST",
                    "/api/v1/messages/send",
                    Some(serde_json::json!({
                        "conversation_id": convo_id,
                        "kind": "Text",
                        "body": body
                    })),
                ),
            )
            .await,
        )
        .await;
    }

    let page_one = decode_response::<Vec<MessageDto>>(
        dispatch_request(
            state.clone(),
            addr,
            build_request(
                "GET",
                &format!(
                    "/api/v1/conversations/{}/messages?cursor=0&limit=2",
                    convo_id
                ),
                None,
            ),
        )
        .await,
    )
    .await;
    let page_one = page_one.data.unwrap();
    assert_eq!(page_one.len(), 2);
    assert_eq!(
        page_one
            .iter()
            .map(|msg| msg.body_preview.clone().unwrap_or_default())
            .collect::<Vec<_>>(),
        vec!["one".to_string(), "two".to_string()]
    );

    let page_two = decode_response::<Vec<MessageDto>>(
        dispatch_request(
            state.clone(),
            addr,
            build_request(
                "GET",
                &format!(
                    "/api/v1/conversations/{}/messages?cursor=2&limit=2",
                    convo_id
                ),
                None,
            ),
        )
        .await,
    )
    .await;
    let page_two = page_two.data.unwrap();
    assert_eq!(page_two.len(), 1);
    assert_eq!(
        page_two[0].body_preview.clone().unwrap_or_default(),
        "three".to_string()
    );

    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn ui_api_sync_cursor_monotonic() {
    let _guard = env_guard().await;
    let cfg = test_config(false, false, false);
    let state = build_state(&cfg).await;
    let api_addr = cfg.api.socket_addr().unwrap();
    let (addr, tx, handle) = start_server(state.clone(), api_addr).await;

    let conversation = decode_response::<ConversationDto>(
        dispatch_request(
            state.clone(),
            addr,
            build_request(
                "POST",
                "/api/v1/conversations/create",
                Some(serde_json::json!({"handle":"bob"})),
            ),
        )
        .await,
    )
    .await;
    let convo_id = conversation.data.unwrap().id;

    let _ = decode_response::<SendMessageResponse>(
        dispatch_request(
            state.clone(),
            addr,
            build_request(
                "POST",
                "/api/v1/messages/send",
                Some(serde_json::json!({
                    "conversation_id": convo_id,
                    "kind": "Text",
                    "body": "first"
                })),
            ),
        )
        .await,
    )
    .await;

    let _ = decode_response::<ContactDto>(
        dispatch_request(
            state.clone(),
            addr,
            build_request(
                "POST",
                "/api/v1/contacts/add",
                Some(serde_json::json!({"handle":"carol"})),
            ),
        )
        .await,
    )
    .await;

    let sync_one = decode_response::<SyncResponse>(
        dispatch_request(
            state.clone(),
            addr,
            build_request(
                "POST",
                "/api/v1/sync",
                Some(serde_json::json!({ "limit": 1 })),
            ),
        )
        .await,
    )
    .await;
    let cursor_one = sync_one.data.unwrap().next_cursor.unwrap();

    let sync_two = decode_response::<SyncResponse>(
        dispatch_request(
            state.clone(),
            addr,
            build_request(
                "POST",
                "/api/v1/sync",
                Some(serde_json::json!({ "cursor": cursor_one, "limit": 1 })),
            ),
        )
        .await,
    )
    .await;
    let cursor_two = sync_two.data.unwrap().next_cursor.unwrap();
    assert!(cursor_two > cursor_one);

    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn ui_error_snapshot_validation() {
    let _guard = env_guard().await;
    let cfg = test_config(false, false, false);
    let state = build_state(&cfg).await;
    let api_addr = cfg.api.socket_addr().unwrap();
    let (addr, tx, handle) = start_server(state.clone(), api_addr).await;

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/send")
        .header(CONTENT_TYPE, "application/json")
        .body(Full::from(Bytes::from("{")))
        .unwrap();
    let resp = dispatch_request(state.clone(), addr, request).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let normalized = normalize_envelope(body);
    let expected = error_fixture(include_str!("fixtures/error_validation.json"));
    assert_eq!(normalized, expected);

    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
}

#[cfg(feature = "ui-auth")]
#[tokio::test]
async fn ui_error_snapshot_auth() {
    let _guard = env_guard().await;
    let cfg = test_config(false, false, false);
    let state = build_state(&cfg).await;
    let api_addr = cfg.api.socket_addr().unwrap();
    let (addr, tx, handle) = start_server(state.clone(), api_addr).await;

    let prev = std::env::var("ENIGMA_UI_TOKEN").ok();
    std::env::set_var("ENIGMA_UI_TOKEN", "token");

    let resp = dispatch_request(
        state.clone(),
        addr,
        build_request("GET", "/api/v1/health", None),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let normalized = normalize_envelope(body);
    let expected = error_fixture(include_str!("fixtures/error_auth.json"));
    assert_eq!(normalized, expected);

    let mut req = build_request("GET", "/api/v1/health", None);
    req.headers_mut()
        .insert("authorization", "Bearer wrong".parse().unwrap());
    let resp = dispatch_request(state.clone(), addr, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let normalized = normalize_envelope(body);
    assert_eq!(normalized, expected);

    if let Some(prev) = prev {
        std::env::set_var("ENIGMA_UI_TOKEN", prev);
    } else {
        std::env::remove_var("ENIGMA_UI_TOKEN");
    }

    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn ui_error_snapshot_not_found() {
    let _guard = env_guard().await;
    let cfg = test_config(false, false, false);
    let state = build_state(&cfg).await;
    let api_addr = cfg.api.socket_addr().unwrap();
    let (addr, tx, handle) = start_server(state.clone(), api_addr).await;

    let resp = dispatch_request(
        state.clone(),
        addr,
        build_request("GET", "/api/v1/does-not-exist", None),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let normalized = normalize_envelope(body);
    let expected = error_fixture(include_str!("fixtures/error_not_found.json"));
    assert_eq!(normalized, expected);

    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn ui_error_snapshot_conflict() {
    let resp = ui_error(StatusCode::CONFLICT, "CONFLICT", "conflict", None);
    let body: Value = serde_json::from_slice(&body_full_bytes(resp).await).unwrap();
    let normalized = normalize_envelope(body);
    let expected = error_fixture(include_str!("fixtures/error_conflict.json"));
    assert_eq!(normalized, expected);
}

#[tokio::test]
async fn ui_error_snapshot_internal() {
    let _guard = env_guard().await;
    let mut cfg = test_config(false, false, false);
    cfg.policy.max_text_bytes = 1;
    let state = build_state(&cfg).await;
    let api_addr = cfg.api.socket_addr().unwrap();
    let (addr, tx, handle) = start_server(state.clone(), api_addr).await;

    let conversation = decode_response::<ConversationDto>(
        dispatch_request(
            state.clone(),
            addr,
            build_request(
                "POST",
                "/api/v1/conversations/create",
                Some(serde_json::json!({"handle":"bob"})),
            ),
        )
        .await,
    )
    .await;
    let convo_id = conversation.data.unwrap().id;

    let resp = dispatch_request(
        state.clone(),
        addr,
        build_request(
            "POST",
            "/api/v1/messages/send",
            Some(serde_json::json!({
                "conversation_id": convo_id,
                "kind": "Text",
                "body": "toolong"
            })),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let normalized = normalize_envelope(body);
    let expected = error_fixture(include_str!("fixtures/error_internal.json"));
    assert_eq!(normalized, expected);

    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn ui_error_invalid_message_kind_is_structured() {
    let _guard = env_guard().await;
    let cfg = test_config(false, false, false);
    let state = build_state(&cfg).await;
    let api_addr = cfg.api.socket_addr().unwrap();
    let (addr, tx, handle) = start_server(state.clone(), api_addr).await;

    let conversation = decode_response::<ConversationDto>(
        dispatch_request(
            state.clone(),
            addr,
            build_request(
                "POST",
                "/api/v1/conversations/create",
                Some(serde_json::json!({"handle":"bob"})),
            ),
        )
        .await,
    )
    .await;
    let convo_id = conversation.data.unwrap().id;

    let resp = dispatch_request(
        state.clone(),
        addr,
        build_request(
            "POST",
            "/api/v1/messages/send",
            Some(serde_json::json!({
                "conversation_id": convo_id,
                "kind": "Nope",
                "body": "hi"
            })),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
    let normalized = normalize_envelope(body);
    assert_eq!(
        normalized
            .get("error")
            .and_then(|err| err.get("code"))
            .and_then(|code| code.as_str()),
        Some("INVALID_MESSAGE_KIND")
    );

    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
}
