use super::*;
use serde::Deserialize;

#[derive(Deserialize)]
struct Envelope<T> {
    meta: serde_json::Value,
    data: Option<T>,
    error: Option<serde_json::Value>,
}

async fn body_bytes(resp: Response<Incoming>) -> Vec<u8> {
    collect_bytes(resp.into_body()).await.unwrap().to_vec()
}

#[tokio::test]
async fn ui_health_identity_contacts_flow() {
    let cfg = test_config(false, false, false);
    let state = build_state(&cfg).await;
    let health = dispatch_request(
        state.clone(),
        None,
        build_request("GET", "/api/v1/health", None),
    )
    .await;
    assert_eq!(health.status(), StatusCode::OK);
    let health_body: Envelope<serde_json::Value> =
        serde_json::from_slice(&body_bytes(health).await).unwrap();
    assert!(health_body.error.is_none());
    assert_eq!(
        health_body.meta.get("api_version").and_then(|v| v.as_u64()),
        Some(enigma_ui_api::API_VERSION as u64)
    );

    let identity = dispatch_request(
        state.clone(),
        None,
        build_request("GET", "/api/v1/identity", None),
    )
    .await;
    assert_eq!(identity.status(), StatusCode::OK);
    let body: Envelope<serde_json::Value> =
        serde_json::from_slice(&body_bytes(identity).await).unwrap();
    assert!(body.data.is_some());

    let add_contact = dispatch_request(
        state.clone(),
        None,
        build_request(
            "POST",
            "/api/v1/contacts/add",
            Some(serde_json::json!({"handle":"bob"})),
        ),
    )
    .await;
    assert_eq!(add_contact.status(), StatusCode::OK);
    let add_body: Envelope<serde_json::Value> =
        serde_json::from_slice(&body_bytes(add_contact).await).unwrap();
    assert!(add_body.error.is_none());

    let contacts = dispatch_request(
        state.clone(),
        None,
        build_request("GET", "/api/v1/contacts", None),
    )
    .await;
    assert_eq!(contacts.status(), StatusCode::OK);
    let list: Envelope<Vec<serde_json::Value>> =
        serde_json::from_slice(&body_bytes(contacts).await).unwrap();
    assert!(!list.data.unwrap().is_empty());

    let conversation = dispatch_request(
        state.clone(),
        None,
        build_request(
            "POST",
            "/api/v1/conversations/create",
            Some(serde_json::json!({"handle":"bob"})),
        ),
    )
    .await;
    assert_eq!(conversation.status(), StatusCode::OK);
    let convo_body: Envelope<serde_json::Value> =
        serde_json::from_slice(&body_bytes(conversation).await).unwrap();
    let convo_id = convo_body
        .data
        .unwrap()
        .get("id")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    assert!(convo_body.error.is_none());
    assert!(convo_body.meta.get("request_id").is_some());

    let send = dispatch_request(
        state.clone(),
        None,
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
    .await;
    assert_eq!(send.status(), StatusCode::OK);
    let send_body: Envelope<serde_json::Value> =
        serde_json::from_slice(&body_bytes(send).await).unwrap();
    assert!(send_body.error.is_none());

    let messages = dispatch_request(
        state.clone(),
        None,
        build_request(
            "GET",
            &format!("/api/v1/conversations/{}/messages", convo_id),
            None,
        ),
    )
    .await;
    assert_eq!(messages.status(), StatusCode::OK);
    let msgs: Envelope<Vec<serde_json::Value>> =
        serde_json::from_slice(&body_bytes(messages).await).unwrap();
    assert_eq!(msgs.data.unwrap().len(), 1);

    let sync = dispatch_request(
        state.clone(),
        None,
        build_request("POST", "/api/v1/sync", Some(serde_json::json!({}))),
    )
    .await;
    assert_eq!(sync.status(), StatusCode::OK);
    let sync_body: Envelope<serde_json::Value> =
        serde_json::from_slice(&body_bytes(sync).await).unwrap();
    assert!(sync_body.error.is_none());
}

#[tokio::test]
async fn ui_errors_are_structured() {
    let cfg = test_config(false, false, false);
    let state = build_state(&cfg).await;
    let resp = dispatch_request(
        state.clone(),
        None,
        build_request(
            "POST",
            "/api/v1/messages/send",
            Some(serde_json::json!({
                "conversation_id": "missing",
                "kind": "Text",
                "body": "hi"
            })),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: Envelope<serde_json::Value> =
        serde_json::from_slice(&body_bytes(resp).await).unwrap();
    assert!(body.data.is_none());
    assert!(body.error.is_some());
    assert!(body.meta.get("timestamp_ms").is_some());
}
