use enigma_ui_api::{
    ApiError, ApiMeta, ApiResponse, ConversationDto, ConversationKind, DeviceInfo, IdentityInfo,
    MessageDto, MessageStatus, SendMessageRequest, SendMessageResponse,
};
use serde_json::json;
use uuid::Uuid;

#[test]
fn error_envelope_serialization_stable() {
    let resp: ApiResponse<serde_json::Value> = ApiResponse {
        meta: ApiMeta {
            api_version: enigma_ui_api::API_VERSION,
            request_id: Uuid::nil(),
            timestamp_ms: 0,
        },
        data: None,
        error: Some(ApiError {
            code: "NOT_FOUND".to_string(),
            message: "not found".to_string(),
            details: None,
        }),
    };
    let value = serde_json::to_value(resp).unwrap();
    let expected = json!({
        "meta": {
            "api_version": enigma_ui_api::API_VERSION,
            "request_id": Uuid::nil(),
            "timestamp_ms": 0
        },
        "error": {
            "code": "NOT_FOUND",
            "message": "not found"
        }
    });
    assert_eq!(value, expected);
}

#[test]
fn health_envelope_serialization_stable() {
    let resp = ApiResponse {
        meta: ApiMeta {
            api_version: enigma_ui_api::API_VERSION,
            request_id: Uuid::nil(),
            timestamp_ms: 0,
        },
        data: Some(json!({"status":"ok"})),
        error: None,
    };
    let value = serde_json::to_value(resp).unwrap();
    let expected = json!({
        "meta": {
            "api_version": enigma_ui_api::API_VERSION,
            "request_id": Uuid::nil(),
            "timestamp_ms": 0
        },
        "data": {
            "status": "ok"
        }
    });
    assert_eq!(value, expected);
}

#[test]
fn identity_serialization_stable() {
    let identity = IdentityInfo {
        user_id: "user".to_string(),
        handle: Some("alice".to_string()),
        devices: vec![DeviceInfo {
            device_id: "device".to_string(),
            last_seen_ms: 0,
        }],
        has_bundle_v2: true,
        created_ms: 1,
    };
    let value = serde_json::to_value(identity).unwrap();
    let expected = json!({
        "user_id": "user",
        "handle": "alice",
        "devices": [
            {
                "device_id": "device",
                "last_seen_ms": 0
            }
        ],
        "has_bundle_v2": true,
        "created_ms": 1
    });
    assert_eq!(value, expected);
}

#[test]
fn send_message_serialization_stable() {
    let request = SendMessageRequest {
        conversation_id: "conv".to_string(),
        kind: "Text".to_string(),
        body: Some("hello".to_string()),
    };
    let response = SendMessageResponse {
        message_id: "msg".to_string(),
        status: MessageStatus::Sent,
    };
    let req_value = serde_json::to_value(request).unwrap();
    let res_value = serde_json::to_value(response).unwrap();
    assert_eq!(
        req_value,
        json!({
            "conversation_id": "conv",
            "kind": "Text",
            "body": "hello"
        })
    );
    assert_eq!(
        res_value,
        json!({
            "message_id": "msg",
            "status": "Sent"
        })
    );
}

#[test]
fn conversation_list_item_serialization_stable() {
    let dto = ConversationDto {
        id: "conv".to_string(),
        kind: ConversationKind::Direct,
        title: None,
        members: vec!["user".to_string()],
        unread_count: 0,
        last_message: None,
    };
    let value = serde_json::to_value(dto).unwrap();
    let expected = json!({
        "id": "conv",
        "kind": "Direct",
        "title": null,
        "members": ["user"],
        "unread_count": 0
    });
    assert_eq!(value, expected);
}

#[test]
fn message_serialization_stable() {
    let dto = MessageDto {
        id: "msg".to_string(),
        conversation_id: "conv".to_string(),
        sender: "user".to_string(),
        sent_ms: 0,
        edited_ms: None,
        kind: "Text".to_string(),
        body_preview: Some("preview".to_string()),
        attachments_meta: None,
        status: MessageStatus::Delivered,
    };
    let value = serde_json::to_value(dto).unwrap();
    let expected = json!({
        "id": "msg",
        "conversation_id": "conv",
        "sender": "user",
        "sent_ms": 0,
        "kind": "Text",
        "body_preview": "preview",
        "status": "Delivered"
    });
    assert_eq!(value, expected);
}
