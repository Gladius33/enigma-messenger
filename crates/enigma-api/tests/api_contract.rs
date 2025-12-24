use enigma_api::types::{
    AttachmentDescriptor, AttachmentId, ConversationId, IncomingMessageEvent, MessageId,
    MessageKind, OutgoingMessageRequest, OutgoingRecipient, ReceiptStatus, UserIdHex,
};
use serde_json::json;
use uuid::Uuid;

#[test]
fn outgoing_message_request_roundtrip() {
    let request = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: ConversationId {
            value: "conv-1".to_string(),
        },
        sender: UserIdHex {
            value: "sender".to_string(),
        },
        recipients: vec![OutgoingRecipient {
            recipient_user_id: Some("recipient".to_string()),
            recipient_handle: None,
        }],
        kind: MessageKind::Text,
        text: Some("hello".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };
    let encoded = serde_json::to_string(&request).expect("serialize");
    let decoded: OutgoingMessageRequest =
        serde_json::from_str(&encoded).expect("deserialize roundtrip");
    assert_eq!(decoded.client_message_id, request.client_message_id);
    assert_eq!(decoded.conversation_id, request.conversation_id);
    assert_eq!(decoded.kind, MessageKind::Text);
    assert_eq!(decoded.text, Some("hello".to_string()));
    assert!(decoded.attachment.is_none());
}

#[test]
fn incoming_message_event_rejects_unknown_fields() {
    let event = IncomingMessageEvent {
        message_id: MessageId { value: Uuid::nil() },
        conversation_id: ConversationId {
            value: "conv-unknown".to_string(),
        },
        sender: UserIdHex {
            value: "sender".to_string(),
        },
        device_id: None,
        kind: MessageKind::File,
        text: None,
        attachment: Some(AttachmentDescriptor {
            id: AttachmentId { value: Uuid::nil() },
            filename: Some("file.bin".to_string()),
            content_type: "application/octet-stream".to_string(),
            total_size: 8,
        }),
        timestamp: 42,
        receipt: ReceiptStatus::Pending,
        edited: false,
        deleted: false,
    };
    let mut value = json!(event);
    value["unexpected"] = json!(true);
    let err = serde_json::from_value::<IncomingMessageEvent>(value);
    assert!(err.is_err());
}
