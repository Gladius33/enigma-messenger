use super::{base_config, key_provider, recipient_user, temp_path};
use crate::config::TransportMode;
use crate::directory::InMemoryRegistry;
use crate::messaging::MockTransport;
use crate::policy::Policy;
use crate::relay::InMemoryRelay;
use crate::Core;
use enigma_api::types::{
    ConversationId, MessageId, MessageKind, OutgoingMessageRequest, UserIdHex,
};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn send_and_receive_text_with_edits_and_deletes() {
    let transport = MockTransport::new();
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(InMemoryRelay::new());
    let core_a = Core::init(
        base_config(temp_path("msg-a"), TransportMode::P2PWebRTC),
        Policy::default(),
        key_provider(),
        registry.clone(),
        relay.clone(),
        Arc::new(transport.clone()),
    )
    .await
    .expect("core a");
    let core_b = Core::init(
        base_config(temp_path("msg-b"), TransportMode::P2PWebRTC),
        Policy::default(),
        key_provider(),
        registry,
        relay,
        Arc::new(transport.clone()),
    )
    .await
    .expect("core b");
    let conv = core_a.dm_conversation(&core_b.local_identity().user_id);
    let mut rx_b = core_b.subscribe();
    let req = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: ConversationId {
            value: conv.value.clone(),
        },
        sender: UserIdHex {
            value: core_a.local_identity().user_id.to_hex(),
        },
        recipients: vec![recipient_user(&core_b.local_identity().user_id.to_hex())],
        kind: MessageKind::Text,
        text: Some("hello".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };
    core_a.send_message(req).await.expect("send text");
    core_b.poll_once().await.expect("poll b");
    let event = rx_b.recv().await.expect("event");
    assert_eq!(event.text.as_deref(), Some("hello"));
    assert!(!event.edited);
    assert!(!event.deleted);
    let edit_req = OutgoingMessageRequest {
        client_message_id: event.message_id.clone(),
        conversation_id: ConversationId {
            value: conv.value.clone(),
        },
        sender: UserIdHex {
            value: core_a.local_identity().user_id.to_hex(),
        },
        recipients: vec![recipient_user(&core_b.local_identity().user_id.to_hex())],
        kind: MessageKind::Text,
        text: Some("hello-edited".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: Some(json!({"edited": true})),
    };
    core_a.send_message(edit_req).await.expect("send edit");
    core_b.poll_once().await.expect("poll b edit");
    let edited = rx_b.recv().await.expect("edited");
    assert!(edited.edited);
    let delete_req = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: ConversationId {
            value: conv.value.clone(),
        },
        sender: UserIdHex {
            value: core_a.local_identity().user_id.to_hex(),
        },
        recipients: vec![recipient_user(&core_b.local_identity().user_id.to_hex())],
        kind: MessageKind::System,
        text: None,
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: Some(json!({"deleted": true})),
    };
    core_a.send_message(delete_req).await.expect("send delete");
    core_b.poll_once().await.expect("poll b delete");
    let deleted = rx_b.recv().await.expect("deleted");
    assert!(deleted.deleted);
}
