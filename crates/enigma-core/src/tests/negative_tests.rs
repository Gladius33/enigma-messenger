use super::{base_config, key_provider, temp_path};
use crate::config::TransportMode;
use crate::directory::InMemoryRegistry;
use crate::messaging::MockTransport;
use crate::packet::deserialize_envelope;
use crate::policy::Policy;
use crate::relay::InMemoryRelay;
use crate::Core;
use enigma_api::types::{
    AttachmentDescriptor, AttachmentId, ConversationId, MessageId, MessageKind,
    OutgoingMessageRequest, UserIdHex,
};
use serde_json::json;
use std::sync::Arc;

#[tokio::test]
async fn oversize_text_is_rejected() {
    let mut policy = Policy::default();
    policy.max_text_bytes = 4;
    let transport = MockTransport::new();
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(InMemoryRelay::new());
    let core = Core::init(
        base_config(temp_path("neg"), TransportMode::P2PWebRTC),
        policy,
        key_provider(),
        registry,
        relay,
        Arc::new(transport),
    )
    .await
    .expect("core");
    let req = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: ConversationId {
            value: "neg".to_string(),
        },
        sender: UserIdHex {
            value: core.local_identity().user_id.to_hex(),
        },
        recipients: vec![UserIdHex {
            value: core.local_identity().user_id.to_hex(),
        }],
        kind: MessageKind::Text,
        text: Some("toolong".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };
    let result = core.send_message(req).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn attachments_disabled_policy() {
    let mut config = base_config(temp_path("neg2"), TransportMode::Hybrid);
    config.allow_attachments = false;
    let policy = Policy::default();
    let transport = MockTransport::new();
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(InMemoryRelay::new());
    let core = Core::init(
        config,
        policy,
        key_provider(),
        registry,
        relay,
        Arc::new(transport),
    )
    .await
    .expect("core");
    let descriptor = AttachmentDescriptor {
        id: AttachmentId::random(),
        filename: None,
        content_type: "application/octet-stream".to_string(),
        total_size: 10,
    };
    let req = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: ConversationId {
            value: "neg2".to_string(),
        },
        sender: UserIdHex {
            value: core.local_identity().user_id.to_hex(),
        },
        recipients: vec![UserIdHex {
            value: core.local_identity().user_id.to_hex(),
        }],
        kind: MessageKind::File,
        text: None,
        attachment: Some(descriptor),
        attachment_bytes: Some(vec![1, 2, 3]),
        ephemeral_expiry_secs: None,
        metadata: Some(json!({"note": "test"})),
    };
    let result = core.send_message(req).await;
    assert!(result.is_err());
}

#[test]
fn invalid_packet_is_rejected() {
    let result = deserialize_envelope(b"not-json");
    assert!(result.is_err());
}
