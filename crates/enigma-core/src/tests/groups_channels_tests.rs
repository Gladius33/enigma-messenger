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
use std::sync::Arc;

#[tokio::test]
async fn group_and_channel_rules_apply() {
    let transport = MockTransport::new();
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(InMemoryRelay::new());
    let core_a = Core::init(
        base_config(temp_path("group-a"), TransportMode::P2PWebRTC),
        Policy::default(),
        key_provider(),
        registry.clone(),
        relay.clone(),
        Arc::new(transport.clone()),
    )
    .await
    .expect("core a");
    let core_b = Core::init(
        base_config(temp_path("group-b"), TransportMode::P2PWebRTC),
        Policy::default(),
        key_provider(),
        registry,
        relay,
        Arc::new(transport.clone()),
    )
    .await
    .expect("core b");
    let mut rx_b = core_b.subscribe();
    let group_id = core_a
        .create_group("team".to_string())
        .await
        .expect("group");
    core_a
        .add_group_member(
            &group_id,
            UserIdHex {
                value: core_b.local_identity().user_id.to_hex(),
            },
        )
        .await
        .expect("add member");
    let group_req = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: ConversationId {
            value: group_id.value.clone(),
        },
        sender: UserIdHex {
            value: core_a.local_identity().user_id.to_hex(),
        },
        recipients: vec![recipient_user(&core_b.local_identity().user_id.to_hex())],
        kind: MessageKind::Text,
        text: Some("hello group".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };
    core_a.send_message(group_req).await.expect("group send");
    core_b.poll_once().await.expect("poll group");
    let event = rx_b.recv().await.expect("group event");
    assert_eq!(event.text.as_deref(), Some("hello group"));
    let channel_id = core_a
        .create_channel("updates".to_string())
        .await
        .expect("channel");
    let bad_req = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: ConversationId {
            value: channel_id.value.clone(),
        },
        sender: UserIdHex {
            value: core_b.local_identity().user_id.to_hex(),
        },
        recipients: vec![recipient_user(&core_a.local_identity().user_id.to_hex())],
        kind: MessageKind::ChannelPost,
        text: Some("blocked".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };
    let result = core_b.send_message(bad_req).await;
    assert!(result.is_err());
}
