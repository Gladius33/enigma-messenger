use super::{base_config, key_provider, temp_path};
use crate::config::TransportMode;
use crate::policy::Policy;
use crate::Core;
use crate::messaging::MockTransport;
use enigma_api::types::{ConversationId, MessageId, MessageKind, OutgoingMessageRequest, UserIdHex};
use enigma_node_client::InMemoryRegistry;
use enigma_relay::{InMemoryRelay, RelayClient};
use std::sync::Arc;

#[tokio::test]
async fn relay_pull_and_ack_flow() {
    let relay = Arc::new(InMemoryRelay::new());
    let registry = Arc::new(InMemoryRegistry::new());
    let transport = MockTransport::new();
    let core_a = Core::init(
        base_config(temp_path("relay-a"), TransportMode::RelayOnly),
        Policy::default(),
        key_provider(),
        registry.clone(),
        relay.clone(),
        Arc::new(transport.clone()),
    )
    .await
    .expect("core a");
    let core_b = Core::init(
        base_config(temp_path("relay-b"), TransportMode::RelayOnly),
        Policy::default(),
        key_provider(),
        registry,
        relay.clone(),
        Arc::new(transport.clone()),
    )
    .await
    .expect("core b");
    let conv = core_a.dm_conversation(&core_b.local_identity().user_id);
    let mut rx_b = core_b.subscribe();
    let req = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: ConversationId { value: conv.value.clone() },
        sender: UserIdHex { value: core_a.local_identity().user_id.to_hex() },
        recipients: vec![UserIdHex { value: core_b.local_identity().user_id.to_hex() }],
        kind: MessageKind::Text,
        text: Some("offline".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };
    core_a.send_message(req).await.expect("send");
    core_b.poll_once().await.expect("process relay");
    let event = rx_b.recv().await.expect("event");
    assert_eq!(event.text.as_deref(), Some("offline"));
    let remaining = relay.pull(&core_b.local_identity().user_id.to_hex()).await.expect("pull");
    assert!(remaining.is_empty());
}
