use super::{base_config, key_provider, recipient_handle, temp_path};
use crate::config::TransportMode;
use crate::directory::InMemoryRegistry;
use crate::error::CoreError;
use crate::messaging::MockTransport;
use crate::node::DirectoryResolver;
use crate::policy::{Policy, ReceiptAggregation};
use crate::relay::InMemoryRelay;
use crate::time::now_ms;
use crate::{ids::DeviceId, Core};
use async_trait::async_trait;
use enigma_api::types::{
    ConversationId, MessageId, MessageKind, OutgoingMessageRequest, UserIdHex,
};
use enigma_node_types::{PublicIdentity, UserId as NodeUserId};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Default)]
struct ResolverWithDevices {
    devices: Arc<Mutex<Vec<DeviceId>>>,
}

impl ResolverWithDevices {
    fn new(devices: Vec<DeviceId>) -> Self {
        Self {
            devices: Arc::new(Mutex::new(devices)),
        }
    }
}

#[async_trait]
impl DirectoryResolver for ResolverWithDevices {
    async fn resolve_handle(&self, handle: &str) -> Result<(String, PublicIdentity), CoreError> {
        let username = handle.trim().trim_start_matches('@');
        let user_id = NodeUserId::from_username(username)
            .map_err(|_| CoreError::Validation("handle".to_string()))?;
        let identity = PublicIdentity {
            user_id,
            username_hint: Some(username.to_string()),
            signing_public_key: vec![1],
            encryption_public_key: vec![1],
            signature: vec![1],
            created_at_ms: now_ms(),
        };
        Ok((user_id.to_hex(), identity))
    }

    async fn check_user(&self, _handle: &str) -> Result<bool, CoreError> {
        Ok(true)
    }

    async fn announce_presence(&self, _identity: &PublicIdentity) -> Result<(), CoreError> {
        Ok(())
    }

    async fn resolve_devices(
        &self,
        _user_id: &str,
    ) -> Result<Vec<crate::directory::DeviceInfo>, CoreError> {
        let devices = self.devices.lock().await.clone();
        Ok(devices
            .into_iter()
            .map(|d| crate::directory::DeviceInfo {
                device_id: d,
                last_seen_ms: now_ms(),
                hints: None,
            })
            .collect())
    }
}

fn make_devices(count: usize) -> Vec<DeviceId> {
    (0..count).map(|_| DeviceId::new(Uuid::new_v4())).collect()
}

#[tokio::test]
async fn fanout_to_multiple_devices() {
    let transport = MockTransport::new();
    transport.fail_p2p_times(10).await;
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(InMemoryRelay::new());
    let mut policy = Policy::default();
    policy.outbox_batch_send = 0;
    let devices = make_devices(2);
    let resolver = Arc::new(ResolverWithDevices::new(devices.clone()));
    let mut core = Core::init(
        base_config(temp_path("multi"), TransportMode::P2PWebRTC),
        policy.clone(),
        key_provider(),
        registry,
        relay,
        Arc::new(transport),
    )
    .await
    .expect("core");
    core.set_resolver(resolver);
    let conv = ConversationId {
        value: "multi-conv".to_string(),
    };
    let req = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: conv,
        sender: UserIdHex {
            value: core.local_identity().user_id.to_hex(),
        },
        recipients: vec![recipient_handle("@alice")],
        kind: MessageKind::Text,
        text: Some("hi".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };
    core.send_message(req).await.expect("send");
    let pending = core
        .outbox
        .load_all_due(crate::time::now_ms().saturating_add(2_000), 8)
        .await
        .expect("outbox");
    assert_eq!(pending.len(), 2);
    let mut seen = Vec::new();
    for item in pending {
        let dev = item.recipient_device_id.clone().expect("device");
        seen.push(dev.as_uuid());
    }
    assert_eq!(seen.len(), 2);
    assert_eq!(policy.receipt_aggregation, ReceiptAggregation::Any);
    let msg_id = MessageId::random();
    core.mark_device_delivered(&msg_id.value, "alice", DeviceId::new(seen[0]))
        .await
        .expect("mark");
    let delivered = core
        .aggregated_delivered(&msg_id.value, "alice", &devices)
        .await;
    assert!(delivered);
}

#[tokio::test]
async fn fallback_to_single_device_when_unknown() {
    let transport = MockTransport::new();
    transport.fail_p2p_times(5).await;
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(InMemoryRelay::new());
    let mut policy = Policy::default();
    policy.outbox_batch_send = 0;
    policy.directory_refresh_on_send = true;
    let resolver = Arc::new(ResolverWithDevices::new(Vec::new()));
    let mut core = Core::init(
        base_config(temp_path("multi-fallback"), TransportMode::P2PWebRTC),
        policy,
        key_provider(),
        registry,
        relay,
        Arc::new(transport),
    )
    .await
    .expect("core");
    core.set_resolver(resolver);
    let conv = ConversationId {
        value: "multi-fallback".to_string(),
    };
    let req = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: conv,
        sender: UserIdHex {
            value: core.local_identity().user_id.to_hex(),
        },
        recipients: vec![recipient_handle("@bob")],
        kind: MessageKind::Text,
        text: Some("hello".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };
    core.send_message(req).await.expect("send");
    let pending = core
        .outbox
        .load_all_due(crate::time::now_ms().saturating_add(2_000), 4)
        .await
        .expect("outbox");
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0]
            .recipient_device_id
            .clone()
            .unwrap_or_else(DeviceId::nil)
            .as_uuid(),
        Uuid::nil()
    );
}
