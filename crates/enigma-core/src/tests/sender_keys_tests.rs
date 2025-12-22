use super::{base_config, key_provider, recipient_user, temp_path};
use crate::config::TransportMode;
use crate::directory::{DeviceInfo, InMemoryRegistry};
use crate::ids::DeviceId;
use crate::packet::{deserialize_envelope, WireEnvelope};
use crate::messaging::MockTransport;
use crate::node::DirectoryResolver;
use crate::policy::{GroupCryptoMode, Policy};
use crate::relay::InMemoryRelay;
use crate::time::now_ms;
use crate::Core;
use async_trait::async_trait;
use enigma_api::types::{
    ConversationId, MessageId, MessageKind, OutgoingMessageRequest, UserIdHex,
};
use enigma_node_types::{PublicIdentity, UserId as NodeUserId};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone)]
struct MockResolver {
    devices: Arc<Mutex<Vec<DeviceId>>>,
}

impl MockResolver {
    fn new(devices: Vec<DeviceId>) -> Self {
        Self {
            devices: Arc::new(Mutex::new(devices)),
        }
    }
}

#[async_trait]
impl DirectoryResolver for MockResolver {
    async fn resolve_handle(&self, handle: &str) -> Result<(String, PublicIdentity), crate::error::CoreError> {
        let username = handle.trim().trim_start_matches('@');
        let user_id = NodeUserId::from_username(username)
            .map_err(|_| crate::error::CoreError::Validation("handle".to_string()))?;
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

    async fn check_user(&self, _handle: &str) -> Result<bool, crate::error::CoreError> {
        Ok(true)
    }

    async fn announce_presence(&self, _identity: &PublicIdentity) -> Result<(), crate::error::CoreError> {
        Ok(())
    }

    async fn resolve_devices(
        &self,
        _user_id: &str,
    ) -> Result<Vec<DeviceInfo>, crate::error::CoreError> {
        let devices = self.devices.lock().await.clone();
        Ok(devices
            .into_iter()
            .map(|d| DeviceInfo {
                device_id: d,
                last_seen_ms: now_ms(),
                hints: None,
            })
            .collect())
    }
}

fn devices(count: usize) -> Vec<DeviceId> {
    (0..count).map(|_| DeviceId::new(Uuid::new_v4())).collect()
}

fn member_id(username: &str) -> UserIdHex {
    UserIdHex {
        value: NodeUserId::from_username(username)
            .expect("user")
            .to_hex(),
    }
}

#[tokio::test]
async fn sender_keys_distribution_and_single_ciphertext() {
    let transport = MockTransport::new();
    transport.fail_p2p_times(50).await;
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(InMemoryRelay::new());
    let mut policy = Policy::default();
    policy.group_crypto_mode = GroupCryptoMode::SenderKeys;
    policy.outbox_batch_send = 0;
    let resolver = Arc::new(MockResolver::new(devices(2)));
    let mut core = Core::init(
        base_config(temp_path("sender-keys"), TransportMode::P2PWebRTC),
        policy,
        key_provider(),
        registry,
        relay,
        Arc::new(transport),
    )
    .await
    .expect("core");
    core.set_resolver(resolver);
    let group_id = core
        .create_group("team".to_string())
        .await
        .expect("group");
    let member_a = member_id("alice");
    let member_b = member_id("bob");
    core.add_group_member(&group_id, member_a.clone())
        .await
        .expect("member a");
    core.add_group_member(&group_id, member_b.clone())
        .await
        .expect("member b");
    let req = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: ConversationId {
            value: group_id.value.clone(),
        },
        sender: UserIdHex {
            value: core.local_identity().user_id.to_hex(),
        },
        recipients: vec![recipient_user(&member_a.value)],
        kind: MessageKind::Text,
        text: Some("hi team".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };
    core.send_message(req).await.expect("send");
    let pending = core
        .outbox
        .load_all_due(now_ms().saturating_add(5_000), 64)
        .await
        .expect("outbox");
    let mut distribution = 0;
    let mut group_packets = Vec::new();
    for item in pending.iter() {
        if let Ok(WireEnvelope::Message(frame)) = deserialize_envelope(&item.packet) {
            if frame.group_sender_key_id.is_some() {
                group_packets.push(item.packet.clone());
            } else {
                distribution += 1;
            }
        }
    }
    assert_eq!(distribution, 4);
    assert_eq!(group_packets.len(), 4);
    let first = group_packets.first().expect("group packet");
    for pkt in group_packets.iter() {
        assert_eq!(pkt, first);
    }
}

#[tokio::test]
async fn rotate_on_membership_change() {
    let transport = MockTransport::new();
    transport.fail_p2p_times(50).await;
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(InMemoryRelay::new());
    let mut policy = Policy::default();
    policy.group_crypto_mode = GroupCryptoMode::SenderKeys;
    policy.outbox_batch_send = 0;
    let resolver = Arc::new(MockResolver::new(devices(1)));
    let mut core = Core::init(
        base_config(temp_path("sender-keys-rotate"), TransportMode::P2PWebRTC),
        policy,
        key_provider(),
        registry,
        relay,
        Arc::new(transport),
    )
    .await
    .expect("core");
    core.set_resolver(resolver);
    let group_id = core
        .create_group("crew".to_string())
        .await
        .expect("group");
    let member_a = member_id("alice");
    let member_b = member_id("bob");
    core.add_group_member(&group_id, member_a.clone())
        .await
        .expect("a");
    let first_req = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: ConversationId {
            value: group_id.value.clone(),
        },
        sender: UserIdHex {
            value: core.local_identity().user_id.to_hex(),
        },
        recipients: vec![recipient_user(&member_a.value)],
        kind: MessageKind::Text,
        text: Some("first".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };
    core.send_message(first_req).await.expect("first");
    let first_items = core
        .outbox
        .load_all_due(now_ms().saturating_add(5_000), 32)
        .await
        .expect("outbox");
    let first_key = first_items
        .iter()
        .filter_map(|item| {
            deserialize_envelope(&item.packet).ok().and_then(|env| {
                    if let WireEnvelope::Message(frame) = env {
                        frame.group_sender_key_id
                    } else {
                        None
                    }
                })
        })
        .next()
        .expect("sender key id");
    core.add_group_member(&group_id, member_b.clone())
        .await
        .expect("b");
    let second_req = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: ConversationId {
            value: group_id.value.clone(),
        },
        sender: UserIdHex {
            value: core.local_identity().user_id.to_hex(),
        },
        recipients: vec![recipient_user(&member_b.value)],
        kind: MessageKind::Text,
        text: Some("second".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };
    core.send_message(second_req).await.expect("second");
    let second_items = core
        .outbox
        .load_all_due(now_ms().saturating_add(5_000), 64)
        .await
        .expect("outbox second");
    let second_key = second_items
        .iter()
        .filter_map(|item| {
            deserialize_envelope(&item.packet).ok().and_then(|env| {
                if let WireEnvelope::Message(frame) = env {
                    if frame.conversation_id == group_id.value {
                        return frame.group_sender_key_id;
                    }
                }
                None
            })
        })
        .max()
        .expect("sender key id 2");
    assert!(second_key > first_key);
}

#[tokio::test]
async fn pending_when_key_missing_then_reprocess() {
    let transport = MockTransport::new();
    transport.fail_p2p_times(50).await;
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(InMemoryRelay::new());
    let mut policy = Policy::default();
    policy.group_crypto_mode = GroupCryptoMode::SenderKeys;
    policy.outbox_batch_send = 0;
    let resolver = Arc::new(MockResolver::new(Vec::new()));
    let mut sender = Core::init(
        base_config(temp_path("sender-keys-pending-s"), TransportMode::P2PWebRTC),
        policy.clone(),
        key_provider(),
        Arc::new(InMemoryRegistry::new()),
        Arc::new(InMemoryRelay::new()),
        Arc::new(transport.clone()),
    )
    .await
    .expect("sender");
    sender.set_resolver(resolver.clone());
    let mut recipient = Core::init(
        base_config(temp_path("sender-keys-pending-r"), TransportMode::P2PWebRTC),
        policy,
        key_provider(),
        registry,
        relay,
        Arc::new(transport),
    )
    .await
    .expect("recipient");
    recipient.set_resolver(resolver);
    let group_id = sender
        .create_group("crew".to_string())
        .await
        .expect("group");
    let recipient_id = UserIdHex {
        value: recipient.local_identity().user_id.to_hex(),
    };
    sender
        .add_group_member(&group_id, recipient_id.clone())
        .await
        .expect("add");
    let req = OutgoingMessageRequest {
        client_message_id: MessageId::random(),
        conversation_id: ConversationId {
            value: group_id.value.clone(),
        },
        sender: UserIdHex {
            value: sender.local_identity().user_id.to_hex(),
        },
        recipients: vec![recipient_user(&recipient_id.value)],
        kind: MessageKind::Text,
        text: Some("hello pending".to_string()),
        attachment: None,
        attachment_bytes: None,
        ephemeral_expiry_secs: None,
        metadata: None,
    };
    sender.send_message(req).await.expect("send");
    let items = sender
        .outbox
        .load_all_due(now_ms().saturating_add(5_000), 16)
        .await
        .expect("outbox");
    let mut group_packet = None;
    let mut dist_packet = None;
    for item in items.iter() {
        if let Ok(WireEnvelope::Message(frame)) = deserialize_envelope(&item.packet) {
            if frame.group_sender_key_id.is_some() {
                group_packet = Some(item.packet.clone());
            } else if dist_packet.is_none() {
                dist_packet = Some(item.packet.clone());
            }
        }
    }
    let mut rx = recipient.subscribe();
    let group_bytes = group_packet.expect("group packet");
    let dist_bytes = dist_packet.expect("distribution");
    assert!(recipient.inject_incoming(group_bytes.clone()).await.is_err());
    assert!(rx.try_recv().is_err());
    recipient
        .inject_incoming(dist_bytes.clone())
        .await
        .expect("dist");
    let event = rx.recv().await.expect("event");
    assert_eq!(event.text.as_deref(), Some("hello pending"));
}
