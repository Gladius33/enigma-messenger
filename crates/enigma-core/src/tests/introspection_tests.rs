use super::{base_config, key_provider, temp_path};
use crate::config::TransportMode;
use crate::directory::InMemoryRegistry;
use crate::messaging::MockTransport;
use crate::policy::Policy;
use crate::relay::InMemoryRelay;
use crate::time::now_ms;
use crate::Core;
use std::sync::Arc;

#[tokio::test]
async fn stats_and_health_work() {
    let transport = MockTransport::new();
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(InMemoryRelay::new());
    let config = base_config(temp_path("introspection"), TransportMode::P2PWebRTC);

    let core = Core::init(
        config.clone(),
        Policy::default(),
        key_provider(),
        registry,
        relay,
        Arc::new(transport),
    )
    .await
    .expect("core init");

    core.create_group("devs".to_string()).await.expect("group");
    core.create_channel("updates".to_string())
        .await
        .expect("channel");

    let stats = core.stats().await;
    assert_eq!(stats.user_id_hex, core.local_identity().user_id.to_hex());
    assert_eq!(stats.device_id, core.local_identity().device_id);
    assert_eq!(stats.groups, 1);
    assert_eq!(stats.channels, 1);
    assert_eq!(stats.conversations, 2);
    assert_eq!(stats.pending_outbox, 0);

    let health = core.store_health().await;
    assert_eq!(health.namespace, config.namespace);
    assert!(health.ok);

    let registry_status = core.registry_status().await;
    assert!(registry_status.endpoints.is_empty());
    assert_eq!(core.directory_len().await, 0);

    core.directory
        .add_or_update_contact(
            "@self",
            &core.local_identity().user_id.to_hex(),
            None,
            now_ms(),
        )
        .await
        .expect("contact");

    assert_eq!(core.directory_len().await, 1);
}
