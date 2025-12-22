use super::{base_config, key_provider, temp_path};
use crate::config::TransportMode;
use crate::directory::InMemoryRegistry;
use crate::messaging::MockTransport;
use crate::policy::Policy;
use crate::relay::InMemoryRelay;
use crate::Core;
use std::sync::Arc;

#[tokio::test]
async fn identity_persists_across_reload() {
    let path = temp_path("identity");
    let mut config = base_config(path.clone(), TransportMode::Hybrid);
    config.polling_interval_ms = 0;
    let mut policy = Policy::default();
    policy.outbox_batch_send = 0;
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(InMemoryRelay::new());
    let transport = MockTransport::new();
    let core_one = Core::init(
        config.clone(),
        policy.clone(),
        key_provider(),
        registry.clone(),
        relay.clone(),
        Arc::new(transport.clone()),
    )
    .await
    .expect("init one");
    let identity_one = core_one.local_identity();
    drop(core_one);
    let core_two = Core::init(
        config,
        policy,
        key_provider(),
        registry,
        relay,
        Arc::new(transport),
    )
    .await
    .expect("init two");
    let identity_two = core_two.local_identity();
    assert_eq!(identity_one.device_id, identity_two.device_id);
    assert_eq!(identity_one.user_id, identity_two.user_id);
}
