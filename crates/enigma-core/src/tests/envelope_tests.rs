use super::{base_config, key_provider, temp_path};
use crate::config::TransportMode;
use crate::directory::InMemoryRegistry;
use crate::directory::RegistryClient;
use crate::envelope_crypto::{decrypt_identity_envelope, requester_keypair};
use crate::messaging::MockTransport;
use crate::policy::Policy;
use crate::relay::InMemoryRelay;
use crate::Core;
use enigma_node_types::UserId;
use std::sync::Arc;

#[tokio::test]
async fn register_stores_ciphertext() {
    let mut cfg = base_config(temp_path("env-reg"), TransportMode::Hybrid);
    cfg.user_handle = "alice".to_string();
    cfg.polling_interval_ms = 0;
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(InMemoryRelay::new());
    let transport = MockTransport::new();
    let core = Core::init(
        cfg,
        Policy::default(),
        key_provider(),
        registry.clone(),
        relay,
        Arc::new(transport),
    )
    .await
    .expect("init");
    let (secret, pubkey) = requester_keypair();
    let envelope = registry
        .resolve(&core.local_identity().user_id.to_hex(), pubkey)
        .await
        .unwrap()
        .expect("envelope");
    let identity_bytes = serde_json::to_vec(&core.local_identity().public_identity).unwrap();
    assert_ne!(envelope.ciphertext, identity_bytes);
    let user = UserId::from_hex(&core.local_identity().user_id.to_hex()).unwrap();
    let decrypted = decrypt_identity_envelope(
        registry.envelope_pepper().unwrap(),
        &envelope,
        secret,
        &user,
    )
    .expect("decrypt");
    assert_eq!(decrypted.user_id.to_hex(), user.to_hex());
}

#[tokio::test]
async fn resolve_envelope_roundtrip() {
    let mut cfg = base_config(temp_path("env-resolve"), TransportMode::Hybrid);
    cfg.user_handle = "bob".to_string();
    cfg.polling_interval_ms = 0;
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(InMemoryRelay::new());
    let transport = MockTransport::new();
    let core = Core::init(
        cfg,
        Policy::default(),
        key_provider(),
        registry.clone(),
        relay,
        Arc::new(transport),
    )
    .await
    .expect("init");
    let (secret, requester) = requester_keypair();
    let envelope = registry
        .resolve(&core.local_identity().user_id.to_hex(), requester)
        .await
        .expect("request")
        .expect("envelope");
    let decrypted = decrypt_identity_envelope(
        registry.envelope_pepper().unwrap(),
        &envelope,
        secret,
        &core.local_identity().public_identity.user_id,
    )
    .expect("decrypt");
    assert_eq!(
        decrypted.user_id,
        core.local_identity().public_identity.user_id
    );
}
