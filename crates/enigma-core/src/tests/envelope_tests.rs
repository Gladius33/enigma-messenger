use super::{base_config, key_provider, temp_path};
use crate::config::TransportMode;
use crate::directory::InMemoryRegistry;
use crate::envelope_crypto::decrypt_identity_envelope;
use crate::messaging::MockTransport;
use crate::policy::Policy;
use crate::relay::InMemoryRelay;
use crate::Core;
use enigma_node_types::MAX_IDENTITY_CIPHERTEXT;
use std::sync::Arc;
use x25519_dalek::{PublicKey, StaticSecret};

#[tokio::test]
async fn register_stores_ciphertext() {
    let mut cfg = base_config(temp_path("env-reg"), TransportMode::Hybrid);
    cfg.device_name = Some("alice".to_string());
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
    let stored = registry.stored_envelopes().await;
    assert_eq!(stored.len(), 1);
    let ciphertext = &stored[0].ciphertext;
    let identity_bytes = serde_json::to_vec(&core.local_identity().public_identity).unwrap();
    assert_ne!(ciphertext, &identity_bytes);
}

#[tokio::test]
async fn resolve_envelope_roundtrip() {
    let mut cfg = base_config(temp_path("env-resolve"), TransportMode::Hybrid);
    cfg.device_name = Some("bob".to_string());
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
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let requester = PublicKey::from(&secret).to_bytes();
    let envelope = registry
        .issue_envelope_for("bob", requester)
        .await
        .expect("envelope");
    let decrypted = decrypt_identity_envelope(
        secret.to_bytes(),
        None,
        &envelope,
        "bob",
        MAX_IDENTITY_CIPHERTEXT,
        None,
    )
    .expect("decrypt");
    let identity: enigma_node_types::PublicIdentity =
        serde_json::from_slice(&decrypted).expect("parse");
    assert_eq!(
        identity.user_id.to_hex(),
        core.local_identity().user_id.to_hex()
    );
}
