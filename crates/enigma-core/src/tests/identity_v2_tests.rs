use crate::config::TransportMode;
use crate::directory::InMemoryRegistry;
use crate::directory::RegistryClient;
use crate::envelope_crypto::{decrypt_identity_envelope, requester_keypair};
use crate::identity::{parse_identity_bundle, verify_signed_prekey};
use crate::messaging::MockTransport;
use crate::policy::Policy;
use crate::tests::{base_config, key_provider, temp_path};
use crate::Core;
use ed25519_dalek::{Signature, VerifyingKey};
use enigma_node_registry::envelope::EnvelopeCrypto;
use enigma_node_registry::envelope::EnvelopeKey;
use std::sync::Arc;
use tempfile;
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn signed_prekey_signature_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let store = enigma_storage::EncryptedStore::open(
        dir.path().to_str().unwrap(),
        "spk-verify",
        crate::tests::key_provider().as_ref(),
    )
    .unwrap();
    let id = crate::identity::LocalIdentity::load_or_create(&store, "alice".to_string()).unwrap();
    let bundle = id.x3dh_bundle().expect("bundle");
    assert!(verify_signed_prekey(&bundle));
}

#[test]
fn bundle_roundtrip_v2() {
    let dir = tempfile::tempdir().unwrap();
    let store = enigma_storage::EncryptedStore::open(
        dir.path().to_str().unwrap(),
        "bundle-v2",
        crate::tests::key_provider().as_ref(),
    )
    .unwrap();
    let id = crate::identity::LocalIdentity::load_or_create(&store, "alice".to_string()).unwrap();
    let key = EnvelopeKey {
        kid: [1u8; 8],
        private: [2u8; 32],
        public: PublicKey::from(&StaticSecret::from([2u8; 32])).to_bytes(),
        active: true,
        not_after: None,
    };
    let crypto = EnvelopeCrypto::new([3u8; 32]);
    let (secret, pubkey) = requester_keypair();
    let envelope = crypto
        .encrypt_identity_for_peer(
            &key,
            &enigma_node_types::UserId::from_hex(&id.user_id.to_hex()).unwrap(),
            &id.public_identity,
            pubkey,
            None,
            crate::time::now_ms(),
        )
        .unwrap();
    let resolved = decrypt_identity_envelope(
        [3u8; 32],
        &envelope,
        secret,
        &enigma_node_types::UserId::from_hex(&id.user_id.to_hex()).unwrap(),
    )
    .unwrap();
    assert!(parse_identity_bundle(&resolved.public).is_some());
    assert_eq!(resolved.public.user_id.to_hex(), id.user_id.to_hex());
    assert_eq!(
        resolved.public.encryption_public_key,
        id.public_identity.encryption_public_key
    );
    let bundle = parse_identity_bundle(&resolved.public).unwrap();
    assert!(verify_signed_prekey(&bundle));
}

#[tokio::test]
async fn registry_resolve_v2_bundle() {
    let mut cfg = base_config(temp_path("idv2-reg"), TransportMode::Hybrid);
    cfg.user_handle = "alice".to_string();
    cfg.polling_interval_ms = 0;
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(crate::relay::InMemoryRelay::new());
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
    .unwrap();
    let (secret, pubkey) = requester_keypair();
    let envelope = registry
        .resolve(&core.local_identity().user_id.to_hex(), pubkey)
        .await
        .unwrap()
        .unwrap();
    let resolved = decrypt_identity_envelope(
        registry.envelope_pepper().unwrap(),
        &envelope,
        secret,
        &core.local_identity().public_identity.user_id,
    )
    .unwrap();
    let bundle = parse_identity_bundle(&resolved.public).expect("bundle");
    let vk = VerifyingKey::from_bytes(&bundle.identity_sig_pub).unwrap();
    let sig_bytes: [u8; 64] = bundle.signed_prekey_sig.clone().try_into().unwrap();
    let sig = Signature::from_bytes(&sig_bytes);
    let mut msg = Vec::new();
    msg.extend_from_slice(crate::identity::SIGN_CONTEXT);
    msg.extend_from_slice(&bundle.signed_prekey_pub);
    assert!(vk.verify_strict(&msg, &sig).is_ok());
}
