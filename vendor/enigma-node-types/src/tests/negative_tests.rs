use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use uuid::Uuid;

use crate::node::NodeInfo;
use crate::relay::{OpaqueMessage, OpaqueSignaling, RelayEnvelope, RelayKind};
use crate::user_id::UserId;

#[test]
fn invalid_base64_rejected() {
    let user_id = UserId::from_username("kate").expect("user id");
    let envelope = RelayEnvelope {
        id: Uuid::new_v4(),
        to: user_id,
        from: None,
        created_at_ms: 1,
        expires_at_ms: Some(2),
        kind: RelayKind::OpaqueMessage(OpaqueMessage {
            blob_b64: "%not-base64%".to_string(),
            content_type: None,
        }),
    };
    assert!(envelope.validate().is_err());
}

#[test]
fn expires_at_not_after_created_rejected() {
    let user_id = UserId::from_username("leo").expect("user id");
    let envelope = RelayEnvelope {
        id: Uuid::new_v4(),
        to: user_id,
        from: None,
        created_at_ms: 10,
        expires_at_ms: Some(5),
        kind: RelayKind::OpaqueSignaling(OpaqueSignaling {
            blob_b64: STANDARD.encode("data"),
        }),
    };
    assert!(envelope.validate().is_err());
}

#[test]
fn base_url_without_scheme_rejected() {
    let node = NodeInfo {
        base_url: "node.example.com".to_string(),
    };
    assert!(node.validate().is_err());
}
