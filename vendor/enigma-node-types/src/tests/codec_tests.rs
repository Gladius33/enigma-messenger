use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use uuid::Uuid;

use crate::codec::{from_json_str, to_json_string};
use crate::identity::PublicIdentity;
use crate::presence::Presence;
use crate::relay::{OpaqueMessage, RelayEnvelope, RelayKind};
use crate::user_id::UserId;

#[test]
fn public_identity_json_roundtrip() {
    let user_id = UserId::from_username("gina").expect("user id");
    let identity = PublicIdentity {
        user_id,
        username_hint: Some("gina".to_string()),
        signing_public_key: vec![1, 2],
        encryption_public_key: vec![3, 4],
        signature: vec![5, 6],
        created_at_ms: 42,
    };
    let json = to_json_string(&identity).expect("json");
    let parsed: PublicIdentity = from_json_str(&json).expect("parsed");
    assert_eq!(identity, parsed);
}

#[test]
fn presence_json_roundtrip() {
    let user_id = UserId::from_username("harry").expect("user id");
    let presence = Presence {
        user_id,
        addr: "example.org:1234".to_string(),
        ts_ms: 77,
    };
    let json = to_json_string(&presence).expect("json");
    let parsed: Presence = from_json_str(&json).expect("parsed");
    assert_eq!(presence, parsed);
}

#[test]
fn relay_envelope_json_roundtrip() {
    let user_id = UserId::from_username("iris").expect("user id");
    let envelope = RelayEnvelope {
        id: Uuid::new_v4(),
        to: user_id,
        from: None,
        created_at_ms: 100,
        expires_at_ms: Some(200),
        kind: RelayKind::OpaqueMessage(OpaqueMessage {
            blob_b64: STANDARD.encode("payload"),
            content_type: Some("application/octet-stream".to_string()),
        }),
    };
    let json = to_json_string(&envelope).expect("json");
    let parsed: RelayEnvelope = from_json_str(&json).expect("parsed");
    assert_eq!(envelope, parsed);
}

#[test]
fn unknown_fields_rejected() {
    let user_id = UserId::from_username("jack").expect("user id");
    let hex = user_id.to_hex();
    let json = format!(
        "{{\"user_id\":\"{}\",\"addr\":\"a:1\",\"ts_ms\":1,\"extra\":true}}",
        hex
    );
    let parsed: Result<Presence> = from_json_str(&json);
    assert!(parsed.is_err());
}
use crate::Result;
