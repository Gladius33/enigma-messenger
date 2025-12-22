use crate::identity::PublicIdentity;
use crate::user_id::UserId;

#[test]
fn valid_public_identity_passes_validation() {
    let user_id = UserId::from_username("dave").expect("user id");
    let identity = PublicIdentity {
        user_id,
        username_hint: Some("dave".to_string()),
        signing_public_key: vec![1, 2, 3],
        encryption_public_key: vec![4, 5, 6],
        signature: vec![7, 8, 9],
        created_at_ms: 123,
    };
    assert!(identity.validate().is_ok());
}

#[test]
fn empty_keys_rejected() {
    let user_id = UserId::from_username("erin").expect("user id");
    let identity = PublicIdentity {
        user_id,
        username_hint: None,
        signing_public_key: Vec::new(),
        encryption_public_key: vec![1],
        signature: vec![2],
        created_at_ms: 1,
    };
    assert!(identity.validate().is_err());
}

#[test]
fn bad_username_hint_rejected() {
    let user_id = UserId::from_username("frank").expect("user id");
    let identity = PublicIdentity {
        user_id,
        username_hint: Some("\nfrank".to_string()),
        signing_public_key: vec![1],
        encryption_public_key: vec![2],
        signature: vec![3],
        created_at_ms: 10,
    };
    assert!(identity.validate().is_err());
}
