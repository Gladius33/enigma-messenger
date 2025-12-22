use crate::user_id::UserId;

#[test]
fn same_username_produces_same_user_id() {
    let id1 = UserId::from_username("alice").expect("id1");
    let id2 = UserId::from_username("alice").expect("id2");
    assert_eq!(id1, id2);
}

#[test]
fn different_usernames_produce_different_user_ids() {
    let id1 = UserId::from_username("alice").expect("alice");
    let id2 = UserId::from_username("bob").expect("bob");
    assert_ne!(id1, id2);
}

#[test]
fn hex_roundtrip() {
    let id = UserId::from_username("carol").expect("id");
    let hex = id.to_hex();
    let parsed = UserId::from_hex(&hex).expect("parsed");
    assert_eq!(id, parsed);
}

#[test]
fn invalid_hex_rejected() {
    let err = UserId::from_hex("zz");
    assert!(err.is_err());
}
