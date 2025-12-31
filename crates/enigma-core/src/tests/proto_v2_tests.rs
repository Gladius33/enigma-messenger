use crate::identity::LocalIdentity;
use crate::ids::DeviceId;
use crate::proto_v2::{DrHeader, PacketV2, ProtoV2Manager};
use crate::tests::key_provider;
use crate::tests::temp_path;
use crate::PlainMessage;
use enigma_api::types::MessageKind;
use enigma_storage::EncryptedStore;
use uuid::Uuid;

fn message(sender: &str, conversation: &str) -> PlainMessage {
    PlainMessage {
        conversation_id: conversation.to_string(),
        message_id: Uuid::new_v4(),
        sender: sender.to_string(),
        kind: MessageKind::Text,
        text: Some("hi".to_string()),
        attachment: None,
        timestamp: crate::time::now_ms(),
        edited: false,
        deleted: false,
        distribution_payload: None,
    }
}

#[tokio::test]
async fn v2_x3dh_handshake_creates_session_and_roundtrips_message() {
    let store_a =
        EncryptedStore::open(&temp_path("v2-a"), "v2-a", key_provider().as_ref()).expect("store");
    let store_b =
        EncryptedStore::open(&temp_path("v2-b"), "v2-b", key_provider().as_ref()).expect("store");
    let id_a = LocalIdentity::load_or_create(&store_a, "alice".to_string()).unwrap();
    let id_b = LocalIdentity::load_or_create(&store_b, "bob".to_string()).unwrap();
    let store_a_arc = std::sync::Arc::new(tokio::sync::Mutex::new(store_a));
    let store_b_arc = std::sync::Arc::new(tokio::sync::Mutex::new(store_b));
    let bundle_b = id_b.x3dh_bundle().expect("bundle");
    let mut mgr_a = ProtoV2Manager::new(id_a.clone(), store_a_arc.clone());
    let mut mgr_b = ProtoV2Manager::new(id_b.clone(), store_b_arc.clone());
    let plain = message(&id_a.user_id.to_hex(), "dm");
    let ad = format!(
        "{}:{}:{}",
        plain.conversation_id, plain.message_id, plain.sender
    );
    let plaintext = serde_json::to_vec(&plain).unwrap();
    let (cipher, prekey) = mgr_a
        .encrypt(
            &id_b.user_id,
            &DeviceId::nil(),
            &bundle_b,
            &plaintext,
            ad.as_bytes(),
        )
        .await
        .unwrap();
    assert!(prekey.as_ref().is_some());
    let packet = PacketV2 {
        conversation_id: plain.conversation_id.clone(),
        message_id: plain.message_id,
        kind: crate::packet::format_kind(&plain.kind),
        header: DrHeader {
            version: 2,
            dh_pub: cipher.header.dh_pub,
            pn: cipher.header.pn,
            n: cipher.header.n,
        },
        prekey,
        ciphertext: cipher.ciphertext,
        associated_data: ad.as_bytes().to_vec(),
        device_id: Some(id_a.device_id.as_uuid()),
        target_device_id: Some(DeviceId::nil().as_uuid()),
        sender: Some(plain.sender.clone()),
    };
    let decrypted = mgr_b
        .decrypt(&id_a.user_id, &DeviceId::nil(), &packet)
        .await
        .unwrap();
    let parsed: PlainMessage = serde_json::from_slice(&decrypted).unwrap();
    assert_eq!(parsed.text.as_deref(), Some("hi"));
    let ad2 = format!(
        "{}:{}:{}",
        plain.conversation_id, plain.message_id, plain.sender
    );
    let plaintext2 = serde_json::to_vec(&plain).unwrap();
    let (cipher2, prekey2) = mgr_a
        .encrypt(
            &id_b.user_id,
            &DeviceId::nil(),
            &bundle_b,
            &plaintext2,
            ad2.as_bytes(),
        )
        .await
        .unwrap();
    assert!(prekey2.as_ref().is_none());
    let packet2 = PacketV2 {
        conversation_id: plain.conversation_id.clone(),
        message_id: plain.message_id,
        kind: crate::packet::format_kind(&plain.kind),
        header: DrHeader {
            version: 2,
            dh_pub: cipher2.header.dh_pub,
            pn: cipher2.header.pn,
            n: cipher2.header.n,
        },
        prekey: None,
        ciphertext: cipher2.ciphertext,
        associated_data: ad2.as_bytes().to_vec(),
        device_id: Some(id_a.device_id.as_uuid()),
        target_device_id: Some(DeviceId::nil().as_uuid()),
        sender: Some(plain.sender.clone()),
    };
    let decrypted2 = mgr_b
        .decrypt(&id_a.user_id, &DeviceId::nil(), &packet2)
        .await
        .unwrap();
    let parsed2: PlainMessage = serde_json::from_slice(&decrypted2).unwrap();
    assert_eq!(parsed2.text.as_deref(), Some("hi"));
}

#[tokio::test]
async fn v2_persistence_reload_keeps_session_and_decrypts() {
    let path_a = temp_path("v2-persist-a");
    let path_b = temp_path("v2-persist-b");
    let store_a = EncryptedStore::open(&path_a, "v2-a", key_provider().as_ref()).expect("store");
    let store_b = EncryptedStore::open(&path_b, "v2-b", key_provider().as_ref()).expect("store");
    let id_a = LocalIdentity::load_or_create(&store_a, "alice".to_string()).unwrap();
    let id_b = LocalIdentity::load_or_create(&store_b, "bob".to_string()).unwrap();
    let store_a_arc = std::sync::Arc::new(tokio::sync::Mutex::new(store_a));
    let store_b_arc = std::sync::Arc::new(tokio::sync::Mutex::new(store_b));
    let bundle_b = id_b.x3dh_bundle().expect("bundle");
    let mut mgr_a = ProtoV2Manager::new(id_a.clone(), store_a_arc.clone());
    let mut mgr_b = ProtoV2Manager::new(id_b.clone(), store_b_arc.clone());
    let plain = message(&id_a.user_id.to_hex(), "dm");
    let ad = format!(
        "{}:{}:{}",
        plain.conversation_id, plain.message_id, plain.sender
    );
    let plaintext = serde_json::to_vec(&plain).unwrap();
    let (cipher, prekey) = mgr_a
        .encrypt(
            &id_b.user_id,
            &DeviceId::nil(),
            &bundle_b,
            &plaintext,
            ad.as_bytes(),
        )
        .await
        .unwrap();
    let packet = PacketV2 {
        conversation_id: plain.conversation_id.clone(),
        message_id: plain.message_id,
        kind: crate::packet::format_kind(&plain.kind),
        header: DrHeader {
            version: 2,
            dh_pub: cipher.header.dh_pub,
            pn: cipher.header.pn,
            n: cipher.header.n,
        },
        prekey,
        ciphertext: cipher.ciphertext,
        associated_data: ad.as_bytes().to_vec(),
        device_id: Some(id_a.device_id.as_uuid()),
        target_device_id: Some(DeviceId::nil().as_uuid()),
        sender: Some(plain.sender.clone()),
    };
    let decrypted = mgr_b
        .decrypt(&id_a.user_id, &DeviceId::nil(), &packet)
        .await
        .unwrap();
    let parsed: PlainMessage = serde_json::from_slice(&decrypted).unwrap();
    assert_eq!(parsed.text.as_deref(), Some("hi"));
    let mut mgr_a = ProtoV2Manager::new(id_a.clone(), store_a_arc.clone());
    let mut mgr_b = ProtoV2Manager::new(id_b.clone(), store_b_arc.clone());
    let ad2 = format!(
        "{}:{}:{}",
        plain.conversation_id, plain.message_id, plain.sender
    );
    let plaintext2 = serde_json::to_vec(&plain).unwrap();
    let (cipher2, prekey2) = mgr_a
        .encrypt(
            &id_b.user_id,
            &DeviceId::nil(),
            &bundle_b,
            &plaintext2,
            ad2.as_bytes(),
        )
        .await
        .unwrap();
    assert!(prekey2.as_ref().is_none());
    let packet2 = PacketV2 {
        conversation_id: plain.conversation_id.clone(),
        message_id: plain.message_id,
        kind: crate::packet::format_kind(&plain.kind),
        header: DrHeader {
            version: 2,
            dh_pub: cipher2.header.dh_pub,
            pn: cipher2.header.pn,
            n: cipher2.header.n,
        },
        prekey: None,
        ciphertext: cipher2.ciphertext,
        associated_data: ad2.as_bytes().to_vec(),
        device_id: Some(id_a.device_id.as_uuid()),
        target_device_id: Some(DeviceId::nil().as_uuid()),
        sender: Some(plain.sender.clone()),
    };
    let decrypted2 = mgr_b
        .decrypt(&id_a.user_id, &DeviceId::nil(), &packet2)
        .await
        .unwrap();
    let parsed2: PlainMessage = serde_json::from_slice(&decrypted2).unwrap();
    assert_eq!(parsed2.text.as_deref(), Some("hi"));
}
