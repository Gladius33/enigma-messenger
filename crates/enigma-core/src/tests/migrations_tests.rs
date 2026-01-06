use crate::migrations::{MigrationPlan, StoreVersions};
use crate::outbox::OUTBOX_VERSION;
use enigma_storage::key_provider::{KeyProvider, MasterKey};
use enigma_storage::EncryptedStore;
use enigma_storage::EnigmaStorageError;
use std::collections::HashSet;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::Mutex;
use uuid::Uuid;

struct TestKey;

impl KeyProvider for TestKey {
    fn get_or_create_master_key(&self) -> Result<MasterKey, EnigmaStorageError> {
        Ok(MasterKey::new([9u8; 32]))
    }

    fn get_master_key(&self) -> Result<MasterKey, EnigmaStorageError> {
        Ok(MasterKey::new([9u8; 32]))
    }
}

fn store(namespace: &str) -> Arc<Mutex<EncryptedStore>> {
    let dir = tempdir().unwrap();
    let path = dir.path().join("store");
    let store = EncryptedStore::open(path.to_str().unwrap(), namespace, &TestKey).unwrap();
    Arc::new(Mutex::new(store))
}

#[tokio::test]
async fn detects_versions_on_empty_store() {
    let store = store("migrate-empty");
    let plan = MigrationPlan::new(store);
    let report = plan.dry_run().await.unwrap();
    assert_eq!(report.detected.identity, 2);
    assert_eq!(report.detected.sessions, 1);
    assert_eq!(report.detected.outbox, OUTBOX_VERSION);
    assert!(!report.needs_migration);
}

#[tokio::test]
async fn migrates_outbox_and_stamps_versions() {
    let store = store("migrate-outbox");
    let id = Uuid::new_v4();
    {
        let guard = store.lock().await;
        let mut index = HashSet::new();
        index.insert(id);
        let index_bytes = serde_json::to_vec(&index).unwrap();
        guard.put("outbox:index", &index_bytes).unwrap();
        let legacy = serde_json::json!({
            "id": id,
            "message_id": "msg",
            "created_at_ms": 1,
            "next_retry_ms": 1,
            "tries": 0,
            "recipient_user_id": "user",
            "conversation_id": "conv",
            "packet": [1,2,3],
            "recipient_device_id": null
        });
        let key = format!("outbox:{}", id);
        guard
            .put(&key, serde_json::to_vec(&legacy).unwrap().as_slice())
            .unwrap();
    }
    let plan = MigrationPlan::new(store.clone());
    let dry = plan.dry_run().await.unwrap();
    assert!(dry.needs_migration);
    let applied = plan.apply().await.unwrap();
    assert!(applied.applied);
    let guard = store.lock().await;
    let key = format!("outbox:{}", id);
    let bytes = guard.get(&key).unwrap().unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        parsed.get("version").and_then(|v| v.as_u64()),
        Some(OUTBOX_VERSION as u64)
    );
    let stored_versions = guard.get("store:versions").unwrap().unwrap();
    let versions: StoreVersions = serde_json::from_slice(&stored_versions).unwrap();
    assert_eq!(versions.outbox, OUTBOX_VERSION);
}
