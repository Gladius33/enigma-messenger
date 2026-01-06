use crate::error::CoreError;
use crate::outbox::{OutboxItem, OUTBOX_VERSION};
use enigma_storage::EncryptedStore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

const STORE_VERSIONS_KEY: &str = "store:versions";
const IDENTITY_LATEST: u8 = 2;
const SESSIONS_LATEST: u8 = 1;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoreVersions {
    pub identity: u8,
    pub sessions: u8,
    pub outbox: u8,
}

impl StoreVersions {
    pub fn latest() -> Self {
        StoreVersions {
            identity: IDENTITY_LATEST,
            sessions: SESSIONS_LATEST,
            outbox: OUTBOX_VERSION,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationReport {
    pub detected: StoreVersions,
    pub target: StoreVersions,
    pub applied: bool,
    pub needs_migration: bool,
}

pub struct MigrationPlan {
    store: Arc<Mutex<EncryptedStore>>,
}

impl MigrationPlan {
    pub fn new(store: Arc<Mutex<EncryptedStore>>) -> Self {
        MigrationPlan { store }
    }

    pub async fn dry_run(&self) -> Result<MigrationReport, CoreError> {
        let mut guard = self.store.lock().await;
        let detected = detect_versions(&mut guard)?;
        let target = StoreVersions::latest();
        Ok(MigrationReport {
            needs_migration: detected != target,
            detected,
            target,
            applied: false,
        })
    }

    pub async fn apply(&self) -> Result<MigrationReport, CoreError> {
        let mut guard = self.store.lock().await;
        let mut detected = detect_versions(&mut guard)?;
        let target = StoreVersions::latest();
        if detected.identity < target.identity {
            return Err(CoreError::Validation(
                "identity_upgrade_unsupported".to_string(),
            ));
        }
        if detected.sessions < target.sessions {
            return Err(CoreError::Validation(
                "session_upgrade_unsupported".to_string(),
            ));
        }
        if detected.outbox < target.outbox {
            migrate_outbox(&mut guard)?;
            detected.outbox = target.outbox;
        }
        persist_versions(&mut guard, &detected)?;
        Ok(MigrationReport {
            needs_migration: detected != target,
            detected,
            target,
            applied: true,
        })
    }
}

fn detect_versions(store: &mut EncryptedStore) -> Result<StoreVersions, CoreError> {
    if let Some(bytes) = store
        .get(STORE_VERSIONS_KEY)
        .map_err(|_| CoreError::Storage)?
    {
        if let Ok(parsed) = serde_json::from_slice::<StoreVersions>(&bytes) {
            return Ok(parsed);
        }
    }
    let identity = detect_identity_version(store)?;
    let sessions = SESSIONS_LATEST;
    let outbox = detect_outbox_version(store)?;
    Ok(StoreVersions {
        identity,
        sessions,
        outbox,
    })
}

fn detect_identity_version(store: &EncryptedStore) -> Result<u8, CoreError> {
    let Some(bytes) = store.get("identity").map_err(|_| CoreError::Storage)? else {
        return Ok(IDENTITY_LATEST);
    };
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| CoreError::Storage)?;
    let Some(version_value) = value.get("version") else {
        return Ok(1);
    };
    match version_value.as_str() {
        Some("V2") => Ok(2),
        _ => Ok(1),
    }
}

fn detect_outbox_version(store: &EncryptedStore) -> Result<u8, CoreError> {
    let Some(index_bytes) = store.get("outbox:index").map_err(|_| CoreError::Storage)? else {
        return Ok(OUTBOX_VERSION);
    };
    let Ok(index): Result<HashSet<Uuid>, _> = serde_json::from_slice(&index_bytes) else {
        return Ok(1);
    };
    if index.is_empty() {
        return Ok(OUTBOX_VERSION);
    }
    if let Some(first) = index.iter().next() {
        let key = format!("outbox:{}", first);
        if let Some(bytes) = store.get(&key).map_err(|_| CoreError::Storage)? {
            if let Ok(item) = serde_json::from_slice::<OutboxItem>(&bytes) {
                return Ok(item.version);
            }
        }
    }
    Ok(1)
}

fn migrate_outbox(store: &mut EncryptedStore) -> Result<(), CoreError> {
    let Some(index_bytes) = store.get("outbox:index").map_err(|_| CoreError::Storage)? else {
        return Ok(());
    };
    let index: HashSet<Uuid> =
        serde_json::from_slice(&index_bytes).map_err(|_| CoreError::Storage)?;
    for id in index.iter() {
        let key = format!("outbox:{}", id);
        let Some(bytes) = store.get(&key).map_err(|_| CoreError::Storage)? else {
            continue;
        };
        let mut item: OutboxItem =
            serde_json::from_slice(&bytes).map_err(|_| CoreError::Storage)?;
        if item.version < OUTBOX_VERSION {
            item.version = OUTBOX_VERSION;
            let updated = serde_json::to_vec(&item).map_err(|_| CoreError::Storage)?;
            store.put(&key, &updated).map_err(|_| CoreError::Storage)?;
        }
    }
    let index_bytes = serde_json::to_vec(&index).map_err(|_| CoreError::Storage)?;
    store
        .put("outbox:index", &index_bytes)
        .map_err(|_| CoreError::Storage)?;
    Ok(())
}

fn persist_versions(store: &mut EncryptedStore, versions: &StoreVersions) -> Result<(), CoreError> {
    let bytes = serde_json::to_vec(versions).map_err(|_| CoreError::Storage)?;
    store
        .put(STORE_VERSIONS_KEY, &bytes)
        .map_err(|_| CoreError::Storage)
}
