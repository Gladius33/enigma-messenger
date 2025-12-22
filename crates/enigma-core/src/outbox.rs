use crate::policy::Policy;
use crate::time::now_ms;
use enigma_storage::EncryptedStore;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutboxItem {
    pub id: Uuid,
    pub message_id: String,
    pub created_at_ms: u64,
    pub next_retry_ms: u64,
    pub tries: u32,
    pub recipient_user_id: String,
    pub conversation_id: String,
    pub packet: Vec<u8>,
}

#[derive(Clone)]
pub struct Outbox {
    store: Arc<Mutex<EncryptedStore>>,
}

impl Outbox {
    pub fn new(store: Arc<Mutex<EncryptedStore>>) -> Self {
        Self { store }
    }

    pub async fn put(&self, item: OutboxItem) -> Result<(), ()> {
        let mut guard = self.store.lock().await;
        let mut index = self.index(&mut guard)?;
        if !index.contains(&item.id) {
            index.insert(item.id);
        }
        let key = Self::item_key(&item.id);
        let bytes = serde_json::to_vec(&item).map_err(|_| ())?;
        guard.put(&key, &bytes).map_err(|_| ())?;
        self.persist_index(&mut guard, &index)?;
        Ok(())
    }

    pub async fn mark_sent(&self, id: &Uuid) -> Result<(), ()> {
        let mut guard = self.store.lock().await;
        let mut index = self.index(&mut guard)?;
        index.remove(id);
        guard.delete(&Self::item_key(id)).map_err(|_| ())?;
        self.persist_index(&mut guard, &index)?;
        Ok(())
    }

    pub async fn load_all_due(&self, now: u64, limit: usize) -> Result<Vec<OutboxItem>, ()> {
        let mut guard = self.store.lock().await;
        let index = self.index(&mut guard)?;
        let mut due = Vec::new();
        for id in index.iter() {
            if due.len() >= limit {
                break;
            }
            let key = Self::item_key(id);
            if let Some(bytes) = guard.get(&key).map_err(|_| ())? {
                if let Ok(item) = serde_json::from_slice::<OutboxItem>(&bytes) {
                    if item.next_retry_ms <= now {
                        due.push(item);
                    }
                }
            }
        }
        Ok(due)
    }

    pub async fn bump_retry(&self, id: &Uuid, policy: &Policy) -> Result<(), ()> {
        let guard = self.store.lock().await;
        let key = Self::item_key(id);
        let Some(bytes) = guard.get(&key).map_err(|_| ())? else {
            return Ok(());
        };
        let mut item: OutboxItem = serde_json::from_slice(&bytes).map_err(|_| ())?;
        item.tries = item.tries.saturating_add(1);
        let factor = 1u64 << (item.tries.saturating_sub(1).min(16));
        let base = policy.backoff_initial_ms.saturating_mul(factor);
        let capped = base.min(policy.backoff_max_ms);
        let jitter = rand::thread_rng().gen_range(0..=capped / 2 + 1);
        item.next_retry_ms = now_ms().saturating_add(capped + jitter);
        let updated = serde_json::to_vec(&item).map_err(|_| ())?;
        guard.put(&key, &updated).map_err(|_| ())?;
        Ok(())
    }

    fn index(&self, store: &mut EncryptedStore) -> Result<HashSet<Uuid>, ()> {
        if let Some(bytes) = store.get("outbox:index").map_err(|_| ())? {
            serde_json::from_slice(&bytes).map_err(|_| ())
        } else {
            Ok(HashSet::new())
        }
    }

    fn persist_index(&self, store: &mut EncryptedStore, index: &HashSet<Uuid>) -> Result<(), ()> {
        let bytes = serde_json::to_vec(index).map_err(|_| ())?;
        store.put("outbox:index", &bytes).map_err(|_| ())
    }

    fn item_key(id: &Uuid) -> String {
        format!("outbox:{}", id)
    }
}
