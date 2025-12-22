use crate::error::CoreError;
use crate::ids::{DeviceId, UserId};
use crate::ratchet::RatchetState;
use blake3::Hasher;
use enigma_aead::AeadKey;
use enigma_storage::EncryptedStore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct SessionManager {
    local: UserId,
    store: Arc<Mutex<EncryptedStore>>,
    peers: HashMap<SessionKey, RatchetState>,
}

impl SessionManager {
    pub fn new(local: UserId, store: Arc<Mutex<EncryptedStore>>) -> Self {
        Self {
            local,
            store,
            peers: HashMap::new(),
        }
    }

    pub async fn next_key(
        &mut self,
        peer: &UserId,
        device: &DeviceId,
    ) -> Result<AeadKey, CoreError> {
        let key = SessionKey {
            user_id: peer.to_hex(),
            device_id: device.clone(),
        };
        if !self.peers.contains_key(&key) {
            if let Some(state) = self.load_state(&key).await? {
                self.peers.insert(key.clone(), state);
            }
        }
        let entry = self
            .peers
            .entry(key.clone())
            .or_insert_with(|| RatchetState::new(derive_seed(&self.local, peer, device)));
        let next = entry.next_key();
        let snapshot = entry.clone();
        self.save_state(&key, &snapshot).await?;
        next
    }

    async fn load_state(&self, key: &SessionKey) -> Result<Option<RatchetState>, CoreError> {
        let guard = self.store.lock().await;
        if let Some(bytes) = guard
            .get(&key.storage_key())
            .map_err(|_| CoreError::Storage)?
        {
            let state: RatchetState =
                serde_json::from_slice(&bytes).map_err(|_| CoreError::Storage)?;
            return Ok(Some(state));
        }
        Ok(None)
    }

    async fn save_state(&self, key: &SessionKey, state: &RatchetState) -> Result<(), CoreError> {
        let guard = self.store.lock().await;
        let bytes = serde_json::to_vec(state).map_err(|_| CoreError::Storage)?;
        guard
            .put(&key.storage_key(), &bytes)
            .map_err(|_| CoreError::Storage)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct SessionKey {
    user_id: String,
    device_id: DeviceId,
}

impl SessionKey {
    fn storage_key(&self) -> String {
        format!("sess:{}:{}", self.user_id, self.device_id.as_uuid())
    }
}

fn derive_seed(local: &UserId, peer: &UserId, device: &DeviceId) -> [u8; 32] {
    let (left, right) = if local.as_bytes() <= peer.as_bytes() {
        (local, peer)
    } else {
        (peer, local)
    };
    let mut hasher = Hasher::new();
    hasher.update(b"session_seed:v1");
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hasher.update(device.as_uuid().as_bytes());
    hasher.finalize().into()
}
