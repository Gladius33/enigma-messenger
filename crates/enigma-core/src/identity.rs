use crate::error::CoreError;
use crate::ids::{DeviceId, UserId};
use blake3::Hasher;
use enigma_node_types::PublicIdentity;
use enigma_storage::EncryptedStore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct LocalIdentity {
    pub device_id: DeviceId,
    pub username_hint: Option<String>,
    pub user_id: UserId,
    pub public_identity: PublicIdentity,
}

#[derive(Serialize, Deserialize)]
struct StoredIdentity {
    device_id: Uuid,
    username_hint: Option<String>,
    user_id_hex: String,
}

impl LocalIdentity {
    pub fn load_or_create(
        store: &mut EncryptedStore,
        username_hint: Option<String>,
    ) -> Result<Self, CoreError> {
        if let Some(bytes) = store.get("identity") {
            let stored: StoredIdentity =
                serde_json::from_slice(&bytes).map_err(|_| CoreError::Storage)?;
            if let Some(user_id) = UserId::from_hex(&stored.user_id_hex) {
                let identity = Self {
                    device_id: stored.device_id,
                    username_hint: stored.username_hint,
                    user_id,
                    public_identity: PublicIdentity {
                        user_id: stored.user_id_hex,
                        device_id: stored.device_id.to_string(),
                    },
                };
                return Ok(identity);
            }
        }
        let identity = Self::create(username_hint);
        identity.persist(store)?;
        Ok(identity)
    }

    fn create(username_hint: Option<String>) -> Self {
        let device_id = Uuid::new_v4();
        let mut hasher = Hasher::new();
        hasher.update(device_id.as_bytes());
        let user_hash = hasher.finalize();
        let user_id = UserId::from_bytes(*user_hash.as_bytes());
        let user_hex = user_id.to_hex();
        Self {
            device_id,
            username_hint,
            user_id,
            public_identity: PublicIdentity {
                user_id: user_hex,
                device_id: device_id.to_string(),
            },
        }
    }

    pub fn persist(&self, store: &mut EncryptedStore) -> Result<(), CoreError> {
        let stored = StoredIdentity {
            device_id: self.device_id,
            username_hint: self.username_hint.clone(),
            user_id_hex: self.user_id.to_hex(),
        };
        let bytes = serde_json::to_vec(&stored).map_err(|_| CoreError::Storage)?;
        store.put("identity", bytes).map_err(|_| CoreError::Storage)
    }
}
