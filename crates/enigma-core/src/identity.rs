use crate::error::CoreError;
use crate::ids::{DeviceId, UserId};
use crate::time::now_ms;
use blake3::Hasher;
use enigma_node_types::{PublicIdentity, UserId as NodeUserId};
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
        store: &EncryptedStore,
        username_hint: Option<String>,
    ) -> Result<Self, CoreError> {
        if let Some(bytes) = store.get("identity").map_err(|_| CoreError::Storage)? {
            let stored: StoredIdentity =
                serde_json::from_slice(&bytes).map_err(|_| CoreError::Storage)?;
            let user_id = UserId::from_hex(&stored.user_id_hex).ok_or(CoreError::Storage)?;
            let node_user =
                NodeUserId::from_hex(&stored.user_id_hex).map_err(|_| CoreError::Storage)?;
            let signing_public_key = user_id.as_bytes().to_vec();
            let stored_hint = stored.username_hint.clone();
            let identity = Self {
                device_id: stored.device_id,
                username_hint: stored_hint.clone(),
                user_id,
                public_identity: PublicIdentity {
                    user_id: node_user,
                    username_hint: stored_hint,
                    signing_public_key: signing_public_key.clone(),
                    encryption_public_key: signing_public_key.clone(),
                    signature: signing_public_key,
                    created_at_ms: now_ms(),
                },
            };
            return Ok(identity);
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
        let node_user = NodeUserId::from_hex(&user_hex).expect("valid user id");
        let signing_public_key = user_hash.as_bytes().to_vec();
        let username_hint_clone = username_hint.clone();
        Self {
            device_id,
            username_hint,
            user_id,
            public_identity: PublicIdentity {
                user_id: node_user,
                username_hint: username_hint_clone,
                signing_public_key: signing_public_key.clone(),
                encryption_public_key: signing_public_key.clone(),
                signature: signing_public_key,
                created_at_ms: now_ms(),
            },
        }
    }

    pub fn persist(&self, store: &EncryptedStore) -> Result<(), CoreError> {
        let stored = StoredIdentity {
            device_id: self.device_id,
            username_hint: self.username_hint.clone(),
            user_id_hex: self.user_id.to_hex(),
        };
        let bytes = serde_json::to_vec(&stored).map_err(|_| CoreError::Storage)?;
        store
            .put("identity", &bytes)
            .map_err(|_| CoreError::Storage)
    }
}
