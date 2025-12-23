use crate::error::CoreError;
use crate::ids::{DeviceId, UserId};
use crate::time::now_ms;
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
    pub fn load_or_create(store: &EncryptedStore, user_handle: String) -> Result<Self, CoreError> {
        if let Some(bytes) = store.get("identity").map_err(|_| CoreError::Storage)? {
            let stored: StoredIdentity =
                serde_json::from_slice(&bytes).map_err(|_| CoreError::Storage)?;
            let user_id = UserId::from_hex(&stored.user_id_hex).ok_or(CoreError::Storage)?;
            let node_user =
                NodeUserId::from_hex(&stored.user_id_hex).map_err(|_| CoreError::Storage)?;
            let signing_public_key = user_id.as_bytes().to_vec();
            let stored_hint = stored.username_hint.clone();
            let identity = Self {
                device_id: DeviceId::new(stored.device_id),
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
        let identity = Self::create(user_handle)?;
        identity.persist(store)?;
        Ok(identity)
    }

    fn create(user_handle: String) -> Result<Self, CoreError> {
        let device_id = Uuid::new_v4();
        let normalized = enigma_node_types::normalize_username(&user_handle)
            .map_err(|_| CoreError::Validation("handle".to_string()))?;
        let node_user = NodeUserId::from_username(&normalized)
            .map_err(|_| CoreError::Validation("handle".to_string()))?;
        let user_hex = node_user.to_hex();
        let user_id =
            UserId::from_hex(&user_hex).ok_or(CoreError::Validation("handle".to_string()))?;
        let signing_public_key = node_user.as_bytes().to_vec();
        Ok(Self {
            device_id: DeviceId::new(device_id),
            username_hint: Some(normalized.clone()),
            user_id,
            public_identity: PublicIdentity {
                user_id: node_user,
                username_hint: Some(normalized),
                signing_public_key: signing_public_key.clone(),
                encryption_public_key: signing_public_key.clone(),
                signature: signing_public_key,
                created_at_ms: now_ms(),
            },
        })
    }

    pub fn persist(&self, store: &EncryptedStore) -> Result<(), CoreError> {
        let stored = StoredIdentity {
            device_id: self.device_id.as_uuid(),
            username_hint: self.username_hint.clone(),
            user_id_hex: self.user_id.to_hex(),
        };
        let bytes = serde_json::to_vec(&stored).map_err(|_| CoreError::Storage)?;
        store
            .put("identity", &bytes)
            .map_err(|_| CoreError::Storage)
    }
}
