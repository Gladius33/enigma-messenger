use crate::error::CoreError;
use crate::ids::DeviceId;
use crate::policy::ReceiptAggregation;
use enigma_storage::EncryptedStore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceReceipt {
    pub delivered: bool,
    pub read: bool,
}

impl DeviceReceipt {
    fn delivered_only() -> Self {
        Self {
            delivered: true,
            read: false,
        }
    }

    fn read_only() -> Self {
        Self {
            delivered: true,
            read: true,
        }
    }
}

#[derive(Clone)]
pub struct ReceiptStore {
    store: Arc<Mutex<EncryptedStore>>,
}

impl ReceiptStore {
    pub fn new(store: Arc<Mutex<EncryptedStore>>) -> Self {
        Self { store }
    }

    pub async fn mark_delivered(
        &self,
        message_id: &Uuid,
        user_id: &str,
        device: &DeviceId,
    ) -> Result<(), CoreError> {
        self.save_receipt(message_id, user_id, device, DeviceReceipt::delivered_only())
            .await
    }

    pub async fn mark_read(
        &self,
        message_id: &Uuid,
        user_id: &str,
        device: &DeviceId,
    ) -> Result<(), CoreError> {
        self.save_receipt(message_id, user_id, device, DeviceReceipt::read_only())
            .await
    }

    async fn save_receipt(
        &self,
        message_id: &Uuid,
        user_id: &str,
        device: &DeviceId,
        receipt: DeviceReceipt,
    ) -> Result<(), CoreError> {
        let guard = self.store.lock().await;
        let key = Self::receipt_key(message_id, user_id, device);
        let existing = guard
            .get(&key)
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice::<DeviceReceipt>(&b).ok())
            .unwrap_or(DeviceReceipt {
                delivered: false,
                read: false,
            });

        let merged = DeviceReceipt {
            delivered: existing.delivered || receipt.delivered,
            read: existing.read || receipt.read,
        };

        let bytes = serde_json::to_vec(&merged).map_err(|_| CoreError::Storage)?;
        guard.put(&key, &bytes).map_err(|_| CoreError::Storage)
    }

    pub async fn aggregated_delivered(
        &self,
        message_id: &Uuid,
        user_id: &str,
        devices: &[DeviceId],
        mode: &ReceiptAggregation,
    ) -> bool {
        self.aggregate(message_id, user_id, devices, mode, |r| r.delivered)
            .await
    }

    pub async fn aggregated_read(
        &self,
        message_id: &Uuid,
        user_id: &str,
        devices: &[DeviceId],
        mode: &ReceiptAggregation,
    ) -> bool {
        self.aggregate(message_id, user_id, devices, mode, |r| r.read)
            .await
    }

    async fn aggregate<F: Fn(&DeviceReceipt) -> bool>(
        &self,
        message_id: &Uuid,
        user_id: &str,
        devices: &[DeviceId],
        mode: &ReceiptAggregation,
        predicate: F,
    ) -> bool {
        let store = self.store.lock().await;
        let mut results = HashMap::new();

        if devices.is_empty() {
            let key = Self::receipt_key(message_id, user_id, &DeviceId::nil());
            if let Some(bytes) = store.get(&key).ok().flatten() {
                if let Ok(receipt) = serde_json::from_slice::<DeviceReceipt>(&bytes) {
                    results.insert(DeviceId::nil(), receipt);
                }
            }
        }

        for device in devices {
            let key = Self::receipt_key(message_id, user_id, device);
            if let Some(bytes) = store.get(&key).ok().flatten() {
                if let Ok(receipt) = serde_json::from_slice::<DeviceReceipt>(&bytes) {
                    results.insert(device.clone(), receipt);
                }
            }
        }

        if results.is_empty() && devices.is_empty() {
            return false;
        }

        match mode {
            ReceiptAggregation::Any => results.values().any(&predicate),
            ReceiptAggregation::All => {
                if devices.is_empty() {
                    results.values().all(&predicate)
                } else {
                    devices
                        .iter()
                        .all(|d| results.get(d).map(&predicate).unwrap_or(false))
                }
            }
        }
    }

    fn receipt_key(message_id: &Uuid, user_id: &str, device: &DeviceId) -> String {
        format!("rcpt:{}:{}:{}", message_id, user_id, device.as_uuid())
    }
}
