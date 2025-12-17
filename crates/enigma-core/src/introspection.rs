#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreStats {
    pub user_id_hex: String,
    pub device_id: uuid::Uuid,
    pub conversations: usize,
    pub groups: usize,
    pub channels: usize,
    pub pending_outbox: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryStatus {
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreHealth {
    pub namespace: String,
    pub ok: bool,
}

#[cfg(feature = "dev")]
impl crate::Core {
    pub async fn stats(&self) -> CoreStats {
        let groups = self.groups.len().await;
        let channels = self.channels.len().await;
        let conversations = groups + channels;
        let pending_outbox = self.relay.pending_len().await;
        CoreStats {
            user_id_hex: self.identity.user_id.to_hex(),
            device_id: self.identity.device_id,
            conversations,
            groups,
            channels,
            pending_outbox,
        }
    }

    pub async fn registry_status(&self) -> RegistryStatus {
        RegistryStatus {
            endpoints: self.registry.endpoints(),
        }
    }

    pub async fn store_health(&self) -> StoreHealth {
        let guard = self.store.lock().await;
        let namespace = self.config.namespace.clone();
        let ok = guard.get("identity").ok().flatten().is_some();
        StoreHealth { namespace, ok }
    }

    pub fn directory_len(&self) -> usize {
        self.directory.len()
    }
}
