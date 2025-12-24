use enigma_node_registry::config::{
    EnvelopeConfig as ServerEnvelopeConfig, EnvelopeKeyConfig, PresenceConfig,
    RateLimitConfig as ServerRateLimitConfig, RegistryConfig as ServerRegistryConfig, ServerMode,
    StorageConfig as ServerStorageConfig,
};
use enigma_node_registry::server::{start as start_registry, RunningServer};
use enigma_relay::config::{
    RelayConfig as ServerRelayConfig, RelayMode, StorageConfig as ServerRelayStorageConfig,
    StorageKind,
};
use enigma_relay::start as start_relay;

pub struct RegistryServerHandle {
    pub base_url: String,
    inner: RunningServer,
}

pub struct RelayServerHandle {
    pub base_url: String,
    shutdown: tokio::sync::oneshot::Sender<()>,
    handle: tokio::task::JoinHandle<enigma_relay::Result<()>>,
}

impl RegistryServerHandle {
    pub async fn stop(self) {
        let _ = self.inner.stop().await;
    }
}

impl RelayServerHandle {
    pub async fn stop(self) {
        let _ = self.shutdown.send(());
        let _ = self.handle.await;
    }
}

pub async fn spawn_registry_server(
    pepper_hex: &str,
    kid_hex: &str,
    private_hex: &str,
) -> Option<RegistryServerHandle> {
    spawn_registry_server_at("127.0.0.1:0".to_string(), pepper_hex, kid_hex, private_hex).await
}

fn registry_config(
    address: String,
    pepper_hex: &str,
    kid_hex: &str,
    private_hex: &str,
) -> ServerRegistryConfig {
    ServerRegistryConfig {
        address,
        mode: ServerMode::Http,
        trusted_proxies: Vec::new(),
        rate_limit: ServerRateLimitConfig::default(),
        envelope: ServerEnvelopeConfig {
            pepper_hex: pepper_hex.to_string(),
            keys: vec![EnvelopeKeyConfig {
                kid_hex: kid_hex.to_string(),
                x25519_private_key_hex: private_hex.to_string(),
                active: true,
                not_after_epoch_ms: None,
            }],
        },
        tls: None,
        storage: ServerStorageConfig {
            kind: "memory".to_string(),
            path: String::new(),
        },
        presence: PresenceConfig::default(),
        pow: enigma_node_registry::config::PowConfig::default(),
        allow_sync: true,
        max_nodes: 128,
    }
}

pub async fn spawn_registry_server_at(
    address: String,
    pepper_hex: &str,
    kid_hex: &str,
    private_hex: &str,
) -> Option<RegistryServerHandle> {
    let server_cfg = registry_config(address, pepper_hex, kid_hex, private_hex);
    match start_registry(server_cfg).await {
        Ok(running) => Some(RegistryServerHandle {
            base_url: running.base_url.clone(),
            inner: running,
        }),
        Err(err) => {
            if format!("{:?}", err).contains("Operation not permitted") {
                None
            } else {
                panic!("{:?}", err);
            }
        }
    }
}

pub async fn spawn_relay_server() -> Option<RelayServerHandle> {
    spawn_relay_server_at("127.0.0.1:0".to_string()).await
}

pub async fn spawn_relay_server_at(address: String) -> Option<RelayServerHandle> {
    let relay_cfg = ServerRelayConfig {
        address,
        mode: RelayMode::Http,
        tls: None,
        storage: ServerRelayStorageConfig {
            kind: StorageKind::Memory,
            path: String::new(),
        },
        ..ServerRelayConfig::default()
    };
    match start_relay(relay_cfg).await {
        Ok(running) => Some(RelayServerHandle {
            base_url: running.base_url.clone(),
            shutdown: running.shutdown,
            handle: running.handle,
        }),
        Err(err) => {
            if format!("{:?}", err).contains("Operation not permitted") {
                None
            } else {
                panic!("{:?}", err);
            }
        }
    }
}
