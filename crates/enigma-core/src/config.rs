use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub enum TransportMode {
    P2PWebRTC,
    RelayOnly,
    Hybrid,
}

impl Default for TransportMode {
    fn default() -> Self {
        TransportMode::Hybrid
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CoreConfig {
    pub storage_path: String,
    pub namespace: String,
    pub node_base_urls: Vec<String>,
    pub relay_base_urls: Vec<String>,
    pub device_name: Option<String>,
    pub enable_read_receipts: bool,
    pub enable_typing: bool,
    pub enable_ephemeral: bool,
    pub default_ephemeral_secs: Option<u64>,
    pub allow_attachments: bool,
    pub transport_mode: TransportMode,
    pub polling_interval_ms: u64,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            storage_path: ".enigma".to_string(),
            namespace: "default".to_string(),
            node_base_urls: Vec::new(),
            relay_base_urls: Vec::new(),
            device_name: None,
            enable_read_receipts: true,
            enable_typing: true,
            enable_ephemeral: true,
            default_ephemeral_secs: None,
            allow_attachments: true,
            transport_mode: TransportMode::Hybrid,
            polling_interval_ms: 2000,
        }
    }
}
