use enigma_core::policy::Policy;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize)]
pub struct EnigmaConfig {
    pub data_dir: PathBuf,
    pub identity: IdentityConfig,
    pub policy: Policy,
    pub registry: RegistryConfig,
    pub relay: RelayConfig,
    pub transport: TransportConfig,
    #[serde(default)]
    pub sfu: SfuConfig,
    #[serde(default)]
    pub calls: CallsConfig,
    pub logging: LoggingConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IdentityConfig {
    pub user_handle: String,
    pub device_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RegistryConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub base_url: String,
    #[serde(default)]
    pub mode: EndpointMode,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub pow: PowConfig,
    #[serde(default)]
    pub pepper_hex: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RelayConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub base_url: Option<String>,
    #[serde(default)]
    pub mode: EndpointMode,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TransportConfig {
    pub webrtc: WebRtcConfig,
}

#[derive(Clone, Debug, Deserialize)]
pub struct WebRtcConfig {
    pub enabled: bool,
    pub stun_servers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EndpointMode {
    Http,
    Tls,
}

impl Default for EndpointMode {
    fn default() -> Self {
        EndpointMode::Http
    }
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct TlsConfig {
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Default)]
pub struct PowConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SfuConfig {
    #[serde(default)]
    pub enabled: bool,
}

impl Default for SfuConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct CallsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_publish")]
    pub max_publish_tracks_per_participant: u32,
    #[serde(default = "default_max_subscriptions")]
    pub max_subscriptions_per_participant: u32,
}

impl Default for CallsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_publish_tracks_per_participant: default_max_publish(),
            max_subscriptions_per_participant: default_max_subscriptions(),
        }
    }
}

fn default_max_publish() -> u32 {
    4
}

fn default_max_subscriptions() -> u32 {
    16
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io")]
    Io,
    #[error("parse")]
    Parse,
}

pub fn load_config(path: &Path) -> Result<EnigmaConfig, ConfigError> {
    let content = fs::read_to_string(path).map_err(|_| ConfigError::Io)?;
    toml::from_str(&content).map_err(|_| ConfigError::Parse)
}
