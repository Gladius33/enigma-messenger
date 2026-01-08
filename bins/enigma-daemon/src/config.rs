use enigma_core::policy::Policy;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
    #[serde(default)]
    pub api: ApiConfig,
    pub logging: LoggingConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    pub user_handle: String,
    pub device_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
    #[serde(default)]
    pub http: HttpClientConfig,
    #[serde(default = "default_key_cache_ttl_secs")]
    pub key_cache_ttl_secs: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub base_url: Option<String>,
    #[serde(default)]
    pub mode: EndpointMode,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    #[serde(default)]
    pub http: HttpClientConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransportConfig {
    pub webrtc: WebRtcConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WebRtcConfig {
    pub enabled: bool,
    pub stun_servers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    #[serde(default = "default_api_bind_addr")]
    pub bind_addr: String,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_api_bind_addr(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    pub level: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum EndpointMode {
    #[default]
    Http,
    Tls,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    #[serde(default)]
    pub ca_cert: Option<PathBuf>,
    #[serde(default)]
    pub client_cert: Option<PathBuf>,
    #[serde(default)]
    pub client_key: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PowConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_pow_max_solve_ms")]
    pub max_solve_ms: u64,
    #[serde(default = "default_pow_retry_attempts")]
    pub retry_attempts: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SfuConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CallsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_publish")]
    pub max_publish_tracks_per_participant: u32,
    #[serde(default = "default_max_subscriptions")]
    pub max_subscriptions_per_participant: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpClientConfig {
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_read_timeout_secs")]
    pub read_timeout_secs: u64,
    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u32,
    #[serde(default = "default_retry_backoff_ms")]
    pub retry_backoff_ms: u64,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            timeout_secs: default_timeout_secs(),
            connect_timeout_secs: default_connect_timeout_secs(),
            read_timeout_secs: default_read_timeout_secs(),
            retry_attempts: default_retry_attempts(),
            retry_backoff_ms: default_retry_backoff_ms(),
        }
    }
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

fn default_timeout_secs() -> u64 {
    10
}

fn default_connect_timeout_secs() -> u64 {
    5
}

fn default_read_timeout_secs() -> u64 {
    10
}

fn default_retry_attempts() -> u32 {
    3
}

fn default_retry_backoff_ms() -> u64 {
    200
}

fn default_pow_max_solve_ms() -> u64 {
    1500
}

fn default_pow_retry_attempts() -> u32 {
    2
}

fn default_key_cache_ttl_secs() -> u64 {
    300
}

fn default_api_bind_addr() -> String {
    "127.0.0.1:9171".to_string()
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io")]
    Io,
    #[error("parse")]
    Parse,
    #[error("validation {0}")]
    Validation(String),
}

impl EnigmaConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.registry.validate()?;
        self.relay.validate()?;
        self.api.validate()?;
        Ok(())
    }
}

impl RegistryConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.base_url.trim().is_empty() {
            return Err(ConfigError::Validation("registry_base_url".to_string()));
        }
        validate_endpoint(&self.base_url, self.mode, "registry_mode")?;
        if matches!(self.mode, EndpointMode::Tls) {
            let tls = self
                .tls
                .as_ref()
                .ok_or_else(|| ConfigError::Validation("registry_tls".to_string()))?;
            tls.enforce("registry_tls")?;
        }
        if self.pepper_hex.is_none() {
            return Err(ConfigError::Validation("registry_pepper".to_string()));
        }
        self.http.validate("registry")?;
        if self.pow.enabled && self.pow.max_solve_ms == 0 {
            return Err(ConfigError::Validation("registry_pow".to_string()));
        }
        if self.key_cache_ttl_secs == 0 {
            return Err(ConfigError::Validation("registry_cache_ttl".to_string()));
        }
        self.pow.validate()?;
        if let Some(tls) = &self.tls {
            tls.validate_pair()?;
        }
        Ok(())
    }
}

impl RelayConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        let base = self
            .base_url
            .as_ref()
            .ok_or_else(|| ConfigError::Validation("relay_base_url".to_string()))?;
        if base.trim().is_empty() {
            return Err(ConfigError::Validation("relay_base_url".to_string()));
        }
        validate_endpoint(base, self.mode, "relay_mode")?;
        if matches!(self.mode, EndpointMode::Tls) {
            let tls = self
                .tls
                .as_ref()
                .ok_or_else(|| ConfigError::Validation("relay_tls".to_string()))?;
            tls.enforce("relay_tls")?;
        }
        self.http.validate("relay")?;
        if let Some(tls) = &self.tls {
            tls.validate_pair()?;
        }
        Ok(())
    }
}

impl TlsConfig {
    pub fn validate_pair(&self) -> Result<(), ConfigError> {
        if self.client_cert.is_some() != self.client_key.is_some() {
            return Err(ConfigError::Validation("tls_identity".to_string()));
        }
        Ok(())
    }

    pub fn enforce(&self, scope: &str) -> Result<(), ConfigError> {
        self.validate_pair()?;
        if self.ca_cert.is_none() {
            return Err(ConfigError::Validation(format!("{}_ca_cert", scope)));
        }
        if self.client_cert.is_none() || self.client_key.is_none() {
            return Err(ConfigError::Validation(format!(
                "{}_client_identity",
                scope
            )));
        }
        if let Some(path) = &self.ca_cert {
            if !path.exists() {
                return Err(ConfigError::Validation(format!("{}_ca_cert", scope)));
            }
        }
        if let Some(cert) = &self.client_cert {
            if !cert.exists() {
                return Err(ConfigError::Validation(format!("{}_client_cert", scope)));
            }
        }
        if let Some(key) = &self.client_key {
            if !key.exists() {
                return Err(ConfigError::Validation(format!("{}_client_key", scope)));
            }
        }
        Ok(())
    }
}

impl PowConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.retry_attempts == 0 {
            return Err(ConfigError::Validation("registry_pow_retry".to_string()));
        }
        Ok(())
    }
}

impl HttpClientConfig {
    pub fn validate(&self, scope: &str) -> Result<(), ConfigError> {
        if self.timeout_secs == 0 || self.connect_timeout_secs == 0 || self.read_timeout_secs == 0 {
            return Err(ConfigError::Validation(format!("{}_timeout", scope)));
        }
        if self.retry_attempts == 0 {
            return Err(ConfigError::Validation(format!("{}_retries", scope)));
        }
        if self.retry_backoff_ms == 0 {
            return Err(ConfigError::Validation(format!("{}_backoff", scope)));
        }
        Ok(())
    }
}

impl ApiConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        let addr = self.socket_addr()?;
        if !addr.ip().is_loopback() {
            if !cfg!(feature = "ui-auth") {
                return Err(ConfigError::Validation("api_bind_addr".to_string()));
            }
            let token = std::env::var("ENIGMA_UI_TOKEN")
                .ok()
                .filter(|value| !value.trim().is_empty());
            if token.is_none() {
                return Err(ConfigError::Validation("api_bind_addr".to_string()));
            }
        }
        Ok(())
    }

    pub fn socket_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.bind_addr
            .parse()
            .map_err(|_| ConfigError::Validation("api_bind_addr".to_string()))
    }
}

fn validate_endpoint(base_url: &str, mode: EndpointMode, code: &str) -> Result<(), ConfigError> {
    if matches!(mode, EndpointMode::Tls) && base_url.starts_with("http://") {
        return Err(ConfigError::Validation(code.to_string()));
    }
    if matches!(mode, EndpointMode::Http) && base_url.starts_with("https://") {
        return Err(ConfigError::Validation(code.to_string()));
    }
    Ok(())
}

pub fn load_config(path: &Path) -> Result<EnigmaConfig, ConfigError> {
    let content = fs::read_to_string(path).map_err(|_| ConfigError::Io)?;
    let parsed: EnigmaConfig = toml::from_str(&content).map_err(|_| ConfigError::Parse)?;
    parsed.validate()?;
    Ok(parsed)
}
