use crate::config::RegistryConfig;
use async_trait::async_trait;
use enigma_core::directory::RegistryClient;
use enigma_core::error::CoreError;
use enigma_node_registry::envelope::{EnvelopePublicKey, IdentityEnvelope};
use enigma_node_types::Presence;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub struct RegistryHttpClient {
    base_url: String,
    http: reqwest::Client,
    pepper: [u8; 32],
    pow_enabled: bool,
}

#[derive(Serialize)]
struct RegisterPayload {
    handle: String,
    envelope: IdentityEnvelope,
}

#[derive(Serialize)]
struct ResolvePayload {
    handle: String,
    requester_ephemeral_pubkey_hex: String,
}

#[derive(Deserialize)]
struct ResolveResponse {
    envelope: Option<IdentityEnvelope>,
}

#[derive(Deserialize)]
struct CheckUserResponse {
    exists: bool,
}

impl RegistryHttpClient {
    pub fn new(cfg: &RegistryConfig) -> Result<Self, CoreError> {
        let base = cfg.base_url.trim_end_matches('/').to_string();
        if matches!(cfg.mode, crate::config::EndpointMode::Tls) && base.starts_with("http://") {
            return Err(CoreError::Validation("registry_mode".to_string()));
        }
        let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
        if let Some(tls) = cfg.tls.as_ref() {
            if let Some(ca) = tls.ca_cert.as_ref() {
                let pem =
                    std::fs::read(ca).map_err(|_| CoreError::Transport("tls_ca".to_string()))?;
                let cert = reqwest::Certificate::from_pem(&pem)
                    .map_err(|_| CoreError::Transport("tls_ca".to_string()))?;
                builder = builder.add_root_certificate(cert);
            }
        }
        let pepper_bytes = cfg
            .pepper_hex
            .as_ref()
            .and_then(|p| hex::decode(p).ok())
            .ok_or(CoreError::Validation("registry_pepper".to_string()))?;
        let pepper: [u8; 32] = pepper_bytes
            .try_into()
            .map_err(|_| CoreError::Validation("registry_pepper".to_string()))?;
        let http = builder
            .build()
            .map_err(|_| CoreError::Transport("client".to_string()))?;
        Ok(Self {
            base_url: base,
            http,
            pepper,
            pow_enabled: cfg.pow.enabled,
        })
    }

    fn map_pow(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if self.pow_enabled {
            builder.header("x-enigma-pow", "disabled")
        } else {
            builder
        }
    }

    async fn parse_json<T: for<'de> Deserialize<'de>>(
        &self,
        resp: Response,
    ) -> Result<T, CoreError> {
        if !resp.status().is_success() {
            return Err(CoreError::Transport(format!(
                "status_{}",
                resp.status().as_u16()
            )));
        }
        resp.json::<T>()
            .await
            .map_err(|_| CoreError::Transport("decode".to_string()))
    }
}

#[async_trait]
impl RegistryClient for RegistryHttpClient {
    async fn envelope_key(&self) -> Result<EnvelopePublicKey, CoreError> {
        let url = format!("{}/envelope_pubkey", self.base_url);
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|_| CoreError::Transport("envelope_key".to_string()))?;
        self.parse_json(resp).await
    }

    async fn register(&self, handle: &str, envelope: IdentityEnvelope) -> Result<(), CoreError> {
        let url = format!("{}/register", self.base_url);
        let payload = RegisterPayload {
            handle: handle.to_string(),
            envelope,
        };
        let resp = self
            .http
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(|_| CoreError::Transport("register".to_string()))?;
        if resp.status().is_success() {
            return Ok(());
        }
        Err(CoreError::Transport(format!(
            "status_{}",
            resp.status().as_u16()
        )))
    }

    async fn resolve(
        &self,
        handle: &str,
        requester_ephemeral_public_key: [u8; 32],
    ) -> Result<Option<IdentityEnvelope>, CoreError> {
        let url = format!("{}/resolve", self.base_url);
        let payload = ResolvePayload {
            handle: handle.to_string(),
            requester_ephemeral_pubkey_hex: hex::encode(requester_ephemeral_public_key),
        };
        let builder = self.http.post(url).json(&payload);
        let resp = self
            .map_pow(builder)
            .send()
            .await
            .map_err(|_| CoreError::Transport("resolve".to_string()))?;
        let parsed: ResolveResponse = self.parse_json(resp).await?;
        Ok(parsed.envelope)
    }

    async fn check_user(&self, handle: &str) -> Result<bool, CoreError> {
        let url = format!("{}/check_user/{}", self.base_url, handle);
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|_| CoreError::Transport("check_user".to_string()))?;
        let parsed: CheckUserResponse = self.parse_json(resp).await?;
        Ok(parsed.exists)
    }

    async fn announce_presence(&self, presence: Presence) -> Result<(), CoreError> {
        let url = format!("{}/announce", self.base_url);
        let resp = self
            .http
            .post(url)
            .json(&presence)
            .send()
            .await
            .map_err(|_| CoreError::Transport("announce".to_string()))?;
        if resp.status().is_success() {
            return Ok(());
        }
        Err(CoreError::Transport(format!(
            "status_{}",
            resp.status().as_u16()
        )))
    }

    fn envelope_pepper(&self) -> Option<[u8; 32]> {
        Some(self.pepper)
    }

    fn endpoints(&self) -> Vec<String> {
        vec![self.base_url.clone()]
    }
}
