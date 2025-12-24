use crate::config::RegistryConfig;
use async_trait::async_trait;
use enigma_core::directory::RegistryClient;
use enigma_core::error::{CoreError, ExternalError};
use enigma_node_registry::envelope::{EnvelopePublicKey, IdentityEnvelope};
use enigma_node_types::Presence;
use reqwest::{Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use tokio::time::sleep;

pub struct RegistryHttpClient {
    base_url: String,
    http: reqwest::Client,
    pepper: [u8; 32],
    pow_enabled: bool,
    pow_retries: u32,
    pow_max_solve: Duration,
    retry_attempts: u32,
    retry_backoff: Duration,
    key_cache: tokio::sync::Mutex<Option<(EnvelopePublicKey, Instant)>>,
    key_ttl: Duration,
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

#[derive(Deserialize)]
struct PowChallenge {
    challenge: String,
    difficulty: u8,
    _expires_ms: u64,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: ErrorBody,
}

#[derive(Deserialize)]
struct ErrorBody {
    code: String,
    message: String,
    details: Option<Value>,
}

impl RegistryHttpClient {
    pub fn new(cfg: &RegistryConfig) -> Result<Self, CoreError> {
        cfg.validate()
            .map_err(|e| CoreError::Validation(e.to_string()))?;
        let base = cfg.base_url.trim_end_matches('/').to_string();
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.http.timeout_secs))
            .connect_timeout(Duration::from_secs(cfg.http.connect_timeout_secs))
            .read_timeout(Duration::from_secs(cfg.http.read_timeout_secs));
        if let Some(tls) = cfg.tls.as_ref() {
            if let Some(ca) = tls.ca_cert.as_ref() {
                let pem =
                    std::fs::read(ca).map_err(|_| CoreError::Transport("tls_ca".to_string()))?;
                let cert = reqwest::Certificate::from_pem(&pem)
                    .map_err(|_| CoreError::Transport("tls_ca".to_string()))?;
                builder = builder.add_root_certificate(cert);
            }
            if let (Some(cert_path), Some(key_path)) =
                (tls.client_cert.as_ref(), tls.client_key.as_ref())
            {
                let cert_bytes = std::fs::read(cert_path)
                    .map_err(|_| CoreError::Transport("tls_client_cert".to_string()))?;
                let key_bytes = std::fs::read(key_path)
                    .map_err(|_| CoreError::Transport("tls_client_key".to_string()))?;
                let identity = reqwest::Identity::from_pem(&[cert_bytes, key_bytes].concat())
                    .map_err(|_| CoreError::Transport("tls_identity".to_string()))?;
                builder = builder.identity(identity);
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
            pow_retries: cfg.pow.retry_attempts,
            pow_max_solve: Duration::from_millis(cfg.pow.max_solve_ms),
            retry_attempts: cfg.http.retry_attempts,
            retry_backoff: Duration::from_millis(cfg.http.retry_backoff_ms),
            key_cache: tokio::sync::Mutex::new(None),
            key_ttl: Duration::from_secs(cfg.key_cache_ttl_secs),
        })
    }

    fn external(
        &self,
        code: &str,
        message: String,
        retryable: bool,
        details: Option<Value>,
    ) -> CoreError {
        CoreError::External(ExternalError {
            code: code.to_string(),
            message,
            details,
            retryable,
        })
    }

    fn should_retry_status(&self, status: StatusCode) -> bool {
        status.is_server_error()
            || status == StatusCode::TOO_MANY_REQUESTS
            || status == StatusCode::REQUEST_TIMEOUT
    }

    async fn send_with_retry<F, Fut>(&self, mut op: F, label: &str) -> Result<Response, CoreError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<Response, reqwest::Error>>,
    {
        let mut remaining = self.retry_attempts;
        loop {
            match op().await {
                Ok(resp) => {
                    if self.should_retry_status(resp.status()) && remaining > 0 {
                        remaining = remaining.saturating_sub(1);
                        sleep(self.retry_backoff).await;
                        continue;
                    }
                    return Ok(resp);
                }
                Err(err) => {
                    if remaining == 0 {
                        return Err(self.map_reqwest_error(err, label));
                    }
                    remaining = remaining.saturating_sub(1);
                    sleep(self.retry_backoff).await;
                }
            }
        }
    }

    fn map_reqwest_error(&self, err: reqwest::Error, code: &str) -> CoreError {
        let lower = err.to_string().to_lowercase();
        let tls = lower.contains("tls");
        let unavailable = err.is_connect() || err.is_timeout();
        let mapped = if tls {
            "REGISTRY_TLS_ERROR"
        } else if unavailable {
            "REGISTRY_UNAVAILABLE"
        } else {
            "REGISTRY_BAD_RESPONSE"
        };
        self.external(mapped, format!("{}: {}", code, err), unavailable, None)
    }

    async fn map_error_response(&self, resp: Response, label: &str) -> CoreError {
        let status = resp.status();
        let parsed = resp.json::<ErrorResponse>().await.ok();
        let message = parsed
            .as_ref()
            .map(|e| e.error.message.clone())
            .unwrap_or_else(|| format!("{}:{:?}", label, status));
        let details = parsed.as_ref().and_then(|e| e.error.details.clone());
        let (code, retryable) = match parsed.as_ref().map(|p| p.error.code.as_str()) {
            Some("RATE_LIMITED") => ("REGISTRY_RATE_LIMITED", true),
            Some("POW_REQUIRED") => ("REGISTRY_POW_REQUIRED", true),
            Some("INVALID_INPUT") => {
                let lower = message.to_lowercase();
                if lower.contains("envelope key") {
                    ("REGISTRY_BAD_KEY", true)
                } else {
                    ("REGISTRY_BAD_RESPONSE", false)
                }
            }
            Some("UNAUTHORIZED") => ("REGISTRY_UNAUTHORIZED", false),
            Some("FEATURE_DISABLED") | Some("CONFIG") => ("REGISTRY_BAD_RESPONSE", false),
            _ => {
                if self.should_retry_status(status) {
                    ("REGISTRY_UNAVAILABLE", true)
                } else {
                    ("REGISTRY_BAD_RESPONSE", false)
                }
            }
        };
        self.external(code, message, retryable, details)
    }

    async fn parse_success<T: for<'de> Deserialize<'de>>(
        &self,
        resp: Response,
        label: &str,
    ) -> Result<T, CoreError> {
        if resp.status().is_success() {
            return resp.json::<T>().await.map_err(|err| {
                self.external("REGISTRY_BAD_RESPONSE", err.to_string(), false, None)
            });
        }
        Err(self.map_error_response(resp, label).await)
    }

    async fn envelope_keys(&self) -> Result<Vec<EnvelopePublicKey>, CoreError> {
        let url = format!("{}/envelope_pubkeys", self.base_url);
        let resp = self
            .send_with_retry(|| self.http.get(url.clone()).send(), "envelope_pubkeys")
            .await?;
        if resp.status() == StatusCode::NOT_FOUND {
            let fallback = format!("{}/envelope_pubkey", self.base_url);
            let single = self
                .send_with_retry(|| self.http.get(fallback.clone()).send(), "envelope_pubkey")
                .await?;
            let parsed: EnvelopePublicKey = self.parse_success(single, "envelope_pubkey").await?;
            return Ok(vec![parsed]);
        }
        self.parse_success(resp, "envelope_pubkeys").await
    }

    async fn active_envelope_key(&self) -> Result<EnvelopePublicKey, CoreError> {
        let now = Instant::now();
        if let Some((cached, expires)) = self.key_cache.lock().await.clone() {
            if now < expires {
                return Ok(cached);
            }
        }
        let keys = self.envelope_keys().await?;
        let chosen = keys
            .iter()
            .find(|k| k.active)
            .cloned()
            .or_else(|| keys.first().cloned())
            .ok_or_else(|| {
                self.external(
                    "REGISTRY_BAD_RESPONSE",
                    "no envelope keys".to_string(),
                    false,
                    None,
                )
            })?;
        let mut guard = self.key_cache.lock().await;
        *guard = Some((chosen.clone(), Instant::now() + self.key_ttl));
        Ok(chosen)
    }

    async fn pow_header(&self) -> Result<Option<String>, CoreError> {
        if !self.pow_enabled {
            return Ok(None);
        }
        let mut attempts = 0;
        let url = format!("{}/pow/challenge", self.base_url);
        loop {
            let resp = self
                .send_with_retry(|| self.http.get(url.clone()).send(), "pow_challenge")
                .await?;
            let challenge: PowChallenge = match self.parse_success(resp, "pow_challenge").await {
                Ok(c) => c,
                Err(err) => {
                    if attempts < self.pow_retries {
                        attempts += 1;
                        sleep(self.retry_backoff).await;
                        continue;
                    }
                    return Err(err);
                }
            };
            match self.solve_pow(&challenge) {
                Ok(solution) => {
                    return Ok(Some(format!("{}:{}", challenge.challenge, solution)));
                }
                Err(err) => {
                    if matches!(&err, CoreError::External(ext) if ext.retryable)
                        && attempts < self.pow_retries
                    {
                        attempts += 1;
                        sleep(self.retry_backoff).await;
                        continue;
                    }
                    return Err(err);
                }
            }
        }
    }

    fn solve_pow(&self, challenge: &PowChallenge) -> Result<String, CoreError> {
        let start = Instant::now();
        let mut nonce: u64 = 0;
        loop {
            let candidate = nonce.to_string();
            let mut hasher = Sha256::new();
            hasher.update(challenge.challenge.as_bytes());
            hasher.update(candidate.as_bytes());
            let digest = hasher.finalize();
            if meets_difficulty(&digest, challenge.difficulty) {
                return Ok(candidate);
            }
            if start.elapsed() > self.pow_max_solve {
                return Err(self.external(
                    "REGISTRY_POW_REQUIRED",
                    "pow solving timed out".to_string(),
                    true,
                    None,
                ));
            }
            nonce = nonce.wrapping_add(1);
        }
    }
}

fn meets_difficulty(digest: &[u8], difficulty: u8) -> bool {
    let zero_bytes = (difficulty / 8) as usize;
    let zero_bits = (difficulty % 8) as usize;
    if digest.len() <= zero_bytes {
        return false;
    }
    if digest.iter().take(zero_bytes).any(|b| *b != 0) {
        return false;
    }
    if zero_bits == 0 {
        return true;
    }
    digest[zero_bytes].leading_zeros() as usize >= zero_bits
}

#[async_trait]
impl RegistryClient for RegistryHttpClient {
    async fn envelope_key(&self) -> Result<EnvelopePublicKey, CoreError> {
        self.active_envelope_key().await
    }

    async fn register(&self, handle: &str, envelope: IdentityEnvelope) -> Result<(), CoreError> {
        let url = format!("{}/register", self.base_url);
        let payload = RegisterPayload {
            handle: handle.to_string(),
            envelope,
        };
        let resp = self
            .send_with_retry(
                || self.http.post(url.clone()).json(&payload).send(),
                "register",
            )
            .await?;
        if resp.status().is_success() {
            return Ok(());
        }
        let err = self.map_error_response(resp, "register").await;
        if let CoreError::External(ext) = &err {
            if ext.code == "REGISTRY_BAD_KEY" {
                let mut guard = self.key_cache.lock().await;
                *guard = None;
            }
        }
        Err(err)
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
        let pow_header = self.pow_header().await?;
        let resp = self
            .send_with_retry(
                || {
                    let mut builder = self.http.post(url.clone()).json(&payload);
                    if let Some(pow) = pow_header.clone() {
                        builder = builder.header("x-enigma-pow", pow);
                    }
                    builder.send()
                },
                "resolve",
            )
            .await?;
        let parsed: ResolveResponse = self.parse_success(resp, "resolve").await?;
        Ok(parsed.envelope)
    }

    async fn check_user(&self, handle: &str) -> Result<bool, CoreError> {
        let url = format!("{}/check_user/{}", self.base_url, handle);
        let pow_header = self.pow_header().await?;
        let resp = self
            .send_with_retry(
                || {
                    let mut builder = self.http.get(url.clone());
                    if let Some(pow) = pow_header.clone() {
                        builder = builder.header("x-enigma-pow", pow);
                    }
                    builder.send()
                },
                "check_user",
            )
            .await?;
        let parsed: CheckUserResponse = self.parse_success(resp, "check_user").await?;
        Ok(parsed.exists)
    }

    async fn announce_presence(&self, presence: Presence) -> Result<(), CoreError> {
        let url = format!("{}/announce", self.base_url);
        let resp = self
            .send_with_retry(
                || self.http.post(url.clone()).json(&presence).send(),
                "announce",
            )
            .await?;
        if resp.status().is_success() {
            return Ok(());
        }
        Err(self.map_error_response(resp, "announce").await)
    }

    fn envelope_pepper(&self) -> Option<[u8; 32]> {
        Some(self.pepper)
    }

    fn endpoints(&self) -> Vec<String> {
        vec![self.base_url.clone()]
    }
}
