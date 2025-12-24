use crate::config::RelayConfig;
use async_trait::async_trait;
use base64::Engine;
use enigma_core::error::{CoreError, ExternalError};
use enigma_core::relay::{RelayAck, RelayAckResponse, RelayClient, RelayPullItem, RelayPullResult};
use enigma_node_types::{RelayEnvelope, RelayKind, UserId};
use enigma_relay::{
    AckEntry, AckRequest, MessageMeta, PullRequest, PullResponse as RelayPullResponse, PushRequest,
};
use reqwest::{Response, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use std::time::Duration;
use tokio::time::sleep;
use uuid::Uuid;

pub struct RelayHttpClient {
    base_url: String,
    http: reqwest::Client,
    retry_attempts: u32,
    retry_backoff: Duration,
}

#[derive(Deserialize)]
struct ErrorBody {
    error: RelayError,
}

#[derive(Deserialize)]
struct RelayError {
    code: String,
    message: String,
    #[serde(default)]
    details: Option<Value>,
}

impl RelayHttpClient {
    pub fn new(cfg: &RelayConfig) -> Result<Self, CoreError> {
        cfg.validate()
            .map_err(|e| CoreError::Validation(e.to_string()))?;
        let base_raw = cfg
            .base_url
            .as_ref()
            .ok_or_else(|| CoreError::Validation("relay_base_url".to_string()))?;
        let base = base_raw.trim_end_matches('/').to_string();
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
        let http = builder
            .build()
            .map_err(|_| CoreError::Transport("client".to_string()))?;
        Ok(Self {
            base_url: base,
            http,
            retry_attempts: cfg.http.retry_attempts,
            retry_backoff: Duration::from_millis(cfg.http.retry_backoff_ms),
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

    fn map_reqwest_error(&self, err: reqwest::Error, label: &str) -> CoreError {
        let lower = err.to_string().to_lowercase();
        let tls = lower.contains("tls");
        let unavailable = err.is_connect() || err.is_timeout();
        let code = if tls {
            "RELAY_TLS_ERROR"
        } else if unavailable {
            "RELAY_UNAVAILABLE"
        } else {
            "RELAY_BAD_RESPONSE"
        };
        self.external(code, format!("{}: {}", label, err), unavailable, None)
    }

    async fn map_error_response(&self, resp: Response, label: &str) -> CoreError {
        let status = resp.status();
        let parsed = resp.json::<ErrorBody>().await.ok();
        let message = parsed
            .as_ref()
            .map(|e| e.error.message.clone())
            .unwrap_or_else(|| format!("{}:{:?}", label, status));
        let details = parsed.as_ref().and_then(|e| e.error.details.clone());
        let (code, retryable) = match parsed.as_ref().map(|p| p.error.code.as_str()) {
            Some("rate_limited") => ("RELAY_RATE_LIMITED", true),
            Some("storage_error") | Some("internal_error") => ("RELAY_UNAVAILABLE", true),
            Some("tls_error") => ("RELAY_TLS_ERROR", false),
            Some("quota_exceeded") => ("RELAY_QUOTA_EXCEEDED", false),
            Some("duplicate") => ("RELAY_DUPLICATE", false),
            _ => {
                if self.should_retry_status(status) {
                    ("RELAY_UNAVAILABLE", true)
                } else {
                    ("RELAY_BAD_RESPONSE", false)
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
            return resp
                .json::<T>()
                .await
                .map_err(|err| self.external("RELAY_BAD_RESPONSE", err.to_string(), false, None));
        }
        Err(self.map_error_response(resp, label).await)
    }

    fn relay_kind(meta: &MessageMeta, ciphertext: String, message_id: Uuid) -> RelayKind {
        match meta.kind.as_str() {
            "signaling" => RelayKind::OpaqueSignaling(enigma_node_types::OpaqueSignaling {
                blob_b64: ciphertext,
            }),
            "attachment" => {
                RelayKind::OpaqueAttachmentChunk(enigma_node_types::OpaqueAttachmentChunk {
                    blob_b64: ciphertext,
                    attachment_id: message_id,
                    index: meta.chunk_index,
                    total: Some(meta.chunk_count),
                })
            }
            _ => RelayKind::OpaqueMessage(enigma_node_types::OpaqueMessage {
                blob_b64: ciphertext,
                content_type: None,
            }),
        }
    }
}

#[async_trait]
impl RelayClient for RelayHttpClient {
    async fn push(&self, envelope: RelayEnvelope) -> Result<(), CoreError> {
        let blob_b64 = match &envelope.kind {
            RelayKind::OpaqueMessage(m) => m.blob_b64.clone(),
            RelayKind::OpaqueSignaling(s) => s.blob_b64.clone(),
            RelayKind::OpaqueAttachmentChunk(c) => c.blob_b64.clone(),
        };
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(blob_b64.as_bytes())
            .map_err(|_| CoreError::Relay("invalid_blob".to_string()))?;
        let (chunk_index, chunk_count, kind) = match &envelope.kind {
            RelayKind::OpaqueAttachmentChunk(chunk) => (
                chunk.index,
                chunk.total.unwrap_or(1),
                "attachment".to_string(),
            ),
            RelayKind::OpaqueSignaling(_) => (0, 1, "signaling".to_string()),
            RelayKind::OpaqueMessage(_) => (0, 1, "opaque".to_string()),
        };
        let meta = MessageMeta {
            kind,
            total_len: decoded.len() as u64,
            chunk_index,
            chunk_count,
            sent_ms: envelope.created_at_ms,
        };
        let payload = PushRequest {
            recipient: envelope.to.to_hex(),
            message_id: envelope.id,
            ciphertext_b64: blob_b64,
            meta,
        };
        let url = format!("{}/push", self.base_url);
        let resp = self
            .send_with_retry(|| self.http.post(url.clone()).json(&payload).send(), "push")
            .await?;
        if resp.status().is_success() {
            return Ok(());
        }
        Err(self.map_error_response(resp, "push").await)
    }

    async fn pull(
        &self,
        recipient: &str,
        cursor: Option<String>,
    ) -> Result<RelayPullResult, CoreError> {
        let payload = PullRequest {
            recipient: recipient.to_string(),
            cursor,
            max: None,
        };
        let url = format!("{}/pull", self.base_url);
        let resp = self
            .send_with_retry(|| self.http.post(url.clone()).json(&payload).send(), "pull")
            .await?;
        let parsed: RelayPullResponse = self.parse_success(resp, "pull").await?;
        let mut items = Vec::new();
        for item in parsed.items.into_iter() {
            let to = UserId::from_hex(&item.recipient).map_err(|_| {
                self.external("RELAY_BAD_RESPONSE", "recipient".to_string(), false, None)
            })?;
            let kind = Self::relay_kind(&item.meta, item.ciphertext_b64, item.message_id);
            let envelope = RelayEnvelope {
                id: item.message_id,
                to,
                from: None,
                created_at_ms: item.arrival_ms,
                expires_at_ms: Some(item.deadline_ms),
                kind,
            };
            items.push(RelayPullItem {
                envelope,
                chunk_index: item.meta.chunk_index,
            });
        }
        Ok(RelayPullResult {
            items,
            cursor: parsed.next_cursor,
        })
    }

    async fn ack(&self, recipient: &str, ack: &[RelayAck]) -> Result<RelayAckResponse, CoreError> {
        let ack_entries: Vec<AckEntry> = ack
            .iter()
            .map(|entry| AckEntry {
                message_id: entry.message_id,
                chunk_index: entry.chunk_index,
            })
            .collect();
        let payload = AckRequest {
            recipient: recipient.to_string(),
            ack: ack_entries,
        };
        let url = format!("{}/ack", self.base_url);
        let resp = self
            .send_with_retry(|| self.http.post(url.clone()).json(&payload).send(), "ack")
            .await?;
        let parsed: enigma_relay::AckResponse = self.parse_success(resp, "ack").await?;
        Ok(RelayAckResponse {
            deleted: parsed.deleted,
            missing: parsed.missing,
            remaining: parsed.remaining,
        })
    }
}
