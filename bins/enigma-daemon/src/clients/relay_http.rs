use crate::config::RelayConfig;
use async_trait::async_trait;
use base64::Engine;
use enigma_core::error::CoreError;
use enigma_core::relay::{RelayAck, RelayAckResponse, RelayClient, RelayPullItem, RelayPullResult};
use enigma_node_types::{RelayEnvelope, RelayKind, UserId};
use enigma_relay::{AckEntry, AckRequest, MessageMeta, PullRequest, PushRequest};
use reqwest::Response;
use std::time::Duration;

pub struct RelayHttpClient {
    base_url: String,
    http: reqwest::Client,
}

impl RelayHttpClient {
    pub fn new(cfg: &RelayConfig) -> Result<Self, CoreError> {
        let base_raw = cfg
            .base_url
            .as_ref()
            .ok_or_else(|| CoreError::Validation("relay_base_url".to_string()))?;
        let base = base_raw.trim_end_matches('/').to_string();
        if matches!(cfg.mode, crate::config::EndpointMode::Tls) && base.starts_with("http://") {
            return Err(CoreError::Validation("relay_mode".to_string()));
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
        let http = builder
            .build()
            .map_err(|_| CoreError::Transport("client".to_string()))?;
        Ok(Self {
            base_url: base,
            http,
        })
    }

    fn map_response(&self, resp: Response, label: &str) -> Result<Response, CoreError> {
        if resp.status().is_success() {
            return Ok(resp);
        }
        Err(CoreError::Relay(format!(
            "{}_{}",
            label,
            resp.status().as_u16()
        )))
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
            .http
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(|_| CoreError::Relay("push".to_string()))?;
        self.map_response(resp, "push")?;
        Ok(())
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
            .http
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(|_| CoreError::Relay("pull".to_string()))?;
        let resp = self.map_response(resp, "pull")?;
        let parsed: enigma_relay::PullResponse = resp
            .json()
            .await
            .map_err(|_| CoreError::Relay("pull_decode".to_string()))?;
        let mut items = Vec::new();
        for item in parsed.items.into_iter() {
            let to = UserId::from_hex(&item.recipient)
                .map_err(|_| CoreError::Relay("recipient".to_string()))?;
            let envelope = RelayEnvelope {
                id: item.message_id,
                to,
                from: None,
                created_at_ms: item.arrival_ms,
                expires_at_ms: Some(item.deadline_ms),
                kind: RelayKind::OpaqueMessage(enigma_node_types::OpaqueMessage {
                    blob_b64: item.ciphertext_b64,
                    content_type: None,
                }),
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
            .http
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(|_| CoreError::Relay("ack".to_string()))?;
        let resp = self.map_response(resp, "ack")?;
        let parsed: enigma_relay::AckResponse = resp
            .json()
            .await
            .map_err(|_| CoreError::Relay("ack_decode".to_string()))?;
        Ok(RelayAckResponse {
            deleted: parsed.deleted,
            missing: parsed.missing,
            remaining: parsed.remaining,
        })
    }
}
