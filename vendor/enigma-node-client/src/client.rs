use std::time::Duration;

use enigma_node_types::{
    CheckUserResponse, EnvelopePubKey, NodesPayload, Presence, RegisterRequest, RegisterResponse,
    ResolveRequest, ResolveResponse, SyncRequest, SyncResponse, MAX_IDENTITY_CIPHERTEXT,
};
use reqwest::Response;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::config::NodeClientConfig;
use crate::error::{EnigmaNodeClientError, Result};
use crate::urls;

pub struct NodeClient {
    base_url: String,
    http: reqwest::Client,
    cfg: NodeClientConfig,
}

impl NodeClient {
    pub fn new(base_url: impl Into<String>, cfg: NodeClientConfig) -> Result<NodeClient> {
        if cfg.timeout_ms == 0 {
            return Err(EnigmaNodeClientError::InvalidInput("timeout_ms"));
        }
        if cfg.connect_timeout_ms == 0 {
            return Err(EnigmaNodeClientError::InvalidInput("connect_timeout_ms"));
        }
        if cfg.max_response_bytes == 0 {
            return Err(EnigmaNodeClientError::InvalidInput("max_response_bytes"));
        }
        if cfg.user_agent.trim().is_empty() {
            return Err(EnigmaNodeClientError::InvalidInput("user_agent"));
        }
        let base_raw: String = base_url.into();
        let base = urls::validated_base(base_raw.as_str())?;
        let http = reqwest::Client::builder()
            .user_agent(cfg.user_agent.clone())
            .timeout(Duration::from_millis(cfg.timeout_ms))
            .connect_timeout(Duration::from_millis(cfg.connect_timeout_ms))
            .build()?;
        Ok(NodeClient {
            base_url: base,
            http,
            cfg,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub async fn envelope_key(&self) -> Result<EnvelopePubKey> {
        let url = urls::envelope_pubkey(&self.base_url)?;
        self.get_json(url).await
    }

    pub async fn register(&self, req: RegisterRequest) -> Result<RegisterResponse> {
        req.validate(MAX_IDENTITY_CIPHERTEXT)
            .map_err(|_| EnigmaNodeClientError::InvalidInput("register"))?;
        let url = urls::register(&self.base_url)?;
        self.post_json(url, req).await
    }

    pub async fn resolve(&self, req: ResolveRequest) -> Result<ResolveResponse> {
        req.validate()
            .map_err(|_| EnigmaNodeClientError::InvalidInput("resolve"))?;
        let url = urls::resolve(&self.base_url)?;
        self.post_json(url, req).await
    }

    pub async fn check_user(&self, handle: &str) -> Result<CheckUserResponse> {
        let validated = validate_handle(handle)?;
        let url = urls::check_user(&self.base_url, &validated)?;
        self.get_json(url).await
    }

    pub async fn announce(&self, presence: Presence) -> Result<serde_json::Value> {
        presence
            .validate()
            .map_err(|_| EnigmaNodeClientError::InvalidInput("presence"))?;
        let url = urls::announce(&self.base_url)?;
        self.post_value(url, presence).await
    }

    pub async fn sync(&self, req: SyncRequest) -> Result<SyncResponse> {
        req.validate(MAX_IDENTITY_CIPHERTEXT)
            .map_err(|_| EnigmaNodeClientError::InvalidInput("sync"))?;
        let url = urls::sync(&self.base_url)?;
        self.post_json(url, req).await
    }

    pub async fn nodes(&self) -> Result<NodesPayload> {
        let url = urls::nodes_get(&self.base_url)?;
        self.get_json(url).await
    }

    pub async fn add_nodes(&self, payload: NodesPayload) -> Result<serde_json::Value> {
        payload
            .validate()
            .map_err(|_| EnigmaNodeClientError::InvalidInput("nodes"))?;
        let url = urls::nodes_post(&self.base_url)?;
        self.post_value(url, payload).await
    }

    async fn get_json<T: DeserializeOwned>(&self, url: String) -> Result<T> {
        let resp = self.http.get(url).send().await?;
        self.handle_json_response(resp).await
    }

    async fn post_json<TReq: Serialize, TResp: DeserializeOwned>(
        &self,
        url: String,
        payload: TReq,
    ) -> Result<TResp> {
        let resp = self.http.post(url).json(&payload).send().await?;
        self.handle_json_response(resp).await
    }

    async fn post_value<TReq: Serialize>(&self, url: String, payload: TReq) -> Result<serde_json::Value> {
        let resp = self.http.post(url).json(&payload).send().await?;
        self.handle_value_response(resp).await
    }

    async fn handle_json_response<T: DeserializeOwned>(&self, resp: Response) -> Result<T> {
        let status = resp.status();
        if !status.is_success() {
            return Err(EnigmaNodeClientError::Status(status.as_u16()));
        }
        let body = resp.bytes().await?;
        if body.len() > self.cfg.max_response_bytes {
            return Err(EnigmaNodeClientError::ResponseTooLarge);
        }
        Ok(serde_json::from_slice(&body)?)
    }

    async fn handle_value_response(&self, resp: Response) -> Result<serde_json::Value> {
        let status = resp.status();
        if !status.is_success() {
            return Err(EnigmaNodeClientError::Status(status.as_u16()));
        }
        let body = resp.bytes().await?;
        if body.len() > self.cfg.max_response_bytes {
            return Err(EnigmaNodeClientError::ResponseTooLarge);
        }
        Ok(serde_json::from_slice(&body)?)
    }
}

fn validate_handle(handle: &str) -> Result<String> {
    enigma_node_types::normalize_username(handle)
        .map_err(|_| EnigmaNodeClientError::InvalidInput("handle"))
}
