mod config;

use config::EnigmaConfig;
use enigma_core::config::{CoreConfig, TransportMode};
use enigma_core::directory::InMemoryRegistry;
use enigma_core::messaging::MockTransport;
use enigma_core::relay::InMemoryRelay;
use enigma_core::Core;
use enigma_storage::key_provider::{KeyProvider, MasterKey};
use enigma_storage::EnigmaStorageError;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::server::conn::http1;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use http_body_util::Full;
use bytes::Bytes;
use log::LevelFilter;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

#[derive(Clone)]
struct DaemonKey;

impl KeyProvider for DaemonKey {
    fn get_or_create_master_key(&self) -> Result<MasterKey, EnigmaStorageError> {
        Ok(MasterKey::new([2u8; 32]))
    }

    fn get_master_key(&self) -> Result<MasterKey, EnigmaStorageError> {
        Ok(MasterKey::new([2u8; 32]))
    }
}

#[derive(thiserror::Error, Debug)]
enum DaemonError {
    #[error("config")]
    Config,
    #[error("core")]
    Core,
}

#[tokio::main]
async fn main() -> Result<(), DaemonError> {
    let args: Vec<String> = std::env::args().collect();
    let mut path = PathBuf::from("enigma.toml");
    let mut i = 1;
    while i + 1 < args.len() {
        if args[i] == "--config" {
            path = PathBuf::from(&args[i + 1]);
        }
        i += 1;
    }
    let cfg = config::load_config(&path).map_err(|_| DaemonError::Config)?;
    init_logging(&cfg);
    let core = init_core(&cfg).await?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let server = start_control_server(core.clone(), shutdown_rx).await?;
    let ctrl_c = signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let _ = ctrl_c.as_mut().await;
    let _ = shutdown_tx.send(());
    let _ = server.await;
    Ok(())
}

fn init_logging(cfg: &EnigmaConfig) {
    let level = match cfg.logging.level.to_lowercase().as_str() {
        "trace" => LevelFilter::Trace,
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };
    let _ = env_logger::Builder::from_default_env()
        .filter_level(level)
        .try_init();
}

async fn init_core(cfg: &EnigmaConfig) -> Result<Arc<Core>, DaemonError> {
    let data_dir = cfg.data_dir.clone();
    let storage_path = data_dir.join("core");
    let registry_urls = if cfg.registry.enabled {
        cfg.registry.endpoints.clone()
    } else {
        Vec::new()
    };
    let relay_urls = if cfg.relay.enabled {
        cfg.relay
            .endpoint
            .clone()
            .into_iter()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let namespace = format!("daemon-{}", cfg.identity.user_handle);
    let _ = cfg.transport.webrtc.stun_servers.len();
    let core_cfg = CoreConfig {
        storage_path: storage_path
            .to_str()
            .unwrap_or(".enigma")
            .to_string(),
        namespace,
        node_base_urls: registry_urls,
        relay_base_urls: relay_urls,
        device_name: cfg.identity.device_name.clone(),
        enable_read_receipts: true,
        enable_typing: true,
        enable_ephemeral: true,
        default_ephemeral_secs: None,
        allow_attachments: true,
        transport_mode: if cfg.transport.webrtc.enabled {
            TransportMode::Hybrid
        } else {
            TransportMode::RelayOnly
        },
        polling_interval_ms: 1000,
    };
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(InMemoryRelay::new());
    let transport: Arc<dyn enigma_core::messaging::Transport> = Arc::new(MockTransport::new());
    Core::init(
        core_cfg,
        cfg.policy.clone(),
        Arc::new(DaemonKey),
        registry,
        relay,
        transport,
    )
    .await
    .map(Arc::new)
    .map_err(|_| DaemonError::Core)
}

async fn start_control_server(core: Arc<Core>, shutdown: oneshot::Receiver<()>) -> Result<JoinHandle<()>, DaemonError> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(_) => {
            let handle = tokio::spawn(async move {
                let _ = shutdown.await;
            });
            return Ok(handle);
        }
    };
    let handle = tokio::spawn(async move {
        let mut shutdown = shutdown;
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    break;
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, _)) => {
                            let core_clone = core.clone();
                            tokio::spawn(async move {
                                let io = TokioIo::new(stream);
                                let service = service_fn(move |req: Request<Incoming>| {
                                    let core = core_clone.clone();
                                    async move { handle_request(core, req).await }
                                });
                                let _ = http1::Builder::new().serve_connection(io, service).await;
                            });
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });
    Ok(handle)
}

async fn handle_request(core: Arc<Core>, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match (req.method().as_str(), req.uri().path()) {
        ("GET", "/health") => Ok(Response::new(Full::from(
            serde_json::json!({"status":"ok"}).to_string(),
        ))),
        ("GET", "/stats") => {
            let stats = core.stats().await;
            let body = serde_json::json!({
                "user_id_hex": stats.user_id_hex,
                "device_id": stats.device_id.to_string(),
                "conversations": stats.conversations,
                "groups": stats.groups,
                "channels": stats.channels,
                "pending_outbox": stats.pending_outbox,
                "directory_len": stats.directory_len
            });
            Ok(Response::new(Full::from(body.to_string())))
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::from(Bytes::from_static(b"not found")))
            .unwrap()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{IdentityConfig, LoggingConfig, RegistryConfig, RelayConfig, TransportConfig, WebRtcConfig};
    use enigma_core::policy::Policy;
    use tempfile::tempdir;
    use std::time::Duration;

    #[tokio::test]
    async fn config_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("conf.toml");
        let cfg = format!(
            r#"
data_dir = "{dir}"

[identity]
user_handle = "alice"
device_name = "device"

[policy]
max_text_bytes = 1
max_message_rate_per_minute = 1
max_inline_media_bytes = 1
max_attachment_chunk_bytes = 1
max_attachment_parallel_chunks = 1
max_group_name_len = 1
max_channel_name_len = 1
max_membership_changes_per_minute = 1
max_retry_window_secs = 1
backoff_initial_ms = 1
backoff_max_ms = 1
outbox_batch_send = 1
directory_ttl_secs = 1
directory_refresh_on_send = false
receipt_aggregation = "Any"
group_crypto_mode = "Fanout"
sender_keys_rotate_every_msgs = 1
sender_keys_rotate_on_membership_change = false

[registry]
enabled = true
endpoints = []

[relay]
enabled = true
endpoint = "https://relay.example.com"

[transport.webrtc]
enabled = false
stun_servers = []

[logging]
level = "info"
"#,
            dir = dir.path().display()
        );
        std::fs::write(&path, cfg).unwrap();
        let loaded = config::load_config(&path).unwrap();
        assert_eq!(loaded.identity.user_handle, "alice");
        assert!(loaded.relay.enabled);
    }

    #[tokio::test]
    async fn daemon_starts_and_stops() {
        let dir = tempdir().unwrap();
        let cfg = EnigmaConfig {
            data_dir: dir.path().to_path_buf(),
            identity: IdentityConfig {
                user_handle: "alice".to_string(),
                device_name: None,
            },
            policy: Policy::default(),
            registry: RegistryConfig {
                enabled: true,
                endpoints: Vec::new(),
            },
            relay: RelayConfig {
                enabled: true,
                endpoint: None,
            },
            transport: TransportConfig {
                webrtc: WebRtcConfig {
                    enabled: false,
                    stun_servers: Vec::new(),
                },
            },
            logging: LoggingConfig {
                level: "error".to_string(),
            },
        };
        init_logging(&cfg);
        let core = init_core(&cfg).await.unwrap();
        let (tx, rx) = oneshot::channel();
        let handle = start_control_server(core, rx).await.unwrap();
        let _ = tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }
}
