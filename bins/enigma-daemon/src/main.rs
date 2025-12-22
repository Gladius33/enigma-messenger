mod config;

use bytes::Bytes;
use config::EnigmaConfig;
use enigma_core::config::{CoreConfig, TransportMode};
use enigma_core::directory::InMemoryRegistry;
use enigma_core::messaging::MockTransport;
use enigma_core::relay::InMemoryRelay;
use enigma_core::Core;
use enigma_storage::key_provider::{KeyProvider, MasterKey};
use enigma_storage::EnigmaStorageError;
use enigma_sfu::{ParticipantId, ParticipantMeta, RoomId, Sfu, SfuError, TrackId, TrackKind, VecEventSink};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::CONTENT_TYPE;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::LevelFilter;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
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

#[derive(Clone)]
struct DaemonState {
    core: Arc<Core>,
    sfu: Option<Arc<Sfu>>,
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
    let sfu = init_sfu(&cfg);
    let state = DaemonState { core, sfu };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (_addr, server) = start_control_server(state, shutdown_rx).await?;
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

fn init_sfu(cfg: &EnigmaConfig) -> Option<Arc<Sfu>> {
    if cfg.sfu.enabled {
        Some(Arc::new(Sfu::new(VecEventSink::new())))
    } else {
        None
    }
}

async fn start_control_server(state: DaemonState, shutdown: oneshot::Receiver<()>) -> Result<(Option<SocketAddr>, JoinHandle<()>), DaemonError> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(_) => {
            let handle = tokio::spawn(async move {
                let _ = shutdown.await;
            });
            return Ok((None, handle));
        }
    };
    let local_addr = listener.local_addr().ok();
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
                            let state_clone = state.clone();
                            tokio::spawn(async move {
                                let io = TokioIo::new(stream);
                                let service = service_fn(move |req: Request<Incoming>| {
                                    let state = state_clone.clone();
                                    async move { handle_request(state, req).await }
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
    Ok((local_addr, handle))
}

async fn handle_request(state: DaemonState, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.method().as_str() == "GET" && req.uri().path() == "/health" {
        return Ok(Response::new(Full::from(
            serde_json::json!({"status":"ok"}).to_string(),
        )));
    }
    if req.method().as_str() == "GET" && req.uri().path() == "/stats" {
        let stats = state.core.stats().await;
        let body = serde_json::json!({
            "user_id_hex": stats.user_id_hex,
            "device_id": stats.device_id.to_string(),
            "conversations": stats.conversations,
            "groups": stats.groups,
            "channels": stats.channels,
            "pending_outbox": stats.pending_outbox,
            "directory_len": stats.directory_len
        });
        return Ok(Response::new(Full::from(body.to_string())));
    }
    if req.uri().path().starts_with("/sfu/") {
        if let Some(sfu) = state.sfu {
            return handle_sfu_request(sfu, req).await;
        }
    }
    Ok(not_found_response())
}

async fn handle_sfu_request(sfu: Arc<Sfu>, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().trim_start_matches('/');
    let segments: Vec<&str> = path.split('/').collect();
    if segments.get(0) != Some(&"sfu") || segments.get(1) != Some(&"rooms") {
        return Ok(not_found_response());
    }
    if segments.len() == 2 {
        if req.method().as_str() != "GET" {
            return Ok(method_not_allowed_response());
        }
        let rooms = match sfu.list_rooms() {
            Ok(list) => list.into_iter().map(|id| id.to_string()).collect::<Vec<_>>(),
            Err(err) => return Ok(sfu_error_response(err)),
        };
        return Ok(json_response(
            StatusCode::OK,
            serde_json::json!({ "rooms": rooms }),
        ));
    }
    if segments.len() >= 3 {
        let room_id = match parse_room_id(segments[2]) {
            Ok(id) => id,
            Err(resp) => return Ok(resp),
        };
        if segments.len() == 3 {
            if req.method().as_str() != "GET" {
                return Ok(method_not_allowed_response());
            }
            let info = match sfu.room_info(room_id.clone()) {
                Ok(info) => info,
                Err(err) => return Ok(sfu_error_response(err)),
            };
            let participants: Vec<String> = info
                .participants
                .into_iter()
                .map(|p| p.to_string())
                .collect();
            let tracks: Vec<serde_json::Value> = info
                .tracks
                .into_iter()
                .map(|track| {
                    serde_json::json!({
                        "track_id": track.track_id.to_string(),
                        "publisher": track.publisher.to_string(),
                        "kind": track.kind,
                        "created_at_ms": track.created_at_ms,
                        "codec_hint": track.codec_hint,
                    })
                })
                .collect();
            let body = serde_json::json!({
                "room_id": room_id.to_string(),
                "participants": participants,
                "tracks": tracks,
                "subscriptions_count": info.subscriptions_count,
                "created_at_ms": info.created_at_ms,
            });
            return Ok(json_response(StatusCode::OK, body));
        }
        if segments.len() == 4 {
            if req.method().as_str() != "POST" {
                return Ok(method_not_allowed_response());
            }
            match segments[3] {
                "create" => {
                    let res = sfu.create_room(room_id.clone(), now_ms());
                    return Ok(match res {
                        Ok(_) => json_response(
                            StatusCode::CREATED,
                            serde_json::json!({"room_id": room_id.to_string()}),
                        ),
                        Err(err) => sfu_error_response(err),
                    });
                }
                "delete" => {
                    let res = sfu.delete_room(room_id.clone());
                    return Ok(match res {
                        Ok(_) => json_response(StatusCode::OK, serde_json::json!({"status":"ok"})),
                        Err(err) => sfu_error_response(err),
                    });
                }
                "join" => {
                    let parsed = parse_body::<JoinPayload>(req.into_body()).await?;
                    let payload = match parsed {
                        Ok(p) => p,
                        Err(resp) => return Ok(resp),
                    };
                    let participant_id = match parse_participant_id(&payload.participant_id) {
                        Ok(id) => id,
                        Err(resp) => return Ok(resp),
                    };
                    let meta = ParticipantMeta {
                        display_name: payload.display_name,
                        tags: HashMap::new(),
                    };
                    let res = sfu.join(room_id.clone(), participant_id, meta, now_ms());
                    return Ok(match res {
                        Ok(_) => json_response(StatusCode::OK, serde_json::json!({"status":"ok"})),
                        Err(err) => sfu_error_response(err),
                    });
                }
                "leave" => {
                    let parsed = parse_body::<LeavePayload>(req.into_body()).await?;
                    let payload = match parsed {
                        Ok(p) => p,
                        Err(resp) => return Ok(resp),
                    };
                    let participant_id = match parse_participant_id(&payload.participant_id) {
                        Ok(id) => id,
                        Err(resp) => return Ok(resp),
                    };
                    let res = sfu.leave(room_id.clone(), participant_id);
                    return Ok(match res {
                        Ok(_) => json_response(StatusCode::OK, serde_json::json!({"status":"ok"})),
                        Err(err) => sfu_error_response(err),
                    });
                }
                "publish" => {
                    let parsed = parse_body::<PublishPayload>(req.into_body()).await?;
                    let payload = match parsed {
                        Ok(p) => p,
                        Err(resp) => return Ok(resp),
                    };
                    let participant_id = match parse_participant_id(&payload.participant_id) {
                        Ok(id) => id,
                        Err(resp) => return Ok(resp),
                    };
                    let res = sfu.publish_track(
                        room_id.clone(),
                        participant_id,
                        payload.kind,
                        payload.codec_hint,
                        now_ms(),
                    );
                    return Ok(match res {
                        Ok(track_id) => json_response(
                            StatusCode::CREATED,
                            serde_json::json!({"track_id": track_id.to_string()}),
                        ),
                        Err(err) => sfu_error_response(err),
                    });
                }
                "unpublish" => {
                    let parsed = parse_body::<TrackPayload>(req.into_body()).await?;
                    let payload = match parsed {
                        Ok(p) => p,
                        Err(resp) => return Ok(resp),
                    };
                    let track_id = match parse_track_id(&payload.track_id) {
                        Ok(id) => id,
                        Err(resp) => return Ok(resp),
                    };
                    let res = sfu.unpublish_track(room_id.clone(), track_id);
                    return Ok(match res {
                        Ok(_) => json_response(StatusCode::OK, serde_json::json!({"status":"ok"})),
                        Err(err) => sfu_error_response(err),
                    });
                }
                "subscribe" => {
                    let parsed = parse_body::<SubscriptionPayload>(req.into_body()).await?;
                    let payload = match parsed {
                        Ok(p) => p,
                        Err(resp) => return Ok(resp),
                    };
                    let participant_id = match parse_participant_id(&payload.participant_id) {
                        Ok(id) => id,
                        Err(resp) => return Ok(resp),
                    };
                    let track_id = match parse_track_id(&payload.track_id) {
                        Ok(id) => id,
                        Err(resp) => return Ok(resp),
                    };
                    let res = sfu.subscribe(room_id.clone(), participant_id, track_id);
                    return Ok(match res {
                        Ok(_) => json_response(StatusCode::OK, serde_json::json!({"status":"ok"})),
                        Err(err) => sfu_error_response(err),
                    });
                }
                "unsubscribe" => {
                    let parsed = parse_body::<SubscriptionPayload>(req.into_body()).await?;
                    let payload = match parsed {
                        Ok(p) => p,
                        Err(resp) => return Ok(resp),
                    };
                    let participant_id = match parse_participant_id(&payload.participant_id) {
                        Ok(id) => id,
                        Err(resp) => return Ok(resp),
                    };
                    let track_id = match parse_track_id(&payload.track_id) {
                        Ok(id) => id,
                        Err(resp) => return Ok(resp),
                    };
                    let res = sfu.unsubscribe(room_id.clone(), participant_id, track_id);
                    return Ok(match res {
                        Ok(_) => json_response(StatusCode::OK, serde_json::json!({"status":"ok"})),
                        Err(err) => sfu_error_response(err),
                    });
                }
                _ => return Ok(not_found_response()),
            }
        }
    }
    Ok(not_found_response())
}

async fn collect_bytes(body: Incoming) -> Result<Bytes, hyper::Error> {
    let collected = body.collect().await?;
    Ok(collected.to_bytes())
}

async fn parse_body<T: DeserializeOwned>(body: Incoming) -> Result<Result<T, Response<Full<Bytes>>>, hyper::Error> {
    let bytes = collect_bytes(body).await?;
    if bytes.is_empty() {
        return Ok(Err(json_response(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"error":"empty body"}),
        )));
    }
    match serde_json::from_slice(&bytes) {
        Ok(parsed) => Ok(Ok(parsed)),
        Err(_) => Ok(Err(json_response(
            StatusCode::BAD_REQUEST,
            serde_json::json!({"error":"invalid json"}),
        ))),
    }
}

fn parse_room_id(value: &str) -> Result<RoomId, Response<Full<Bytes>>> {
    RoomId::from_str(value).map_err(sfu_error_response)
}

fn parse_participant_id(value: &str) -> Result<ParticipantId, Response<Full<Bytes>>> {
    ParticipantId::from_str(value).map_err(sfu_error_response)
}

fn parse_track_id(value: &str) -> Result<TrackId, Response<Full<Bytes>>> {
    TrackId::from_str(value).map_err(sfu_error_response)
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::from(value.to_string()))
        .unwrap()
}

fn method_not_allowed_response() -> Response<Full<Bytes>> {
    json_response(
        StatusCode::METHOD_NOT_ALLOWED,
        serde_json::json!({"error":"method not allowed"}),
    )
}

fn sfu_error_response(err: SfuError) -> Response<Full<Bytes>> {
    let status = match err {
        SfuError::InvalidId(_) => StatusCode::BAD_REQUEST,
        SfuError::AlreadyExists => StatusCode::CONFLICT,
        SfuError::RoomNotFound | SfuError::ParticipantNotFound | SfuError::TrackNotFound => {
            StatusCode::NOT_FOUND
        }
        SfuError::NotAllowed => StatusCode::FORBIDDEN,
        SfuError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    json_response(status, serde_json::json!({"error": err.to_string()}))
}

fn not_found_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::from(Bytes::from_static(b"not found")))
        .unwrap()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Deserialize)]
struct JoinPayload {
    participant_id: String,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct LeavePayload {
    participant_id: String,
}

#[derive(Deserialize)]
struct PublishPayload {
    participant_id: String,
    kind: TrackKind,
    #[serde(default)]
    codec_hint: Option<String>,
}

#[derive(Deserialize)]
struct TrackPayload {
    track_id: String,
}

#[derive(Deserialize)]
struct SubscriptionPayload {
    participant_id: String,
    track_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{IdentityConfig, LoggingConfig, RegistryConfig, RelayConfig, SfuConfig, TransportConfig, WebRtcConfig};
    use enigma_core::policy::Policy;
    use hyper::client::conn::http1 as client_http1;
    use hyper::server::conn::http1 as server_http1;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::io::duplex;

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

[sfu]
enabled = false

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
            sfu: SfuConfig {
                enabled: false,
            },
            logging: LoggingConfig {
                level: "error".to_string(),
            },
        };
        init_logging(&cfg);
        let core = init_core(&cfg).await.unwrap();
        let state = DaemonState {
            core,
            sfu: init_sfu(&cfg),
        };
        let (tx, rx) = oneshot::channel();
        let (_addr, handle) = start_control_server(state, rx).await.unwrap();
        let _ = tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    #[tokio::test]
    async fn sfu_control_endpoints() {
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
            sfu: SfuConfig {
                enabled: true,
            },
            logging: LoggingConfig {
                level: "error".to_string(),
            },
        };
        init_logging(&cfg);
        let core = init_core(&cfg).await.unwrap();
        let state = DaemonState {
            core,
            sfu: init_sfu(&cfg),
        };
        let (tx, rx) = oneshot::channel();
        let (addr, handle) = start_control_server(state.clone(), rx).await.unwrap();
        let health = dispatch_request(state.clone(), addr, build_request("GET", "/health", None)).await;
        assert_eq!(health.status(), StatusCode::OK);
        let health_body = collect_bytes(health.into_body()).await.unwrap();
        let health_json: serde_json::Value = serde_json::from_slice(&health_body).unwrap();
        assert_eq!(health_json["status"], "ok");
        let rooms = dispatch_request(state.clone(), addr, build_request("GET", "/sfu/rooms", None)).await;
        assert_eq!(rooms.status(), StatusCode::OK);
        let rooms_body = collect_bytes(rooms.into_body()).await.unwrap();
        let rooms_json: serde_json::Value = serde_json::from_slice(&rooms_body).unwrap();
        assert_eq!(
            rooms_json["rooms"].as_array().map(|a| a.is_empty()),
            Some(true)
        );
        let create = dispatch_request(state.clone(), addr, build_request("POST", "/sfu/rooms/test-room/create", None)).await;
        assert_eq!(create.status(), StatusCode::CREATED);
        let create_body = collect_bytes(create.into_body()).await.unwrap();
        let create_json: serde_json::Value = serde_json::from_slice(&create_body).unwrap();
        assert_eq!(create_json["room_id"], "test-room");
        let info = dispatch_request(state.clone(), addr, build_request("GET", "/sfu/rooms/test-room", None)).await;
        assert_eq!(info.status(), StatusCode::OK);
        let info_body = collect_bytes(info.into_body()).await.unwrap();
        let info_json: serde_json::Value = serde_json::from_slice(&info_body).unwrap();
        assert_eq!(info_json["room_id"], "test-room");
        assert_eq!(info_json["participants"].as_array().map(|a| a.len()), Some(0));
        assert_eq!(info_json["tracks"].as_array().map(|a| a.len()), Some(0));
        let _ = tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }

    fn build_request(method: &str, path: &str, body: Option<serde_json::Value>) -> Request<Full<Bytes>> {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost");
        if body.is_some() {
            builder = builder.header(CONTENT_TYPE, "application/json");
        }
        let bytes = body
            .map(|value| value.to_string().into_bytes())
            .unwrap_or_default();
        builder
            .body(Full::from(Bytes::from(bytes)))
            .unwrap()
    }

    async fn dispatch_request(state: DaemonState, addr: Option<SocketAddr>, req: Request<Full<Bytes>>) -> Response<Incoming> {
        if let Some(addr) = addr {
            return send_request(addr, req).await;
        }
        send_in_memory_request(state, req).await
    }

    async fn send_request(addr: SocketAddr, req: Request<Full<Bytes>>) -> Response<Incoming> {
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, connection) = client_http1::handshake(io).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        sender.send_request(req).await.unwrap()
    }

    async fn send_in_memory_request(state: DaemonState, req: Request<Full<Bytes>>) -> Response<Incoming> {
        let (client, server) = duplex(4096);
        let server_state = state.clone();
        let service = service_fn(move |incoming: Request<Incoming>| {
            let inner = server_state.clone();
            async move { handle_request(inner, incoming).await }
        });
        let server_task = tokio::spawn(async move {
            let io = TokioIo::new(server);
            let _ = server_http1::Builder::new().serve_connection(io, service).await;
        });
        let io = TokioIo::new(client);
        let (mut sender, connection) = client_http1::handshake(io).await.unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = sender.send_request(req).await.unwrap();
        drop(sender);
        let _ = server_task.await;
        response
    }
}
