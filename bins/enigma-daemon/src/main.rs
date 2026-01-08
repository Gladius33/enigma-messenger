mod calls;
mod clients;
mod config;
mod sfu_adapter;

use bytes::Bytes;
use calls::{
    CallManager, CallManagerError, CallRole, CallRoomState, IceDirection, SignalingRecord,
};
use clients::{registry_http::RegistryHttpClient, relay_http::RelayHttpClient};
use config::EnigmaConfig;
use enigma_core::config::{CoreConfig, TransportMode};
use enigma_core::directory::InMemoryRegistry;
use enigma_core::messaging::MockTransport;
use enigma_core::relay::InMemoryRelay;
use enigma_core::Core;
use enigma_sfu::{
    ParticipantId, ParticipantMeta, RoomId, Sfu, SfuError, TrackId, TrackKind, VecEventSink,
};
use enigma_storage::key_provider::{KeyProvider, MasterKey};
use enigma_storage::EnigmaStorageError;
use enigma_ui_api::{
    ApiError, ApiMeta, ApiResponse, ContactDto, ConversationDto, ConversationKind, DeviceInfo,
    Event, IdentityInfo, MessageDto, MessageStatus, SendMessageRequest, SendMessageResponse,
    SyncRequest, SyncResponse, API_VERSION,
};
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
use sfu_adapter::DaemonSfuAdapter;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::oneshot;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use url::form_urlencoded;

#[derive(Clone)]
struct DaemonKey;

impl KeyProvider for DaemonKey {
    fn get_or_create_master_key(&self) -> Result<MasterKey, EnigmaStorageError> {
        load_master_key()
    }

    fn get_master_key(&self) -> Result<MasterKey, EnigmaStorageError> {
        load_master_key()
    }
}

fn load_master_key() -> Result<MasterKey, EnigmaStorageError> {
    if let Ok(path) = std::env::var("ENIGMA_MASTER_KEY_PATH") {
        let value = std::fs::read_to_string(path)
            .map_err(|err| EnigmaStorageError::KeyProviderError(err.to_string()))?;
        return parse_master_key(&value);
    }
    if let Ok(value) = std::env::var("ENIGMA_MASTER_KEY_HEX") {
        return parse_master_key(&value);
    }
    Ok(MasterKey::new([2u8; 32]))
}

fn parse_master_key(value: &str) -> Result<MasterKey, EnigmaStorageError> {
    let bytes = hex::decode(value.trim())
        .map_err(|_| EnigmaStorageError::KeyProviderError("invalid master key".to_string()))?;
    if bytes.len() != 32 {
        return Err(EnigmaStorageError::InvalidKey);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(MasterKey::new(key))
}

#[derive(Clone)]
struct DaemonState {
    core: Arc<Core>,
    sfu: Option<Arc<Sfu>>,
    sfu_adapter: Option<Arc<DaemonSfuAdapter>>,
    call_manager: CallManager,
    calls_enabled: bool,
    calls_policy: CallsPolicy,
    ui_messages: Arc<Mutex<HashMap<String, Vec<MessageDto>>>>,
    ui_events: Arc<Mutex<UiEvents>>,
    ui_conversations: Arc<Mutex<HashMap<String, UiConversationEntry>>>,
}

#[derive(Clone)]
struct CallsPolicy {
    max_publish_tracks_per_participant: u32,
    max_subscriptions_per_participant: u32,
}

#[derive(thiserror::Error, Debug)]
enum DaemonError {
    #[error("config")]
    Config,
    #[error("core")]
    Core,
    #[error("bind")]
    Bind,
}

#[tokio::main]
async fn main() -> Result<(), DaemonError> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let mut path = PathBuf::from("enigma.toml");
    let mut i = 1;
    while i + 1 < args.len() {
        if args[i] == "--config" {
            path = PathBuf::from(&args[i + 1]);
        }
        i += 1;
    }
    let cfg = config::load_config(&path).map_err(|_| DaemonError::Config)?;
    let api_addr = cfg.api.socket_addr().map_err(|_| DaemonError::Config)?;
    init_logging(&cfg);
    let core = init_core(&cfg).await?;
    let (sfu, sfu_adapter) = init_sfu(&cfg);
    let calls_enabled = cfg.calls.enabled;
    let call_manager = CallManager::new();
    let calls_policy = CallsPolicy {
        max_publish_tracks_per_participant: cfg.calls.max_publish_tracks_per_participant,
        max_subscriptions_per_participant: cfg.calls.max_subscriptions_per_participant,
    };
    let state = DaemonState {
        core,
        sfu,
        sfu_adapter,
        call_manager,
        calls_enabled,
        calls_policy,
        ui_messages: Arc::new(Mutex::new(HashMap::new())),
        ui_events: Arc::new(Mutex::new(UiEvents::new())),
        ui_conversations: Arc::new(Mutex::new(HashMap::new())),
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (_addr, server) = start_control_server(state, shutdown_rx, api_addr).await?;
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
    cfg.validate().map_err(|_| DaemonError::Config)?;
    let data_dir = cfg.data_dir.clone();
    let storage_path = data_dir.join("core");
    let namespace = format!("daemon-{}", cfg.identity.user_handle);
    let _ = cfg.transport.webrtc.stun_servers.len();
    let core_cfg = CoreConfig {
        storage_path: storage_path.to_str().unwrap_or(".enigma").to_string(),
        namespace,
        user_handle: cfg.identity.user_handle.clone(),
        node_base_urls: Vec::new(),
        relay_base_urls: cfg.relay.base_url.clone().into_iter().collect::<Vec<_>>(),
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
    let registry_client: Arc<dyn enigma_core::directory::RegistryClient> = if cfg.registry.enabled {
        Arc::new(RegistryHttpClient::new(&cfg.registry).map_err(|_| DaemonError::Core)?)
    } else {
        Arc::new(InMemoryRegistry::new())
    };
    let relay_client: Arc<dyn enigma_core::relay::RelayClient> = if cfg.relay.enabled {
        if cfg.relay.base_url.is_some() {
            Arc::new(RelayHttpClient::new(&cfg.relay).map_err(|_| DaemonError::Core)?)
        } else {
            Arc::new(InMemoryRelay::new())
        }
    } else {
        Arc::new(InMemoryRelay::new())
    };
    let transport: Arc<dyn enigma_core::messaging::Transport> = Arc::new(MockTransport::new());
    Core::init(
        core_cfg,
        cfg.policy.clone(),
        Arc::new(DaemonKey),
        registry_client,
        relay_client,
        transport,
    )
    .await
    .map(Arc::new)
    .map_err(|_| DaemonError::Core)
}

fn init_sfu(cfg: &EnigmaConfig) -> (Option<Arc<Sfu>>, Option<Arc<DaemonSfuAdapter>>) {
    if cfg.sfu.enabled {
        #[cfg(feature = "webrtc-media")]
        {
            let adapter = Arc::new(DaemonSfuAdapter::new());
            let sfu = Arc::new(Sfu::with_adapter(
                Arc::new(VecEventSink::new()),
                adapter.clone(),
            ));
            return (Some(sfu), Some(adapter));
        }
        #[cfg(not(feature = "webrtc-media"))]
        {
            let sfu = Arc::new(Sfu::new(VecEventSink::new()));
            return (Some(sfu), None);
        }
    }
    (None, None)
}

async fn start_control_server(
    state: DaemonState,
    shutdown: oneshot::Receiver<()>,
    api_addr: SocketAddr,
) -> Result<(SocketAddr, JoinHandle<()>), DaemonError> {
    let mut shutdown_rx = shutdown;
    let listener = TcpListener::bind(api_addr)
        .await
        .map_err(|_| DaemonError::Bind)?;
    let local_addr = listener.local_addr().map_err(|_| DaemonError::Bind)?;
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
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

async fn handle_request(
    state: DaemonState,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if req.uri().path().starts_with("/api/") {
        return handle_ui_request(state, req).await;
    }
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
    if req.uri().path().starts_with("/calls/") {
        return handle_calls_request(state.clone(), req).await;
    }
    if req.uri().path().starts_with("/sfu/") {
        if let Some(sfu) = state.sfu.clone() {
            return handle_sfu_request(state, sfu, req).await;
        }
    }
    Ok(not_found_response())
}

async fn handle_calls_request(
    state: DaemonState,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if !state.calls_enabled {
        return Ok(calls_disabled_response());
    }
    let sfu = match state.sfu.clone() {
        Some(s) => s,
        None => return Ok(calls_disabled_response()),
    };
    let path = req.uri().path().trim_start_matches('/');
    let segments: Vec<&str> = path.split('/').collect();
    if segments.first() != Some(&"calls") || segments.len() < 3 {
        return Ok(not_found_response());
    }
    let room_id = match parse_room_id(segments[1]) {
        Ok(id) => id,
        Err(resp) => return Ok(*resp),
    };
    let action = segments[2];
    match action {
        "join" => {
            if req.method().as_str() != "POST" {
                return Ok(method_not_allowed_response());
            }
            let parsed = parse_body::<CallJoinPayload>(req.into_body()).await?;
            let payload = match parsed {
                Ok(p) => p,
                Err(resp) => return Ok(resp),
            };
            let participant_id = match parse_participant_id(&payload.participant_id) {
                Ok(id) => id,
                Err(resp) => return Ok(*resp),
            };
            let role = payload.role.unwrap_or_default();
            let res = state.call_manager.join_room(
                &sfu,
                room_id.clone(),
                participant_id.clone(),
                payload.display_name,
                role.clone(),
                now_ms(),
            );
            Ok(match res {
                Ok(participant) => json_response(
                    StatusCode::CREATED,
                    serde_json::json!({
                        "room_id": room_id.to_string(),
                        "participant_id": participant.participant_id.to_string(),
                        "role": role,
                        "updated_at_ms": participant.signaling.updated_at_ms
                    }),
                ),
                Err(err) => call_error_response(err),
            })
        }
        "leave" => {
            if req.method().as_str() != "POST" {
                return Ok(method_not_allowed_response());
            }
            let parsed = parse_body::<LeavePayload>(req.into_body()).await?;
            let payload = match parsed {
                Ok(p) => p,
                Err(resp) => return Ok(resp),
            };
            let participant_id = match parse_participant_id(&payload.participant_id) {
                Ok(id) => id,
                Err(resp) => return Ok(*resp),
            };
            let res = state
                .call_manager
                .leave_room(&sfu, room_id.clone(), participant_id);
            Ok(match res {
                Ok(_) => json_response(StatusCode::OK, serde_json::json!({"status":"ok"})),
                Err(err) => call_error_response(err),
            })
        }
        "offer" => {
            if req.method().as_str() != "POST" {
                return Ok(method_not_allowed_response());
            }
            let parsed = parse_body::<OfferPayload>(req.into_body()).await?;
            let payload = match parsed {
                Ok(p) => p,
                Err(resp) => return Ok(resp),
            };
            let participant_id = match parse_participant_id(&payload.participant_id) {
                Ok(id) => id,
                Err(resp) => return Ok(*resp),
            };
            let res = state.call_manager.upsert_offer(
                room_id.clone(),
                participant_id.clone(),
                payload.sdp,
                now_ms(),
            );
            Ok(match res {
                Ok(record) => json_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "room_id": room_id.to_string(),
                        "participant_id": participant_id.to_string(),
                        "signaling": signaling_json(&record)
                    }),
                ),
                Err(err) => call_error_response(err),
            })
        }
        "answer" => {
            if req.method().as_str() != "POST" {
                return Ok(method_not_allowed_response());
            }
            let parsed = parse_body::<AnswerPayload>(req.into_body()).await?;
            let payload = match parsed {
                Ok(p) => p,
                Err(resp) => return Ok(resp),
            };
            let participant_id = match parse_participant_id(&payload.participant_id) {
                Ok(id) => id,
                Err(resp) => return Ok(*resp),
            };
            let res = state.call_manager.upsert_answer(
                room_id.clone(),
                participant_id.clone(),
                payload.sdp,
                now_ms(),
            );
            Ok(match res {
                Ok(record) => json_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "room_id": room_id.to_string(),
                        "participant_id": participant_id.to_string(),
                        "signaling": signaling_json(&record)
                    }),
                ),
                Err(err) => call_error_response(err),
            })
        }
        "ice" => {
            if req.method().as_str() != "POST" {
                return Ok(method_not_allowed_response());
            }
            let parsed = parse_body::<IcePayload>(req.into_body()).await?;
            let payload = match parsed {
                Ok(p) => p,
                Err(resp) => return Ok(resp),
            };
            let participant_id = match parse_participant_id(&payload.participant_id) {
                Ok(id) => id,
                Err(resp) => return Ok(*resp),
            };
            let direction = match parse_direction(&payload.direction) {
                Ok(d) => d,
                Err(resp) => return Ok(*resp),
            };
            let res = state.call_manager.add_ice(
                room_id.clone(),
                participant_id.clone(),
                payload.candidate,
                direction,
                now_ms(),
            );
            Ok(match res {
                Ok(record) => json_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "room_id": room_id.to_string(),
                        "participant_id": participant_id.to_string(),
                        "signaling": signaling_json(&record)
                    }),
                ),
                Err(err) => call_error_response(err),
            })
        }
        "state" => {
            if req.method().as_str() != "GET" || segments.len() != 3 {
                return Ok(method_not_allowed_response());
            }
            let res = state.call_manager.room_state(room_id.clone());
            Ok(match res {
                Ok(room) => json_response(StatusCode::OK, room_state_json(room)),
                Err(err) => call_error_response(err),
            })
        }
        "signaling" => {
            if req.method().as_str() != "GET" || segments.len() != 4 {
                return Ok(not_found_response());
            }
            let participant_id = match parse_participant_id(segments[3]) {
                Ok(id) => id,
                Err(resp) => return Ok(*resp),
            };
            let res = state
                .call_manager
                .get_signaling(room_id.clone(), participant_id.clone());
            Ok(match res {
                Ok(record) => json_response(
                    StatusCode::OK,
                    serde_json::json!({
                        "room_id": room_id.to_string(),
                        "participant_id": participant_id.to_string(),
                        "signaling": signaling_json(&record)
                    }),
                ),
                Err(err) => call_error_response(err),
            })
        }
        _ => Ok(not_found_response()),
    }
}

async fn handle_sfu_request(
    state: DaemonState,
    sfu: Arc<Sfu>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().trim_start_matches('/');
    let segments: Vec<&str> = path.split('/').collect();
    if segments.first() != Some(&"sfu") || segments.get(1) != Some(&"rooms") {
        return Ok(not_found_response());
    }
    if segments.len() == 2 {
        if req.method().as_str() != "GET" {
            return Ok(method_not_allowed_response());
        }
        let rooms = match sfu.list_rooms() {
            Ok(list) => list
                .into_iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>(),
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
            Err(resp) => return Ok(*resp),
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
            return match segments[3] {
                "create" => {
                    let res = sfu.create_room(room_id.clone(), now_ms());
                    Ok(match res {
                        Ok(_) => json_response(
                            StatusCode::CREATED,
                            serde_json::json!({"room_id": room_id.to_string()}),
                        ),
                        Err(err) => sfu_error_response(err),
                    })
                }
                "delete" => {
                    let res = sfu.delete_room(room_id.clone());
                    Ok(match res {
                        Ok(_) => json_response(StatusCode::OK, serde_json::json!({"status":"ok"})),
                        Err(err) => sfu_error_response(err),
                    })
                }
                "join" => {
                    let parsed = parse_body::<JoinPayload>(req.into_body()).await?;
                    let payload = match parsed {
                        Ok(p) => p,
                        Err(resp) => return Ok(resp),
                    };
                    let participant_id = match parse_participant_id(&payload.participant_id) {
                        Ok(id) => id,
                        Err(resp) => return Ok(*resp),
                    };
                    let meta = ParticipantMeta {
                        display_name: payload.display_name,
                        tags: HashMap::new(),
                    };
                    let res = sfu.join(room_id.clone(), participant_id, meta, now_ms());
                    Ok(match res {
                        Ok(_) => json_response(StatusCode::OK, serde_json::json!({"status":"ok"})),
                        Err(err) => sfu_error_response(err),
                    })
                }
                "leave" => {
                    let parsed = parse_body::<LeavePayload>(req.into_body()).await?;
                    let payload = match parsed {
                        Ok(p) => p,
                        Err(resp) => return Ok(resp),
                    };
                    let participant_id = match parse_participant_id(&payload.participant_id) {
                        Ok(id) => id,
                        Err(resp) => return Ok(*resp),
                    };
                    let res = sfu.leave(room_id.clone(), participant_id);
                    Ok(match res {
                        Ok(_) => json_response(StatusCode::OK, serde_json::json!({"status":"ok"})),
                        Err(err) => sfu_error_response(err),
                    })
                }
                "publish" => {
                    let parsed = parse_body::<PublishPayload>(req.into_body()).await?;
                    let payload = match parsed {
                        Ok(p) => p,
                        Err(resp) => return Ok(resp),
                    };
                    let participant_id = match parse_participant_id(&payload.participant_id) {
                        Ok(id) => id,
                        Err(resp) => return Ok(*resp),
                    };
                    if let Some(resp) =
                        enforce_publish_limit(&state, &sfu, &room_id, &participant_id)
                    {
                        return Ok(resp);
                    }
                    let res = sfu.publish_track(
                        room_id.clone(),
                        participant_id,
                        payload.kind,
                        payload.codec_hint,
                        now_ms(),
                    );
                    Ok(match res {
                        Ok(track_id) => json_response(
                            StatusCode::CREATED,
                            serde_json::json!({"track_id": track_id.to_string()}),
                        ),
                        Err(err) => sfu_error_response(err),
                    })
                }
                "unpublish" => {
                    let parsed = parse_body::<TrackPayload>(req.into_body()).await?;
                    let payload = match parsed {
                        Ok(p) => p,
                        Err(resp) => return Ok(resp),
                    };
                    let track_id = match parse_track_id(&payload.track_id) {
                        Ok(id) => id,
                        Err(resp) => return Ok(*resp),
                    };
                    let res = sfu.unpublish_track(room_id.clone(), track_id);
                    Ok(match res {
                        Ok(_) => json_response(StatusCode::OK, serde_json::json!({"status":"ok"})),
                        Err(err) => sfu_error_response(err),
                    })
                }
                "subscribe" => {
                    let parsed = parse_body::<SubscriptionPayload>(req.into_body()).await?;
                    let payload = match parsed {
                        Ok(p) => p,
                        Err(resp) => return Ok(resp),
                    };
                    let participant_id = match parse_participant_id(&payload.participant_id) {
                        Ok(id) => id,
                        Err(resp) => return Ok(*resp),
                    };
                    let track_id = match parse_track_id(&payload.track_id) {
                        Ok(id) => id,
                        Err(resp) => return Ok(*resp),
                    };
                    if let Some(resp) =
                        enforce_subscription_limit(&state, &sfu, &room_id, &participant_id)
                    {
                        return Ok(resp);
                    }
                    let res = sfu.subscribe(room_id.clone(), participant_id, track_id);
                    Ok(match res {
                        Ok(_) => json_response(StatusCode::OK, serde_json::json!({"status":"ok"})),
                        Err(err) => sfu_error_response(err),
                    })
                }
                "unsubscribe" => {
                    let parsed = parse_body::<SubscriptionPayload>(req.into_body()).await?;
                    let payload = match parsed {
                        Ok(p) => p,
                        Err(resp) => return Ok(resp),
                    };
                    let participant_id = match parse_participant_id(&payload.participant_id) {
                        Ok(id) => id,
                        Err(resp) => return Ok(*resp),
                    };
                    let track_id = match parse_track_id(&payload.track_id) {
                        Ok(id) => id,
                        Err(resp) => return Ok(*resp),
                    };
                    let res = sfu.unsubscribe(room_id.clone(), participant_id, track_id);
                    Ok(match res {
                        Ok(_) => json_response(StatusCode::OK, serde_json::json!({"status":"ok"})),
                        Err(err) => sfu_error_response(err),
                    })
                }
                _ => Ok(not_found_response()),
            };
        }
    }
    Ok(not_found_response())
}

async fn collect_bytes(body: Incoming) -> Result<Bytes, hyper::Error> {
    let collected = body.collect().await?;
    Ok(collected.to_bytes())
}

async fn parse_body<T: DeserializeOwned>(
    body: Incoming,
) -> Result<Result<T, Response<Full<Bytes>>>, hyper::Error> {
    let bytes = collect_bytes(body).await?;
    if bytes.is_empty() {
        return Ok(Err(api_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_BODY",
            "empty body",
            None,
        )));
    }
    match serde_json::from_slice(&bytes) {
        Ok(parsed) => Ok(Ok(parsed)),
        Err(_) => Ok(Err(api_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_BODY",
            "invalid json",
            None,
        ))),
    }
}

async fn parse_ui_body<T: DeserializeOwned>(
    body: Incoming,
) -> Result<Result<T, Response<Full<Bytes>>>, hyper::Error> {
    let bytes = collect_bytes(body).await?;
    if bytes.is_empty() {
        return Ok(Err(ui_error(
            StatusCode::BAD_REQUEST,
            "INVALID_BODY",
            "empty body",
            None,
        )));
    }
    match serde_json::from_slice(&bytes) {
        Ok(parsed) => Ok(Ok(parsed)),
        Err(_) => Ok(Err(ui_error(
            StatusCode::BAD_REQUEST,
            "INVALID_BODY",
            "invalid json",
            None,
        ))),
    }
}

type BoxedResponse = Box<Response<Full<Bytes>>>;

fn parse_room_id(value: &str) -> Result<RoomId, BoxedResponse> {
    RoomId::from_str(value).map_err(|err| Box::new(sfu_error_response(err)))
}

fn parse_participant_id(value: &str) -> Result<ParticipantId, BoxedResponse> {
    ParticipantId::from_str(value).map_err(|err| Box::new(sfu_error_response(err)))
}

fn parse_track_id(value: &str) -> Result<TrackId, BoxedResponse> {
    TrackId::from_str(value).map_err(|err| Box::new(sfu_error_response(err)))
}

async fn handle_ui_request(
    state: DaemonState,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    if cfg!(feature = "ui-auth") {
        if let Ok(expected) = std::env::var("ENIGMA_UI_TOKEN") {
            let auth = req
                .headers()
                .get("authorization")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("");
            let valid = auth
                .strip_prefix("Bearer ")
                .map(|v| v == expected)
                .unwrap_or(false);
            if !valid {
                return Ok(ui_error(
                    StatusCode::UNAUTHORIZED,
                    "UNAUTHORIZED",
                    "missing or invalid token",
                    None,
                ));
            }
        }
    }
    let path = req.uri().path().trim_end_matches('/');
    if path == "/api/v1" || path == "/api/v1/" {
        return Ok(ui_ok(serde_json::json!({"status":"ok"})));
    }
    if path == "/api/v1/health" {
        return Ok(ui_ok(serde_json::json!({"status":"ok"})));
    }
    if path == "/api/v1/identity" && req.method() == hyper::Method::GET {
        let id = state.core.local_identity();
        let devices = vec![DeviceInfo {
            device_id: id.device_id.as_uuid().to_string(),
            last_seen_ms: now_ms(),
        }];
        let info = IdentityInfo {
            user_id: id.user_id.to_hex(),
            handle: id.username_hint.clone(),
            devices,
            has_bundle_v2: id.x3dh_bundle().is_some(),
            created_ms: id.public_identity.created_at_ms,
        };
        return Ok(ui_ok(info));
    }
    if path == "/api/v1/contacts/add" && req.method() == hyper::Method::POST {
        let parsed = parse_ui_body::<UiContactPayload>(req.into_body()).await?;
        let payload = match parsed {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };
        let user_id = match parse_ui_user_id(payload.handle.clone(), payload.user_id.clone()) {
            Ok(id) => id,
            Err(resp) => return Ok(*resp),
        };
        let contact = match state
            .core
            .ui_add_contact(
                payload.handle.unwrap_or_else(|| user_id.clone()),
                user_id.clone(),
                payload.display_name.clone(),
            )
            .await
        {
            Ok(c) => c,
            Err(_) => {
                return Ok(ui_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "CONTACT_ERROR",
                    "failed",
                    None,
                ))
            }
        };
        let dto = ContactDto {
            user_id: contact.user_id.clone(),
            handle: contact.handle.clone(),
            display_name: contact.alias.clone(),
            last_seen_ms: contact.last_resolved_ms,
        };
        {
            let mut events = state.ui_events.lock().await;
            events.push(Event::ContactAdded(dto.clone()));
        }
        return Ok(ui_ok(dto));
    }
    if path == "/api/v1/contacts" && req.method() == hyper::Method::GET {
        let contacts = state.core.ui_contacts().await;
        let dtos: Vec<ContactDto> = contacts
            .into_iter()
            .map(|c| ContactDto {
                user_id: c.user_id,
                handle: c.handle,
                display_name: c.alias,
                last_seen_ms: c.last_resolved_ms,
            })
            .collect();
        return Ok(ui_ok(dtos));
    }
    if path == "/api/v1/conversations/create" && req.method() == hyper::Method::POST {
        let parsed = parse_ui_body::<UiConversationPayload>(req.into_body()).await?;
        let payload = match parsed {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };
        let peer_id = match parse_ui_user_id(payload.handle, payload.user_id) {
            Ok(id) => id,
            Err(resp) => return Ok(*resp),
        };
        let user = match enigma_core::ids::UserId::from_hex(&peer_id) {
            Some(u) => u,
            None => {
                return Ok(ui_error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_USER",
                    "invalid user",
                    None,
                ))
            }
        };
        let conv = state.core.dm_conversation(&user);
        let title = payload.title.clone();
        {
            let mut map = state.ui_conversations.lock().await;
            map.insert(
                conv.value.clone(),
                UiConversationEntry {
                    peer_user_id: peer_id.clone(),
                    title: title.clone(),
                },
            );
        }
        let dto = ConversationDto {
            id: conv.value.clone(),
            kind: ConversationKind::Direct,
            title,
            members: vec![peer_id.clone()],
            unread_count: 0,
            last_message: None,
        };
        return Ok(ui_ok(dto));
    }
    if path == "/api/v1/conversations" && req.method() == hyper::Method::GET {
        let map = state.ui_conversations.lock().await;
        let convs: Vec<ConversationDto> = map
            .iter()
            .map(|(id, entry)| ConversationDto {
                id: id.clone(),
                kind: ConversationKind::Direct,
                title: entry.title.clone(),
                members: vec![entry.peer_user_id.clone()],
                unread_count: 0,
                last_message: None,
            })
            .collect();
        return Ok(ui_ok(convs));
    }
    if path.starts_with("/api/v1/conversations/") && req.method() == hyper::Method::GET {
        let segments: Vec<&str> = path.split('/').collect();
        if segments.len() == 6 && segments[3] == "conversations" && segments[5] == "messages" {
            let conv_id = segments[4];
            let query = req.uri().query().unwrap_or("");
            let mut cursor: Option<u64> = None;
            let mut limit: usize = 50;
            for (k, v) in form_urlencoded::parse(query.as_bytes()) {
                if k == "cursor" {
                    if let Ok(val) = v.parse::<u64>() {
                        cursor = Some(val);
                    }
                } else if k == "limit" {
                    if let Ok(val) = v.parse::<usize>() {
                        limit = val;
                    }
                }
            }
            let messages = {
                let mut store = state.ui_messages.lock().await;
                let list = store.entry(conv_id.to_string()).or_default();
                let start = cursor.unwrap_or(0) as usize;
                if start >= list.len() {
                    return Ok(ui_ok(Vec::<MessageDto>::new()));
                }
                let end = (start + limit).min(list.len());
                list[start..end].to_vec()
            };
            return Ok(ui_ok(messages));
        }
    }
    if path == "/api/v1/messages/send" && req.method() == hyper::Method::POST {
        let parsed = parse_ui_body::<SendMessageRequest>(req.into_body()).await?;
        let payload = match parsed {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };
        let peer = {
            let map = state.ui_conversations.lock().await;
            map.get(&payload.conversation_id).cloned()
        };
        let peer = match peer {
            Some(p) => p,
            None => {
                return Ok(ui_error(
                    StatusCode::BAD_REQUEST,
                    "UNKNOWN_CONVERSATION",
                    "unknown conversation",
                    None,
                ))
            }
        };
        let kind = match parse_ui_message_kind(&payload.kind) {
            Ok(k) => k,
            Err(resp) => return Ok(*resp),
        };
        let msg_id = enigma_api::types::MessageId::random();
        let req_core = enigma_api::types::OutgoingMessageRequest {
            client_message_id: msg_id.clone(),
            conversation_id: enigma_api::types::ConversationId {
                value: payload.conversation_id.clone(),
            },
            sender: enigma_api::types::UserIdHex {
                value: state.core.local_identity().user_id.to_hex(),
            },
            recipients: vec![enigma_api::types::OutgoingRecipient {
                recipient_user_id: Some(peer.peer_user_id.clone()),
                recipient_handle: None,
            }],
            kind: kind.clone(),
            text: payload.body.clone(),
            attachment: None,
            attachment_bytes: None,
            ephemeral_expiry_secs: None,
            metadata: None,
        };
        let send_res = state.core.send_message(req_core).await;
        if send_res.is_err() {
            return Ok(ui_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SEND_FAILED",
                "failed to send",
                None,
            ));
        }
        let dto = MessageDto {
            id: msg_id.value.to_string(),
            conversation_id: payload.conversation_id.clone(),
            sender: state.core.local_identity().user_id.to_hex(),
            sent_ms: now_ms(),
            edited_ms: None,
            kind: ui_kind_label(&kind).to_string(),
            body_preview: payload.body.clone(),
            attachments_meta: None,
            status: MessageStatus::Sent,
        };
        store_message(&state, dto.clone()).await;
        let resp = SendMessageResponse {
            message_id: msg_id.value.to_string(),
            status: MessageStatus::Sent,
        };
        return Ok(ui_ok(resp));
    }
    if path == "/api/v1/sync" && req.method() == hyper::Method::POST {
        let parsed = parse_ui_body::<SyncRequest>(req.into_body()).await?;
        let payload = match parsed {
            Ok(p) => p,
            Err(resp) => return Ok(resp),
        };
        let limit = payload.limit.unwrap_or(50);
        let (events, next) = {
            let log = state.ui_events.lock().await;
            log.since(payload.cursor, limit)
        };
        let resp = SyncResponse {
            events,
            next_cursor: next,
        };
        return Ok(ui_ok(resp));
    }
    if path == "/api/v1/stats" && req.method() == hyper::Method::GET {
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
        return Ok(ui_ok(body));
    }
    Ok(ui_error(
        StatusCode::NOT_FOUND,
        "NOT_FOUND",
        "not found",
        None,
    ))
}

fn ui_meta() -> ApiMeta {
    ApiMeta {
        api_version: API_VERSION,
        request_id: uuid::Uuid::new_v4(),
        timestamp_ms: now_ms(),
    }
}

fn ui_ok<T: serde::Serialize>(data: T) -> Response<Full<Bytes>> {
    let resp = ApiResponse {
        meta: ui_meta(),
        data: Some(data),
        error: None,
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::from(serde_json::to_string(&resp).unwrap()))
        .unwrap()
}

fn ui_error(
    status: StatusCode,
    code: &str,
    message: impl Into<String>,
    details: Option<serde_json::Value>,
) -> Response<Full<Bytes>> {
    let resp: ApiResponse<serde_json::Value> = ApiResponse {
        meta: ui_meta(),
        data: None,
        error: Some(ApiError {
            code: code.to_string(),
            message: message.into(),
            details,
        }),
    };
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::from(serde_json::to_string(&resp).unwrap()))
        .unwrap()
}

async fn store_message(state: &DaemonState, message: MessageDto) {
    {
        let mut map = state.ui_messages.lock().await;
        map.entry(message.conversation_id.clone())
            .or_default()
            .push(message.clone());
    }
    let mut events = state.ui_events.lock().await;
    events.push(Event::Message(message));
}

#[derive(Clone)]
struct UiConversationEntry {
    peer_user_id: String,
    title: Option<String>,
}

#[derive(Default)]
struct UiEvents {
    cursor: u64,
    events: Vec<(u64, Event)>,
}

impl UiEvents {
    fn new() -> Self {
        Self {
            cursor: 0,
            events: Vec::new(),
        }
    }

    fn push(&mut self, event: Event) {
        self.cursor = self.cursor.saturating_add(1);
        self.events.push((self.cursor, event));
    }

    fn since(&self, cursor: Option<u64>, limit: usize) -> (Vec<Event>, Option<u64>) {
        let start = cursor.unwrap_or(0);
        let mut collected = Vec::new();
        let mut next = None;
        for (idx, ev) in self.events.iter() {
            if *idx > start {
                collected.push(ev.clone());
                if collected.len() >= limit {
                    next = Some(*idx);
                    break;
                }
            }
        }
        if next.is_none() {
            if let Some(last) = self.events.last() {
                next = Some(last.0);
            }
        }
        (collected, next)
    }
}

#[derive(Deserialize)]
struct UiContactPayload {
    handle: Option<String>,
    user_id: Option<String>,
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct UiConversationPayload {
    handle: Option<String>,
    user_id: Option<String>,
    title: Option<String>,
}

fn parse_ui_message_kind(kind: &str) -> Result<enigma_api::types::MessageKind, BoxedResponse> {
    match kind.to_lowercase().as_str() {
        "text" => Ok(enigma_api::types::MessageKind::Text),
        "file" => Ok(enigma_api::types::MessageKind::File),
        "image" => Ok(enigma_api::types::MessageKind::Image),
        "video" => Ok(enigma_api::types::MessageKind::Video),
        "voice" => Ok(enigma_api::types::MessageKind::Voice),
        "system" => Ok(enigma_api::types::MessageKind::System),
        "callsignal" => Ok(enigma_api::types::MessageKind::CallSignal),
        "channelpost" => Ok(enigma_api::types::MessageKind::ChannelPost),
        "groupevent" => Ok(enigma_api::types::MessageKind::GroupEvent),
        _ => Err(Box::new(ui_error(
            StatusCode::BAD_REQUEST,
            "INVALID_MESSAGE_KIND",
            "unsupported message kind",
            None,
        ))),
    }
}

fn ui_kind_label(kind: &enigma_api::types::MessageKind) -> &'static str {
    match kind {
        enigma_api::types::MessageKind::Text => "Text",
        enigma_api::types::MessageKind::File => "File",
        enigma_api::types::MessageKind::Image => "Image",
        enigma_api::types::MessageKind::Video => "Video",
        enigma_api::types::MessageKind::Voice => "Voice",
        enigma_api::types::MessageKind::System => "System",
        enigma_api::types::MessageKind::CallSignal => "CallSignal",
        enigma_api::types::MessageKind::ChannelPost => "ChannelPost",
        enigma_api::types::MessageKind::GroupEvent => "GroupEvent",
    }
}

fn parse_ui_user_id(
    handle: Option<String>,
    user_id: Option<String>,
) -> Result<String, BoxedResponse> {
    match (user_id, handle) {
        (Some(id), _) => Ok(id),
        (None, Some(handle)) => {
            let normalized = match enigma_node_types::normalize_username(&handle) {
                Ok(n) => n,
                Err(_) => {
                    return Err(Box::new(ui_error(
                        StatusCode::BAD_REQUEST,
                        "INVALID_HANDLE",
                        "invalid handle",
                        None,
                    )))
                }
            };
            match enigma_node_types::UserId::from_username(&normalized) {
                Ok(u) => Ok(u.to_hex()),
                Err(_) => Err(Box::new(ui_error(
                    StatusCode::BAD_REQUEST,
                    "INVALID_HANDLE",
                    "invalid handle",
                    None,
                ))),
            }
        }
        _ => Err(Box::new(ui_error(
            StatusCode::BAD_REQUEST,
            "INVALID_REQUEST",
            "handle or user_id required",
            None,
        ))),
    }
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .body(Full::from(value.to_string()))
        .unwrap()
}

fn error_body(
    code: &str,
    message: impl Into<String>,
    details: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut root = serde_json::json!({
        "error": {
            "code": code,
            "message": message.into(),
        }
    });
    if let Some(det) = details {
        if let Some(error_obj) = root.get_mut("error").and_then(|v| v.as_object_mut()) {
            error_obj.insert("details".to_string(), det);
        }
    }
    root
}

fn api_error_response(
    status: StatusCode,
    code: &str,
    message: impl Into<String>,
    details: Option<serde_json::Value>,
) -> Response<Full<Bytes>> {
    json_response(status, error_body(code, message, details))
}

fn method_not_allowed_response() -> Response<Full<Bytes>> {
    api_error_response(
        StatusCode::METHOD_NOT_ALLOWED,
        "METHOD_NOT_ALLOWED",
        "method not allowed",
        None,
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
    let code = match err {
        SfuError::InvalidId(_) => "INVALID_ID",
        SfuError::AlreadyExists => "ALREADY_EXISTS",
        SfuError::RoomNotFound => "ROOM_NOT_FOUND",
        SfuError::ParticipantNotFound => "PARTICIPANT_NOT_FOUND",
        SfuError::TrackNotFound => "TRACK_NOT_FOUND",
        SfuError::NotAllowed => "NOT_ALLOWED",
        SfuError::Internal(_) => "SFU_INTERNAL",
    };
    api_error_response(status, code, err.to_string(), None)
}

fn not_found_response() -> Response<Full<Bytes>> {
    api_error_response(StatusCode::NOT_FOUND, "NOT_FOUND", "not found", None)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn parse_direction(value: &str) -> Result<IceDirection, BoxedResponse> {
    match value {
        "local" => Ok(IceDirection::Local),
        "remote" => Ok(IceDirection::Remote),
        _ => Err(Box::new(api_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_DIRECTION",
            "invalid direction",
            None,
        ))),
    }
}

fn calls_disabled_response() -> Response<Full<Bytes>> {
    api_error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "CALLS_DISABLED",
        "calls disabled",
        None,
    )
}

fn call_error_response(err: CallManagerError) -> Response<Full<Bytes>> {
    match err {
        CallManagerError::RoomNotFound | CallManagerError::ParticipantNotFound => {
            api_error_response(
                StatusCode::NOT_FOUND,
                "CALL_NOT_FOUND",
                err.to_string(),
                None,
            )
        }
        CallManagerError::ParticipantExists => api_error_response(
            StatusCode::CONFLICT,
            "PARTICIPANT_EXISTS",
            err.to_string(),
            None,
        ),
        CallManagerError::StateUnavailable => api_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CALL_STATE_UNAVAILABLE",
            err.to_string(),
            None,
        ),
        CallManagerError::SfuError(err) => sfu_error_response(err),
    }
}

fn signaling_json(record: &SignalingRecord) -> serde_json::Value {
    serde_json::json!({
        "offer_sdp": record.offer_sdp,
        "answer_sdp": record.answer_sdp,
        "ice_local": record.ice_local,
        "ice_remote": record.ice_remote,
        "updated_at_ms": record.updated_at_ms
    })
}

fn room_state_json(room: CallRoomState) -> serde_json::Value {
    let participants: Vec<serde_json::Value> = room
        .participants
        .values()
        .map(|p| {
            serde_json::json!({
                "participant_id": p.participant_id.to_string(),
                "role": p.role,
                "offer": p.signaling.offer_sdp.is_some(),
                "answer": p.signaling.answer_sdp.is_some(),
                "ice_local": p.signaling.ice_local.len(),
                "ice_remote": p.signaling.ice_remote.len(),
                "updated_at_ms": p.signaling.updated_at_ms
            })
        })
        .collect();
    serde_json::json!({
        "room_id": room.room_id.as_room_id().to_string(),
        "created_at_ms": room.created_at_ms,
        "participants": participants
    })
}

fn enforce_publish_limit(
    state: &DaemonState,
    sfu: &Arc<Sfu>,
    room_id: &RoomId,
    participant_id: &ParticipantId,
) -> Option<Response<Full<Bytes>>> {
    if !state.calls_enabled {
        return None;
    }
    if state.calls_policy.max_publish_tracks_per_participant == 0 {
        return Some(api_error_response(
            StatusCode::FORBIDDEN,
            "PUBLISH_LIMIT",
            "publish limit reached",
            None,
        ));
    }
    match current_publish_count(state, sfu, room_id, participant_id) {
        Ok(count) => {
            if count >= state.calls_policy.max_publish_tracks_per_participant as usize {
                return Some(api_error_response(
                    StatusCode::FORBIDDEN,
                    "PUBLISH_LIMIT",
                    "publish limit reached",
                    None,
                ));
            }
        }
        Err(err) => return Some(sfu_error_response(err)),
    }
    None
}

fn enforce_subscription_limit(
    state: &DaemonState,
    sfu: &Arc<Sfu>,
    room_id: &RoomId,
    participant_id: &ParticipantId,
) -> Option<Response<Full<Bytes>>> {
    if !state.calls_enabled {
        return None;
    }
    if state.calls_policy.max_subscriptions_per_participant == 0 {
        return Some(api_error_response(
            StatusCode::FORBIDDEN,
            "SUBSCRIPTION_LIMIT",
            "subscription limit reached",
            None,
        ));
    }
    match current_subscription_count(state, sfu, room_id, participant_id) {
        Ok(count) => {
            if count >= state.calls_policy.max_subscriptions_per_participant as usize {
                return Some(api_error_response(
                    StatusCode::FORBIDDEN,
                    "SUBSCRIPTION_LIMIT",
                    "subscription limit reached",
                    None,
                ));
            }
        }
        Err(err) => return Some(sfu_error_response(err)),
    }
    None
}

fn current_publish_count(
    state: &DaemonState,
    sfu: &Arc<Sfu>,
    room_id: &RoomId,
    participant_id: &ParticipantId,
) -> Result<usize, SfuError> {
    if let Some(adapter) = &state.sfu_adapter {
        return Ok(adapter.publisher_count(room_id, participant_id));
    }
    let info = sfu.room_info(room_id.clone())?;
    Ok(info
        .tracks
        .into_iter()
        .filter(|track| track.publisher == *participant_id)
        .count())
}

fn current_subscription_count(
    state: &DaemonState,
    sfu: &Arc<Sfu>,
    room_id: &RoomId,
    participant_id: &ParticipantId,
) -> Result<usize, SfuError> {
    if let Some(adapter) = &state.sfu_adapter {
        return Ok(adapter.subscription_count(room_id, participant_id));
    }
    let list = sfu.subscriptions(room_id.clone(), participant_id.clone())?;
    Ok(list.len())
}

#[derive(Deserialize)]
struct JoinPayload {
    participant_id: String,
    #[serde(default)]
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct CallJoinPayload {
    participant_id: String,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    role: Option<CallRole>,
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

#[derive(Deserialize)]
struct OfferPayload {
    participant_id: String,
    sdp: String,
}

#[derive(Deserialize)]
struct AnswerPayload {
    participant_id: String,
    sdp: String,
}

#[derive(Deserialize)]
struct IcePayload {
    participant_id: String,
    candidate: String,
    direction: String,
}

#[cfg(test)]
mod tests;
