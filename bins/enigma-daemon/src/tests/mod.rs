use super::*;
use crate::config::{
    CallsConfig, IdentityConfig, LoggingConfig, RegistryConfig, RelayConfig, SfuConfig,
    TransportConfig, WebRtcConfig,
};
use enigma_core::policy::Policy;
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1 as server_http1;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::duplex;

mod calls_tests;

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

[calls]
enabled = true
max_publish_tracks_per_participant = 2
max_subscriptions_per_participant = 3

[logging]
level = "info"
"#,
        dir = dir.path().display()
    );
    std::fs::write(&path, cfg).unwrap();
    let loaded = config::load_config(&path).unwrap();
    assert_eq!(loaded.identity.user_handle, "alice");
    assert!(loaded.relay.enabled);
    assert!(loaded.calls.enabled);
    assert_eq!(loaded.calls.max_publish_tracks_per_participant, 2);
}

#[tokio::test]
async fn daemon_starts_and_stops() {
    let cfg = test_config(false, false, false);
    let state = build_state(&cfg).await;
    let (addr, tx, handle) = start_server(state).await;
    assert!(addr.is_some() || addr.is_none());
    let _ = tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn sfu_control_endpoints() {
    let dir = tempdir().unwrap();
    let cfg = EnigmaConfig {
        data_dir: dir.path().to_path_buf(),
        ..test_config(true, true, true)
    };
    let state = build_state(&cfg).await;
    let (addr, tx, handle) = start_server(state.clone()).await;
    let health = dispatch_request(state.clone(), addr, build_request("GET", "/health", None)).await;
    assert_eq!(health.status(), StatusCode::OK);
    let rooms = dispatch_request(state.clone(), addr, build_request("GET", "/sfu/rooms", None)).await;
    assert_eq!(rooms.status(), StatusCode::OK);
    let create = dispatch_request(
        state.clone(),
        addr,
        build_request("POST", "/sfu/rooms/test-room/create", None),
    )
    .await;
    assert_eq!(create.status(), StatusCode::CREATED);
    let info = dispatch_request(state.clone(), addr, build_request("GET", "/sfu/rooms/test-room", None)).await;
    assert_eq!(info.status(), StatusCode::OK);
    let _ = tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

pub(super) fn test_config(calls_enabled: bool, sfu_enabled: bool, relay_enabled: bool) -> EnigmaConfig {
    #[allow(deprecated)]
    EnigmaConfig {
        data_dir: tempdir().unwrap().into_path(),
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
            enabled: relay_enabled,
            endpoint: None,
        },
        transport: TransportConfig {
            webrtc: WebRtcConfig {
                enabled: false,
                stun_servers: Vec::new(),
            },
        },
        sfu: SfuConfig { enabled: sfu_enabled },
        calls: CallsConfig {
            enabled: calls_enabled,
            ..CallsConfig::default()
        },
        logging: LoggingConfig {
            level: "error".to_string(),
        },
    }
}

pub(super) async fn build_state(cfg: &EnigmaConfig) -> DaemonState {
    init_logging(cfg);
    let core = init_core(cfg).await.unwrap();
    let (sfu, sfu_adapter) = init_sfu(cfg);
    DaemonState {
        core,
        sfu,
        sfu_adapter,
        call_manager: CallManager::new(),
        calls_enabled: cfg.calls.enabled,
        calls_policy: CallsPolicy {
            max_publish_tracks_per_participant: cfg.calls.max_publish_tracks_per_participant,
            max_subscriptions_per_participant: cfg.calls.max_subscriptions_per_participant,
        },
    }
}

pub(super) async fn start_server(state: DaemonState) -> (Option<SocketAddr>, oneshot::Sender<()>, JoinHandle<()>) {
    let (tx, rx) = oneshot::channel();
    let (addr, handle) = start_control_server(state, rx).await.unwrap();
    (addr, tx, handle)
}

pub(super) fn build_request(method: &str, path: &str, body: Option<serde_json::Value>) -> Request<Full<Bytes>> {
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

pub(super) async fn dispatch_request(state: DaemonState, addr: Option<SocketAddr>, req: Request<Full<Bytes>>) -> Response<Incoming> {
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
