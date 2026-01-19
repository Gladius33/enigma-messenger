use super::*;
use crate::clients::{registry_http::RegistryHttpClient, relay_http::RelayHttpClient};
use crate::config::{
    ApiConfig, CallsConfig, EndpointMode, HttpClientConfig, IdentityConfig, LoggingConfig,
    PowConfig, RegistryConfig, RelayConfig, SfuConfig, TransportConfig, WebRtcConfig,
};
use base64::Engine;
use enigma_core::directory::RegistryClient;
use enigma_core::envelope_crypto::{decrypt_identity_envelope, requester_keypair};
use enigma_core::policy::Policy;
use enigma_core::relay::{RelayAck, RelayClient};
use enigma_core::time::now_ms;
use enigma_node_types::{RelayKind, UserId};
use hyper::client::conn::http1 as client_http1;
use hyper::server::conn::http1 as server_http1;
use hyper::service::service_fn;
use std::collections::HashMap;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::duplex;
use tokio::sync::Mutex;
use uuid::Uuid;

mod calls_tests;
mod config_validation_tests;
mod harness;
mod ui_api_tests;

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
base_url = "http://127.0.0.1:7000"
mode = "http"
pepper_hex = "0000000000000000000000000000000000000000000000000000000000000000"

[relay]
enabled = true
base_url = "http://relay.example.com"
mode = "http"

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
    assert_eq!(loaded.api.bind_addr, "127.0.0.1:9171");
}

#[tokio::test]
async fn daemon_starts_and_stops() {
    let cfg = test_config(false, false, false);
    let state = build_state(&cfg).await;
    let api_addr = cfg.api.socket_addr().unwrap();
    let (addr, tx, handle) = start_server(state, api_addr).await;
    if let Some(value) = addr {
        assert!(value.port() > 0);
    }
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
    let api_addr = cfg.api.socket_addr().unwrap();
    let (addr, tx, handle) = start_server(state.clone(), api_addr).await;
    let health = dispatch_request(state.clone(), addr, build_request("GET", "/health", None)).await;
    assert_eq!(health.status(), StatusCode::OK);
    let rooms = dispatch_request(
        state.clone(),
        addr,
        build_request("GET", "/sfu/rooms", None),
    )
    .await;
    assert_eq!(rooms.status(), StatusCode::OK);
    let create = dispatch_request(
        state.clone(),
        addr,
        build_request("POST", "/sfu/rooms/test-room/create", None),
    )
    .await;
    assert_eq!(create.status(), StatusCode::CREATED);
    let info = dispatch_request(
        state.clone(),
        addr,
        build_request("GET", "/sfu/rooms/test-room", None),
    )
    .await;
    assert_eq!(info.status(), StatusCode::OK);
    let _ = tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn registry_integration_smoke() {
    let pepper_hex = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let key_hex = hex::encode([7u8; 32]);
    let running =
        match harness::spawn_registry_server(&pepper_hex, "0102030405060708", &key_hex).await {
            Some(server) => server,
            None => return,
        };
    let mut cfg = test_config(false, false, false);
    let data_dir = tempdir().unwrap();
    cfg.data_dir = data_dir.path().to_path_buf();
    cfg.registry.enabled = true;
    cfg.registry.base_url = running.base_url.clone();
    cfg.registry.mode = EndpointMode::Http;
    cfg.registry.pepper_hex = Some(pepper_hex.clone());
    let state = build_state(&cfg).await;
    let handle_hex = state.core.local_identity().user_id.to_hex();
    let (secret, pubkey) = requester_keypair();
    let client = RegistryHttpClient::new(&cfg.registry).unwrap();
    let envelope = client
        .resolve(&handle_hex, pubkey)
        .await
        .unwrap()
        .expect("envelope");
    let identity = decrypt_identity_envelope(
        client.envelope_pepper().unwrap(),
        &envelope,
        secret,
        &enigma_node_types::UserId::from_hex(&handle_hex).unwrap(),
    )
    .unwrap();
    assert_eq!(identity.public.user_id.to_hex(), handle_hex);
    running.stop().await;
}

#[tokio::test]
async fn relay_integration_outbox() {
    tokio::task::LocalSet::new()
        .run_until(async {
            let running = match harness::spawn_relay_server().await {
                Some(running) => running,
                None => return,
            };
            let mut cfg_a = test_config(false, false, true);
            let data_dir_a = tempdir().unwrap();
            cfg_a.data_dir = data_dir_a.path().to_path_buf();
            cfg_a.identity.user_handle = "alice".to_string();
            cfg_a.relay.base_url = Some(running.base_url.clone());
            cfg_a.registry.enabled = false;
            cfg_a.policy.outbox_batch_send = 4;
            cfg_a.policy.max_retry_window_secs = 2;
            let mut cfg_b = test_config(false, false, true);
            let data_dir_b = tempdir().unwrap();
            cfg_b.data_dir = data_dir_b.path().to_path_buf();
            cfg_b.identity.user_handle = "bob".to_string();
            cfg_b.relay.base_url = Some(running.base_url.clone());
            cfg_b.registry.enabled = false;
            cfg_b.policy.outbox_batch_send = 4;
            cfg_b.policy.max_retry_window_secs = 2;
            let core_a = init_core(&cfg_a).await.unwrap();
            let core_b = init_core(&cfg_b).await.unwrap();
            let conv = core_a.dm_conversation(&core_b.local_identity().user_id);
            let mut rx = core_b.subscribe();
            let req = enigma_api::types::OutgoingMessageRequest {
                client_message_id: enigma_api::types::MessageId::random(),
                conversation_id: enigma_api::types::ConversationId {
                    value: conv.value.clone(),
                },
                sender: enigma_api::types::UserIdHex {
                    value: core_a.local_identity().user_id.to_hex(),
                },
                recipients: vec![enigma_api::types::OutgoingRecipient {
                    recipient_user_id: Some(core_b.local_identity().user_id.to_hex()),
                    recipient_handle: None,
                }],
                kind: enigma_api::types::MessageKind::Text,
                text: Some("hello".to_string()),
                attachment: None,
                attachment_bytes: None,
                ephemeral_expiry_secs: None,
                metadata: None,
            };
            core_a.send_message(req).await.unwrap();
            core_b.poll_once().await.unwrap();
            let event = rx.recv().await.unwrap();
            assert_eq!(event.text.as_deref(), Some("hello"));
            let relay_client = RelayHttpClient::new(&cfg_a.relay).unwrap();
            let recipient = core_b.local_identity().user_id.to_hex();
            let pulled = relay_client.pull(&recipient, None).await.unwrap();
            let ack_entries: Vec<RelayAck> = pulled
                .items
                .iter()
                .map(|item| RelayAck {
                    message_id: item.envelope.id,
                    chunk_index: item.chunk_index,
                })
                .collect();
            let ack_response = relay_client.ack(&recipient, &ack_entries).await.unwrap();
            assert_eq!(ack_response.deleted, ack_entries.len() as u64);
            let pulled_after = relay_client.pull(&recipient, None).await.unwrap();
            assert!(pulled_after.items.is_empty());
            running.stop().await;
        })
        .await
}

#[tokio::test]
async fn relay_outbox_roundtrip_multi_chunk() {
    let running = match harness::spawn_relay_server().await {
        Some(running) => running,
        None => return,
    };
    let mut cfg = test_config(false, false, true);
    cfg.relay.base_url = Some(running.base_url.clone());
    cfg.registry.enabled = false;
    let client = RelayHttpClient::new(&cfg.relay).unwrap();
    let recipient = UserId::from_username("relay-multi").unwrap();
    let message_id = Uuid::new_v4();
    let created_at = now_ms();
    for idx in 0..3u32 {
        let envelope = enigma_node_types::RelayEnvelope {
            id: message_id,
            to: recipient,
            from: None,
            created_at_ms: created_at + idx as u64,
            expires_at_ms: None,
            kind: RelayKind::OpaqueAttachmentChunk(enigma_node_types::OpaqueAttachmentChunk {
                blob_b64: base64::engine::general_purpose::STANDARD.encode(format!("chunk-{idx}")),
                attachment_id: message_id,
                index: idx,
                total: Some(3),
            }),
        };
        client.push(envelope).await.unwrap();
    }
    let pulled = client.pull(&recipient.to_hex(), None).await.unwrap();
    assert_eq!(pulled.items.len(), 3);
    let order: Vec<u32> = pulled.items.iter().map(|i| i.chunk_index).collect();
    assert_eq!(order, vec![0, 1, 2]);
    let ack_entries: Vec<RelayAck> = pulled
        .items
        .iter()
        .map(|item| RelayAck {
            message_id: item.envelope.id,
            chunk_index: item.chunk_index,
        })
        .collect();
    let ack_response = client.ack(&recipient.to_hex(), &ack_entries).await.unwrap();
    assert_eq!(ack_response.deleted, 3);
    let pulled_again = client.pull(&recipient.to_hex(), None).await.unwrap();
    assert!(pulled_again.items.is_empty());
    running.stop().await;
}

#[tokio::test]
async fn registry_key_rotation_resilience() {
    let pepper_hex = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let key1 = hex::encode([7u8; 32]);
    let key2 = hex::encode([8u8; 32]);
    let first = match harness::spawn_registry_server(&pepper_hex, "0102030405060708", &key1).await {
        Some(server) => server,
        None => return,
    };
    let base_url = first.base_url.clone();
    let address = base_url.trim_start_matches("http://").to_string();
    let mut cfg = test_config(false, false, false);
    cfg.registry.enabled = true;
    cfg.registry.base_url = base_url.clone();
    cfg.registry.pepper_hex = Some(pepper_hex.clone());
    let client = Arc::new(RegistryHttpClient::new(&cfg.registry).unwrap());
    client.envelope_key().await.unwrap();
    first.stop().await;
    let second =
        match harness::spawn_registry_server_at(address, &pepper_hex, "1112131415161718", &key2)
            .await
        {
            Some(server) => server,
            None => return,
        };
    let identity_core = init_core(&test_config(false, false, false)).await.unwrap();
    let identity = identity_core.local_identity();
    let identity_user = enigma_node_types::UserId::from_hex(&identity.user_id.to_hex()).unwrap();
    enigma_core::directory::register_identity(client.clone(), &identity)
        .await
        .unwrap();
    let (secret, pubkey) = requester_keypair();
    let envelope = client
        .resolve(&identity.user_id.to_hex(), pubkey)
        .await
        .unwrap()
        .expect("envelope");
    let decrypted = decrypt_identity_envelope(
        client.envelope_pepper().unwrap(),
        &envelope,
        secret,
        &identity_user,
    )
    .unwrap();
    assert_eq!(decrypted.public.user_id, identity_user);
    second.stop().await;
}

#[tokio::test]
async fn retry_policy_smoke() {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(sock) => sock,
        Err(err) => {
            if err.kind() == std::io::ErrorKind::PermissionDenied {
                return;
            }
            panic!("{:?}", err);
        }
    };
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let base_url = format!("http://{}", addr);
    let mut cfg = test_config(false, false, true);
    cfg.relay.enabled = true;
    cfg.relay.base_url = Some(base_url.clone());
    cfg.relay.http = HttpClientConfig {
        timeout_secs: 1,
        connect_timeout_secs: 1,
        read_timeout_secs: 1,
        retry_attempts: 5,
        retry_backoff_ms: 50,
    };
    cfg.registry.enabled = false;
    let client = RelayHttpClient::new(&cfg.relay).unwrap();
    let address = format!("{}", addr);
    let server_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(75)).await;
        harness::spawn_relay_server_at(address).await
    });
    let recipient = UserId::from_username("retry").unwrap().to_hex();
    let pulled_result = client.pull(&recipient, None).await;
    let server_handle = server_task.await.unwrap_or(None);
    if let Some(handle) = server_handle {
        let pulled = pulled_result.unwrap();
        assert!(pulled.items.is_empty());
        handle.stop().await;
    }
}

pub(super) fn test_config(
    calls_enabled: bool,
    sfu_enabled: bool,
    relay_enabled: bool,
) -> EnigmaConfig {
    #[allow(deprecated)]
    EnigmaConfig {
        data_dir: tempdir().unwrap().into_path(),
        identity: IdentityConfig {
            user_handle: "alice".to_string(),
            device_name: None,
        },
        policy: Policy::default(),
        registry: RegistryConfig {
            enabled: false,
            base_url: "http://127.0.0.1:0".to_string(),
            mode: EndpointMode::Http,
            tls: None,
            pow: PowConfig {
                enabled: false,
                ..PowConfig::default()
            },
            pepper_hex: Some(
                "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
            http: HttpClientConfig::default(),
            key_cache_ttl_secs: 300,
        },
        relay: RelayConfig {
            enabled: relay_enabled,
            base_url: relay_enabled.then(|| "http://127.0.0.1:0".to_string()),
            mode: EndpointMode::Http,
            tls: None,
            http: HttpClientConfig::default(),
        },
        transport: TransportConfig {
            webrtc: WebRtcConfig {
                enabled: false,
                stun_servers: Vec::new(),
            },
        },
        api: ApiConfig {
            bind_addr: "127.0.0.1:0".to_string(),
        },
        sfu: SfuConfig {
            enabled: sfu_enabled,
        },
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
    let ready_state = ReadyState::new();
    ready_state.mark_ready(); // Mark immediately for tests
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
        policy: cfg.policy.clone(),
        allow_attachments: true,
        registry_enabled: cfg.registry.enabled,
        relay_enabled: cfg.relay.enabled,
        transport_webrtc_enabled: cfg.transport.webrtc.enabled,
        sfu_enabled: cfg.sfu.enabled,
        ui_auth_enabled: ui_auth_enabled(),
        ui_messages: Arc::new(Mutex::new(HashMap::new())),
        ui_events: Arc::new(Mutex::new(UiEvents::new())),
        ui_conversations: Arc::new(Mutex::new(HashMap::new())),
        ready_state,
        boot_metrics: None, // No boot metrics in tests
    }
}

pub(super) async fn start_server(
    state: DaemonState,
    api_addr: SocketAddr,
) -> (Option<SocketAddr>, oneshot::Sender<()>, JoinHandle<()>) {
    let (tx, rx) = oneshot::channel();
    let (addr, handle) = match start_control_server(state, rx, api_addr).await {
        Ok(output) => output,
        Err(DaemonError::Bind(_)) => {
            let handle = tokio::spawn(async move {});
            return (None, tx, handle);
        }
        Err(err) => panic!("{:?}", err),
    };
    (Some(addr), tx, handle)
}

pub(super) fn build_request(
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> Request<Full<Bytes>> {
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
    builder.body(Full::from(Bytes::from(bytes))).unwrap()
}

pub(super) async fn dispatch_request(
    state: DaemonState,
    addr: Option<SocketAddr>,
    req: Request<Full<Bytes>>,
) -> Response<Incoming> {
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

async fn send_in_memory_request(
    state: DaemonState,
    req: Request<Full<Bytes>>,
) -> Response<Incoming> {
    let (client, server) = duplex(4096);
    let server_state = state.clone();
    let service = service_fn(move |incoming: Request<Incoming>| {
        let inner = server_state.clone();
        async move { handle_request(inner, incoming).await }
    });
    let server_task = tokio::spawn(async move {
        let io = TokioIo::new(server);
        let _ = server_http1::Builder::new()
            .serve_connection(io, service)
            .await;
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
