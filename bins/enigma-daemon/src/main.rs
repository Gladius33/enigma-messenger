use enigma_core::config::CoreConfig;
use enigma_core::messaging::MockTransport;
use enigma_core::policy::Policy;
use enigma_core::Core;
use enigma_node_client::InMemoryRegistry;
use enigma_relay::InMemoryRelay;
use enigma_storage::KeyProvider;
use serde::Deserialize;
use std::fs;
use std::sync::Arc;

#[derive(Clone, Deserialize)]
struct DaemonConfigWrapper {
    core: Option<CoreConfig>,
}

#[derive(Clone)]
struct DaemonKey;

impl KeyProvider for DaemonKey {
    fn key(&self) -> Vec<u8> {
        b"daemon-key".to_vec()
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "config.json".to_string());
    let content = fs::read_to_string(&path).unwrap_or_default();
    let parsed: DaemonConfigWrapper =
        serde_json::from_str(&content).unwrap_or(DaemonConfigWrapper { core: None });
    let config = parsed.core.unwrap_or_default();
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(InMemoryRelay::new());
    let transport = Arc::new(MockTransport::new());
    let core = Core::init(
        config,
        Policy::default(),
        Arc::new(DaemonKey),
        registry,
        relay,
        transport,
    )
    .await
    .expect("daemon init");
    let mut events = core.subscribe();
    while let Ok(event) = events.recv().await {
        println!("event {} {:?}", event.conversation_id.value, event.kind);
    }
}
