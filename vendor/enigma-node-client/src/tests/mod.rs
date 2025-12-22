use enigma_node_registry::{start, RegistryConfig, RunningServer};
use enigma_node_types::{NodeInfo, PublicIdentity, UserId};

use crate::{NodeClient, NodeClientConfig};

pub(crate) fn sample_identity(username: &str) -> PublicIdentity {
    let user_id = UserId::from_username(username).expect("valid user id");
    PublicIdentity {
        user_id,
        username_hint: Some(username.to_string()),
        signing_public_key: vec![1, 2, 3],
        encryption_public_key: vec![4, 5, 6],
        signature: vec![7, 8, 9],
        created_at_ms: 1,
    }
}

pub(crate) fn sample_node() -> NodeInfo {
    NodeInfo {
        base_url: "https://node.example.com".to_string(),
    }
}

pub(crate) async fn spawn_server() -> RunningServer {
    start(RegistryConfig::default(), vec![sample_node()])
        .await
        .expect("server start")
}

pub(crate) fn client_for(base_url: &str) -> NodeClient {
    NodeClient::new(base_url.to_string(), NodeClientConfig::default()).expect("client")
}

pub(crate) async fn stop_server(server: RunningServer) {
    let RunningServer {
        shutdown,
        handle,
        ..
    } = server;
    let _ = shutdown.send(());
    let _ = handle.await;
}
