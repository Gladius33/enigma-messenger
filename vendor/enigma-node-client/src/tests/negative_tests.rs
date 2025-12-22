use enigma_node_types::RegisterRequest;

use super::{client_for, sample_identity, spawn_server, stop_server};
use crate::error::EnigmaNodeClientError;
use crate::{NodeClient, NodeClientConfig};

#[tokio::test]
async fn rejects_invalid_base_url() {
    let err = NodeClient::new("ftp://invalid", NodeClientConfig::default()).unwrap_err();
    assert!(matches!(err, EnigmaNodeClientError::InvalidBaseUrl));
}

#[tokio::test]
async fn rejects_invalid_user_id_hex() {
    let server = spawn_server().await;
    let client = client_for(&server.base_url);
    let err = client.resolve("not-a-hex").await.unwrap_err();
    assert!(matches!(err, EnigmaNodeClientError::InvalidUserIdHex));
    stop_server(server).await;
}

#[tokio::test]
async fn register_wrong_path_returns_status() {
    let server = spawn_server().await;
    let bad_base = format!("{}/bad", server.base_url);
    let client = NodeClient::new(bad_base, NodeClientConfig::default()).unwrap();
    let identity = sample_identity("carol");
    let err = client
        .register(RegisterRequest { identity })
        .await
        .unwrap_err();
    match err {
        EnigmaNodeClientError::Status(code) => assert!(code >= 400),
        _ => panic!("unexpected error"),
    }
    stop_server(server).await;
}
