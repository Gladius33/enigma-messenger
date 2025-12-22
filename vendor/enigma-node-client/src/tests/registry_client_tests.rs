use enigma_node_types::{NodeInfo, NodesPayload, Presence, RegisterRequest, SyncRequest};

use super::{client_for, sample_identity, spawn_server, stop_server};

#[tokio::test]
async fn registry_happy_path() {
    let server = spawn_server().await;
    let base_url = server.base_url.clone();
    let client = client_for(&base_url);

    let identity = sample_identity("alice");
    let register_resp = client
        .register(RegisterRequest {
            identity: identity.clone(),
        })
        .await
        .unwrap();
    assert!(register_resp.ok);

    let user_hex = identity.user_id.to_hex();
    let resolved = client.resolve(&user_hex).await.unwrap();
    assert_eq!(resolved.identity, Some(identity.clone()));

    let exists = client.check_user(&user_hex).await.unwrap();
    assert!(exists.exists);

    let presence = Presence {
        user_id: identity.user_id,
        addr: "wss://alice.example.com".to_string(),
        ts_ms: 1,
    };
    let announce = client.announce(presence).await.unwrap();
    assert_eq!(announce.get("ok"), Some(&serde_json::Value::Bool(true)));

    let sync_resp = client
        .sync(SyncRequest {
            identities: vec![sample_identity("bob")],
        })
        .await
        .unwrap();
    assert_eq!(sync_resp.merged, 1);

    let nodes = client.nodes().await.unwrap();
    assert!(!nodes.nodes.is_empty());

    let added = client
        .add_nodes(NodesPayload {
            nodes: vec![NodeInfo {
                base_url: "https://node-two.example.com".to_string(),
            }],
        })
        .await
        .unwrap();
    assert!(added.get("merged").is_some());

    stop_server(server).await;
}
