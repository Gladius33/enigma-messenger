use super::*;
use crate::tests::{build_request, build_state, dispatch_request, start_server, test_config};

#[tokio::test]
async fn calls_disabled_returns_503() {
    let cfg = test_config(false, true, true);
    let state = build_state(&cfg).await;
    let (addr, tx, handle) = start_server(state.clone()).await;
    let resp = dispatch_request(
        state.clone(),
        addr,
        build_request(
            "POST",
            "/calls/test-room/join",
            Some(serde_json::json!({"participant_id":"alice"})),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn join_leave_updates_state_and_sfu_room_info() {
    let cfg = test_config(true, true, true);
    let state = build_state(&cfg).await;
    let (addr, tx, handle) = start_server(state.clone()).await;
    create_room(&state, addr, "test-room").await;
    let join = dispatch_request(
        state.clone(),
        addr,
        build_request(
            "POST",
            "/calls/test-room/join",
            Some(serde_json::json!({"participant_id":"alice"})),
        ),
    )
    .await;
    assert_eq!(join.status(), StatusCode::CREATED);
    let info = dispatch_request(state.clone(), addr, build_request("GET", "/sfu/rooms/test-room", None)).await;
    let body = collect_bytes(info.into_body()).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let participants = json["participants"].as_array().cloned().unwrap_or_default();
    assert!(participants.iter().any(|p| p.as_str() == Some("alice")));
    let leave = dispatch_request(
        state.clone(),
        addr,
        build_request(
            "POST",
            "/calls/test-room/leave",
            Some(serde_json::json!({"participant_id":"alice"})),
        ),
    )
    .await;
    assert_eq!(leave.status(), StatusCode::OK);
    let info_after = dispatch_request(state.clone(), addr, build_request("GET", "/sfu/rooms/test-room", None)).await;
    let body_after = collect_bytes(info_after.into_body()).await.unwrap();
    let json_after: serde_json::Value = serde_json::from_slice(&body_after).unwrap();
    let participants_after = json_after["participants"].as_array().cloned().unwrap_or_default();
    assert!(participants_after.is_empty());
    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn offer_answer_roundtrip_persists_and_get_signaling_returns_it() {
    let cfg = test_config(true, true, true);
    let state = build_state(&cfg).await;
    let (addr, tx, handle) = start_server(state.clone()).await;
    create_room(&state, addr, "test-room").await;
    join_call(&state, addr, "test-room", "alice").await;
    let offer = dispatch_request(
        state.clone(),
        addr,
        build_request(
            "POST",
            "/calls/test-room/offer",
            Some(serde_json::json!({"participant_id":"alice","sdp":"offer-sdp"})),
        ),
    )
    .await;
    assert_eq!(offer.status(), StatusCode::OK);
    let answer = dispatch_request(
        state.clone(),
        addr,
        build_request(
            "POST",
            "/calls/test-room/answer",
            Some(serde_json::json!({"participant_id":"alice","sdp":"answer-sdp"})),
        ),
    )
    .await;
    assert_eq!(answer.status(), StatusCode::OK);
    let signaling = dispatch_request(
        state.clone(),
        addr,
        build_request("GET", "/calls/test-room/signaling/alice", None),
    )
    .await;
    let body = collect_bytes(signaling.into_body()).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["signaling"]["offer_sdp"], "offer-sdp");
    assert_eq!(json["signaling"]["answer_sdp"], "answer-sdp");
    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn ice_candidates_are_stored_and_retrievable() {
    let cfg = test_config(true, true, true);
    let state = build_state(&cfg).await;
    let (addr, tx, handle) = start_server(state.clone()).await;
    create_room(&state, addr, "test-room").await;
    join_call(&state, addr, "test-room", "alice").await;
    let _ = dispatch_request(
        state.clone(),
        addr,
        build_request(
            "POST",
            "/calls/test-room/ice",
            Some(serde_json::json!({"participant_id":"alice","candidate":"cand1","direction":"local"})),
        ),
    )
    .await;
    let _ = dispatch_request(
        state.clone(),
        addr,
        build_request(
            "POST",
            "/calls/test-room/ice",
            Some(serde_json::json!({"participant_id":"alice","candidate":"cand2","direction":"remote"})),
        ),
    )
    .await;
    let signaling = dispatch_request(
        state.clone(),
        addr,
        build_request("GET", "/calls/test-room/signaling/alice", None),
    )
    .await;
    let body = collect_bytes(signaling.into_body()).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["signaling"]["ice_local"].as_array().map(|a| a.len()), Some(1));
    assert_eq!(json["signaling"]["ice_remote"].as_array().map(|a| a.len()), Some(1));
    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn invalid_ids_rejected() {
    let cfg = test_config(true, true, true);
    let state = build_state(&cfg).await;
    let (addr, tx, handle) = start_server(state.clone()).await;
    create_room(&state, addr, "test-room").await;
    let resp = dispatch_request(
        state.clone(),
        addr,
        build_request(
            "POST",
            "/calls/test-room/join",
            Some(serde_json::json!({"participant_id":"!!!"})),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
}

#[tokio::test]
async fn join_twice_returns_409() {
    let cfg = test_config(true, true, true);
    let state = build_state(&cfg).await;
    let (addr, tx, handle) = start_server(state.clone()).await;
    create_room(&state, addr, "test-room").await;
    join_call(&state, addr, "test-room", "alice").await;
    let second = dispatch_request(
        state.clone(),
        addr,
        build_request(
            "POST",
            "/calls/test-room/join",
            Some(serde_json::json!({"participant_id":"alice"})),
        ),
    )
    .await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let _ = tx.send(());
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
}

async fn create_room(state: &DaemonState, addr: Option<SocketAddr>, room: &str) {
    let _ = dispatch_request(
        state.clone(),
        addr,
        build_request("POST", &format!("/sfu/rooms/{room}/create"), None),
    )
    .await;
}

async fn join_call(state: &DaemonState, addr: Option<SocketAddr>, room: &str, participant: &str) {
    let _ = dispatch_request(
        state.clone(),
        addr,
        build_request(
            "POST",
            &format!("/calls/{room}/join"),
            Some(serde_json::json!({"participant_id":participant})),
        ),
    )
    .await;
}
