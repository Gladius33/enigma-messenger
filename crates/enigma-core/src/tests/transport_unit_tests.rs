use crate::messaging::{MockTransport, Transport};

#[tokio::test]
async fn mock_transport_roundtrip_respects_channels() {
    let transport = MockTransport::new();
    let payload = b"hi".to_vec();
    transport.send_p2p("alice", &payload).await.expect("send");
    let msgs = transport.receive("alice").await.expect("receive");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].bytes, payload);
    assert_eq!(msgs[0].sender, "peer");

    let relay_payload = b"relay".to_vec();
    transport
        .send_relay("bob", &relay_payload)
        .await
        .expect("send relay");
    let relay_msgs = transport.receive("bob").await.expect("receive relay");
    assert_eq!(relay_msgs.len(), 1);
    assert_eq!(relay_msgs[0].sender, "relay");
    assert_eq!(relay_msgs[0].bytes, relay_payload);
}

#[tokio::test]
async fn mock_transport_failures_are_consumed() {
    let transport = MockTransport::new();
    transport.fail_p2p_times(1).await;
    let send_err = transport.send_p2p("user", b"msg").await;
    assert!(send_err.is_err());
    // second attempt succeeds after failure budget is spent
    transport
        .send_p2p("user", b"msg")
        .await
        .expect("second send");
    let msgs = transport.receive("user").await.expect("receive");
    assert_eq!(msgs.len(), 1);
}
