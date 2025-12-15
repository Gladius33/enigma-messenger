use enigma_core::config::{CoreConfig, TransportMode};
use enigma_core::messaging::MockTransport;
use enigma_core::policy::Policy;
use enigma_core::{ids::UserId, Core};
use enigma_node_client::InMemoryRegistry;
use enigma_relay::InMemoryRelay;
use enigma_storage::KeyProvider;
use enigma_api::types::{ConversationId, MessageId, MessageKind, OutgoingMessageRequest, UserIdHex};
use std::sync::Arc;

#[derive(Clone)]
struct CliKey;

impl KeyProvider for CliKey {
    fn key(&self) -> Vec<u8> {
        b"cli-key".to_vec()
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("init");
    let mut config = CoreConfig::default();
    config.storage_path = ".enigma-cli".to_string();
    config.namespace = "cli".to_string();
    config.transport_mode = TransportMode::Hybrid;
    let registry = Arc::new(InMemoryRegistry::new());
    let relay = Arc::new(InMemoryRelay::new());
    let transport = Arc::new(MockTransport::new());
    let core = Core::init(config, Policy::default(), Arc::new(CliKey), registry, relay, transport)
        .await
        .expect("cli init");
    match command {
        "init" => {
            let identity = core.local_identity();
            println!("initialized {} {}", identity.user_id.to_hex(), identity.device_id);
        }
        "send-text" => {
            if args.len() < 4 {
                eprintln!("usage: enigma-cli send-text <recipient_hex> <text>");
                return;
            }
            let recipient_hex = args[2].clone();
            let text = args[3..].join(" ");
            if let Some(recipient_user) = UserId::from_hex(&recipient_hex) {
                let conv = core.dm_conversation(&recipient_user);
                let request = OutgoingMessageRequest {
                    client_message_id: MessageId::random(),
                    conversation_id: ConversationId { value: conv.value.clone() },
                    sender: UserIdHex { value: core.local_identity().user_id.to_hex() },
                    recipients: vec![UserIdHex { value: recipient_hex.clone() }],
                    kind: MessageKind::Text,
                    text: Some(text),
                    attachment: None,
                    attachment_bytes: None,
                    ephemeral_expiry_secs: None,
                    metadata: None,
                };
                match core.send_message(request).await {
                    Ok(msg_id) => println!("sent {}", msg_id.value),
                    Err(err) => eprintln!("error {:?}", err),
                }
            } else {
                eprintln!("invalid recipient");
            }
        }
        "events" => {
            let mut rx = core.subscribe();
            loop {
                match rx.recv().await {
                    Ok(event) => println!("{} {:?}", event.conversation_id.value, event.kind),
                    Err(_) => break,
                }
            }
        }
        _ => {
            eprintln!("unknown command");
        }
    }
}
