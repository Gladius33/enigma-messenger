use enigma_api::types::IncomingMessageEvent;
use tokio::sync::broadcast;

pub type EventReceiver = broadcast::Receiver<IncomingMessageEvent>;

#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<IncomingMessageEvent>,
}

impl EventBus {
    pub fn new(size: usize) -> Self {
        let (tx, _) = broadcast::channel(size);
        Self { tx }
    }

    pub fn subscribe(&self) -> EventReceiver {
        self.tx.subscribe()
    }

    pub fn publish(&self, event: IncomingMessageEvent) {
        let _ = self.tx.send(event);
    }
}
