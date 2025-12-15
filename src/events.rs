//! Event bus for broadcasting attack events

use crate::db::AttackEvent;
use std::sync::Arc;
use tokio::sync::broadcast;

#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<Arc<AttackEvent>>,
}

impl EventBus {
    pub fn new(sender: broadcast::Sender<Arc<AttackEvent>>) -> Self {
        Self { sender }
    }

    pub fn publish(&self, event: AttackEvent) {
        let _ = self.sender.send(Arc::new(event));
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<AttackEvent>> {
        self.sender.subscribe()
    }
}
