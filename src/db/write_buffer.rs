//! Bounded write buffer for async batch inserts
//!
//! Events are queued on a bounded channel and flushed to the database in batches,
//! preventing OOM under flood traffic and preventing pool timeouts under stats queries.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use super::{AttackEvent, Database};

/// Bounded sender handle for queueing events without blocking protocol handlers.
#[derive(Clone)]
pub struct WriteSender {
    tx: mpsc::Sender<AttackEvent>,
    dropped: Arc<AtomicU64>,
}

impl WriteSender {
    /// Enqueue an event without waiting. Returns `false` if the buffer is full.
    pub fn send(&self, event: AttackEvent) -> bool {
        match self.tx.try_send(event) {
            Ok(()) => true,
            Err(mpsc::error::TrySendError::Full(_)) => {
                let count = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if count == 1 || count % 100 == 0 {
                    warn!("Write buffer full; dropped {} events so far", count);
                }
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        }
    }

    #[allow(dead_code)]
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub fn for_test(tx: mpsc::Sender<AttackEvent>) -> Self {
        Self {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Start the write buffer background task with a bounded queue capacity.
pub fn start_write_buffer(db: Arc<Database>, capacity: usize) -> WriteSender {
    let cap = capacity.max(1);
    let (tx, rx) = mpsc::channel(cap);
    let dropped = Arc::new(AtomicU64::new(0));

    tokio::spawn(write_buffer_task(db, rx));

    WriteSender { tx, dropped }
}

/// Background task that collects events and writes them in batches
async fn write_buffer_task(db: Arc<Database>, mut rx: mpsc::Receiver<AttackEvent>) {
    const BATCH_SIZE: usize = 100;
    const FLUSH_INTERVAL_MS: u64 = 250;

    let mut buffer: Vec<AttackEvent> = Vec::with_capacity(BATCH_SIZE);
    let mut flush_interval = tokio::time::interval(
        tokio::time::Duration::from_millis(FLUSH_INTERVAL_MS),
    );

    info!(
        "Write buffer started (batch_size={}, flush_interval={}ms)",
        BATCH_SIZE, FLUSH_INTERVAL_MS
    );

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Some(e) => {
                        buffer.push(e);
                        if buffer.len() >= BATCH_SIZE {
                            flush_batch(&db, &mut buffer).await;
                        }
                    }
                    None => {
                        if !buffer.is_empty() {
                            flush_batch(&db, &mut buffer).await;
                        }
                        info!("Write buffer shutting down");
                        break;
                    }
                }
            }
            _ = flush_interval.tick() => {
                if !buffer.is_empty() {
                    flush_batch(&db, &mut buffer).await;
                }
            }
        }
    }
}

/// Flush buffered events to database in a single transaction
async fn flush_batch(db: &Database, buffer: &mut Vec<AttackEvent>) {
    let count = buffer.len();
    debug!("Flushing {} events to database", count);

    match db.batch_insert_events(buffer).await {
        Ok(_) => {
            debug!("Successfully flushed {} events", count);
        }
        Err(e) => {
            error!("Failed to flush {} events: {}", count, e);
        }
    }

    buffer.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_sender_drops_cleanly_when_full() {
        let (tx, _rx) = mpsc::channel(2);
        let sender = WriteSender {
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        };

        let ev = AttackEvent::new("1.2.3.4".into(), "ssh".into(), 22, "test".into());
        assert!(sender.send(ev.clone()));
        assert!(sender.send(ev.clone()));
        assert!(!sender.send(ev));
        assert_eq!(sender.dropped_count(), 1);
    }
}
