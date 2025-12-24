//! Write buffer for async batch inserts
//! 
//! Events are sent to a channel and flushed to the database in batches,
//! preventing "pool timed out" errors when stats queries block connections.

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use super::{AttackEvent, Database};

/// Sender handle for queueing events
pub type WriteSender = mpsc::UnboundedSender<AttackEvent>;

/// Start the write buffer background task
/// Returns a sender that handlers use to queue events
pub fn start_write_buffer(db: Arc<Database>) -> WriteSender {
    let (tx, rx) = mpsc::unbounded_channel();
    
    tokio::spawn(write_buffer_task(db, rx));
    
    tx
}

/// Background task that collects events and writes them in batches
async fn write_buffer_task(db: Arc<Database>, mut rx: mpsc::UnboundedReceiver<AttackEvent>) {
    const BATCH_SIZE: usize = 100;
    const FLUSH_INTERVAL_MS: u64 = 250;
    
    let mut buffer: Vec<AttackEvent> = Vec::with_capacity(BATCH_SIZE);
    let mut flush_interval = tokio::time::interval(
        tokio::time::Duration::from_millis(FLUSH_INTERVAL_MS)
    );
    
    info!("Write buffer started (batch_size={}, flush_interval={}ms)", BATCH_SIZE, FLUSH_INTERVAL_MS);
    
    loop {
        tokio::select! {
            // Receive events from handlers
            event = rx.recv() => {
                match event {
                    Some(e) => {
                        buffer.push(e);
                        // Flush immediately if batch is full
                        if buffer.len() >= BATCH_SIZE {
                            flush_batch(&db, &mut buffer).await;
                        }
                    }
                    None => {
                        // Channel closed, flush remaining and exit
                        if !buffer.is_empty() {
                            flush_batch(&db, &mut buffer).await;
                        }
                        info!("Write buffer shutting down");
                        break;
                    }
                }
            }
            // Periodic flush for low-traffic periods
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
            // Events are lost on failure - acceptable for honeypot
            // Could add retry logic here if needed
        }
    }
    
    buffer.clear();
}
